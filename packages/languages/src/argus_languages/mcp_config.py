"""Static inspection of MCP server definitions; no process or network access."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from functools import lru_cache
from urllib.parse import parse_qsl, urlsplit

import yaml

from argus_languages.config_checks import ConfigFindings, config_strings, parse_json_config
from argus_languages.models import Finding
from argus_languages.package_names import looks_like_package
from argus_languages.rules_loader import LoadedRule, load_rules_from_files

MCP_CONFIG_FILES = {
    ".cursor": {"mcp.json"},
    ".vscode": {"mcp.json"},
    ".gemini": {"settings.json"},
    ".continue": {"config.json", "config.yaml", "config.yml"},
}
MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
    ".claude.json",
}
KNOWN_SERVER_PACKAGES = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-fetch",
    "postmark-mcp",
)
_SECRET_KEY = re.compile(r"token|password|passwd|secret|api[-_]?key|authorization|credential", re.I)
_REFERENCE = re.compile(r"\$\{(?:(?:env|input):)?[\w.-]+\}|\$[A-Za-z_][A-Za-z_0-9]*")
_GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b")
_DOWNLOAD = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\b", re.I
)


@lru_cache(maxsize=1)
def _provider_secret_patterns() -> tuple[re.Pattern[str], ...]:
    # Share the existing provider-token patterns rather than maintaining divergent copies.
    ids = {"ml-openai-key-inline", "ml-anthropic-key-inline", "ml-huggingface-token-inline"}
    return tuple(rule.pattern for rule in load_rules_from_files(("ml.yaml",)) if rule.id in ids)


def _literal(value: str) -> bool:
    remainder = _REFERENCE.sub("", value).strip()
    return bool(remainder and remainder.casefold() != "bearer")


def _package_name(spec: str) -> str:
    return "@" + spec[1:].split("@", 1)[0] if spec.startswith("@") else spec.split("@", 1)[0]


def _runner_packages(args: list[str], runner: str) -> list[str]:
    """Extract package/image operands while accounting for common runner options."""
    if runner == "pipx":
        if not args or args[0] != "run":
            return []
        args = args[1:]
    elif runner == "docker":
        if not args or args[0] != "run":
            return []
        args = args[1:]
    packages = []
    position = 0
    takes_value = {
        "--registry",
        "--cache",
        "--userconfig",
        "--index-url",
        "--python",
        "--index",
        "--directory",
        "--with",
        "--with-executables",
        "--name",
        "--network",
        "--mount",
        "--volume",
        "-v",
        "--env",
        "-e",
        "--env-file",
        "--publish",
        "-p",
        "--user",
        "-u",
        "--workdir",
        "-w",
        "--entrypoint",
        "--pull",
        "--platform",
    }
    while position < len(args):
        arg = args[position]
        option = arg.split("=", 1)[0]
        package_option = option in (
            {"--package", "-p"} if runner == "npx" else {"--from", "--spec"}
        )
        if package_option:
            value = (
                arg.split("=", 1)[1]
                if "=" in arg
                else (args[position + 1] if position + 1 < len(args) else "")
            )
            if value:
                packages.append(value)
            position += 1 if "=" in arg else 2
            continue
        if option in takes_value and "=" not in arg:
            position += 2
            continue
        if arg.startswith("-"):
            position += 1
            continue
        return packages or [arg]
    return packages


def _pinned(spec: str, runner: str) -> bool:
    if runner == "docker":
        if re.search(r"@sha256:[a-fA-F0-9]{64}$", spec):
            return True
        tail = spec.rsplit("/", 1)[-1]
        return ":" in tail and tail.rsplit(":", 1)[-1] not in {
            "",
            "latest",
            "main",
            "stable",
            "dev",
        }
    if runner in {"uvx", "pipx"}:
        return bool(re.fullmatch(r"[\w.\[\],-]+==[0-9][\w.+!-]*", spec)) or (
            runner == "uvx" and bool(re.fullmatch(r"[\w.\[\],-]+@[0-9][\w.+!-]*", spec))
        )
    name = _package_name(spec)
    version = spec[len(name) + 1 :] if spec.startswith(name + "@") else ""
    return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", version))


def _servers(data: dict) -> Iterator[tuple[str, dict]]:
    tables = [data.get("mcpServers"), data.get("servers")]
    experimental = data.get("experimental")
    if isinstance(experimental, dict):
        tables.append(experimental.get("modelContextProtocolServers"))
    for table in tables:
        if isinstance(table, dict):
            for name, server in table.items():
                if isinstance(server, dict):
                    yield str(name), server
        elif isinstance(table, list):
            for server in table:
                if isinstance(server, dict):
                    yield str(server.get("name", "server")), server


def scan_mcp_config(
    relative: str, language: str, content: str, rules: list[LoadedRule]
) -> list[Finding]:
    """Review command pins, transport, credentials and similar-looking package names."""
    if language != "mcp-config":
        return []
    if relative.endswith((".yaml", ".yml")):
        try:
            data = yaml.safe_load(content)
        except (yaml.YAMLError, RecursionError):
            return []
        if not isinstance(data, dict):
            return []
    else:
        data = parse_json_config(content)
    out = ConfigFindings(relative, language, content, rules)
    for name, server in _servers(data):
        if looks_like_package(name, KNOWN_SERVER_PACKAGES):
            out.add("mcp-lookalike-name", name)
        command = server.get("command", "")
        args = server.get("args", [])
        args = args if isinstance(args, list) and all(isinstance(a, str) for a in args) else []
        runner = (
            command.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if isinstance(command, str)
            else ""
        )
        runner = re.sub(r"\.(?:exe|cmd)$", "", runner)
        if runner in {"npx", "uvx", "pipx", "docker"}:
            for spec in _runner_packages(args, runner):
                if not _pinned(spec, runner):
                    out.add("mcp-unpinned-command", spec)
                if looks_like_package(_package_name(spec), KNOWN_SERVER_PACKAGES):
                    out.add("mcp-lookalike-name", spec)
        if runner in {"sh", "bash", "zsh", "dash", "ksh", "powershell", "pwsh", "cmd"} and any(
            arg.lower() in {"-c", "-lc", "-ic", "-command", "/c"} for arg in args
        ):
            script = " ".join(args)
            if _DOWNLOAD.search(script):
                out.add(
                    "mcp-shell-download",
                    next((arg for arg in args if _DOWNLOAD.search(arg)), command),
                )
        for section in ("env", "headers"):
            values = server.get(section, {})
            if isinstance(values, dict):
                for key, value in values.items():
                    if isinstance(value, str) and _SECRET_KEY.search(str(key)) and _literal(value):
                        out.add("mcp-inline-secret", value)
        for index, arg in enumerate(args[:-1]):
            if arg.startswith("--") and _SECRET_KEY.search(arg) and _literal(args[index + 1]):
                out.add("mcp-inline-secret", args[index + 1])
        for arg in args:
            key, separator, value = arg.partition("=")
            if separator and key.startswith("--") and _SECRET_KEY.search(key) and _literal(value):
                out.add("mcp-inline-secret", arg)
        for value in config_strings(server):
            if _GITHUB_TOKEN.search(value) or any(
                pattern.search(value) for pattern in _provider_secret_patterns()
            ):
                if _literal(value):
                    out.add("mcp-inline-secret", value)
        url = server.get("url")
        if isinstance(url, str):
            try:
                parsed = urlsplit(url)
                raw_ip = False
                try:
                    ipaddress.ip_address(parsed.hostname or "")
                    raw_ip = True
                except ValueError:
                    pass
                if parsed.scheme.lower() == "http" or raw_ip:
                    out.add("mcp-insecure-endpoint", url)
                if (
                    parsed.username
                    or parsed.password
                    or any(
                        _SECRET_KEY.search(key) and _literal(value)
                        for key, value in parse_qsl(parsed.query)
                    )
                ):
                    out.add("mcp-inline-secret", url)
            except ValueError:
                pass
    return out.findings
