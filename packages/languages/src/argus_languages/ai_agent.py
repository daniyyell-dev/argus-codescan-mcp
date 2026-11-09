"""Inspect project agent hooks and auto-run settings; never execute commands."""

from __future__ import annotations

import re

from argus_languages.config_checks import ConfigFindings, config_strings, parse_json_config
from argus_languages.models import Finding
from argus_languages.rules_loader import LoadedRule

AI_CONFIG_FILES = {
    ".claude": {"settings.json", "settings.local.json"},
    ".vscode": {"settings.json", "tasks.json"},
    ".devcontainer": {"devcontainer.json"},
}
AI_CONFIG_LANGUAGES = frozenset(
    {"claude-settings", "vscode-settings", "vscode-tasks", "devcontainer", "npm-manifest"}
)
_NETWORK_COMMAND = re.compile(
    r"\b(?:curl|wget|base64|ncat|socat|Invoke-WebRequest|Invoke-RestMethod|"
    r"DownloadString|DownloadFile)\b|\bnc\s|https?://",
    re.I,
)


def scan_ai_agent_config(
    relative: str, language: str, content: str, rules: list[LoadedRule]
) -> list[Finding]:
    """Detect risky settings only in the fields used by each supported client."""
    if language not in AI_CONFIG_LANGUAGES:
        return []
    data = parse_json_config(content)
    out = ConfigFindings(relative, language, content, rules)
    if language == "npm-manifest":
        scripts = data.get("scripts", {})
        bypass = out.rules.get("ai-agent-bypass-approvals")
        if bypass and isinstance(scripts, dict):
            for command in scripts.values():
                if isinstance(command, str) and bypass.pattern.search(command):
                    out.add(bypass.id, command)
    elif language == "claude-settings":
        hooks = data.get("hooks", {})
        if isinstance(hooks, dict):
            for event, settings in hooks.items():
                if not isinstance(settings, list):
                    continue
                for entry in settings:
                    if not isinstance(entry, dict):
                        continue
                    commands = entry.get("hooks", [])
                    if not isinstance(commands, list):
                        continue
                    for hook in commands:
                        if not isinstance(hook, dict) or hook.get("type") != "command":
                            continue
                        command = hook.get("command")
                        if not isinstance(command, str):
                            continue
                        if event in {"SessionStart", "PreToolUse"}:
                            out.add("ai-agent-automatic-hook", event)
                        if _NETWORK_COMMAND.search(command):
                            out.add("ai-agent-hook-network-command", command)
        permissions = data.get("permissions", {})
        allow = permissions.get("allow", []) if isinstance(permissions, dict) else []
        if isinstance(allow, list):
            for item in allow:
                if isinstance(item, str) and (
                    re.fullmatch(r"Bash\(\s*\*\s*\)", item)
                    or re.fullmatch(r"Bash\(\s*(?:curl|wget)(?::|\s)\*\s*\)", item)
                    or (item.startswith("WebFetch(") and "*" in item)
                ):
                    out.add("ai-agent-broad-permissions", item)
    elif language == "vscode-settings":
        if data.get("chat.tools.autoApprove") is True:
            out.add("ai-agent-auto-approve", "chat.tools.autoApprove")
        if data.get("task.allowAutomaticTasks") in ("on", True):
            out.add("ai-agent-automatic-tasks", "task.allowAutomaticTasks")
    elif language == "vscode-tasks":
        tasks = data.get("tasks", [])
        for task in tasks if isinstance(tasks, list) else []:
            if not isinstance(task, dict):
                continue
            options = task.get("runOptions", {})
            if isinstance(options, dict) and options.get("runOn") == "folderOpen":
                out.add("ai-agent-folder-open-task", "folderOpen")
            command = " ".join(config_strings([task.get("command"), task.get("args")]))
            if _NETWORK_COMMAND.search(command) and re.search(r"\|\s*(?:ba)?sh\b", command):
                out.add("ai-agent-task-remote-exec", str(task.get("command", "command")))
    elif language == "devcontainer":
        for key in ("postCreateCommand", "postStartCommand"):
            for command in config_strings(data.get(key)):
                if _NETWORK_COMMAND.search(command) and re.search(r"\|\s*(?:ba)?sh\b", command):
                    out.add("ai-agent-container-remote-exec", command)
    return out.findings
