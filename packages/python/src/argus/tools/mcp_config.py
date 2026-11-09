"""Built-in MCP server configuration review, with opt-in global configuration."""

from __future__ import annotations

import os
from pathlib import Path

from argus_languages.models import Severity as LangSeverity
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path

from argus.models import Finding, ScanResult, ScanType, Severity

MCP_RULE_FILES = ("mcp.yaml",)


def global_mcp_configs(home: Path | None = None) -> list[Path]:
    """Return only existing, explicitly named client configs; never walk the home directory."""
    home = home if home is not None else Path.home()
    candidates = [home / ".claude.json", home / ".cursor/mcp.json", home / ".gemini/settings.json"]
    candidates.extend(home / ".continue" / f"config.{ext}" for ext in ("json", "yaml", "yml"))
    roots = [home / "Library/Application Support", home / ".config"]
    if os.name == "nt" and os.environ.get("APPDATA"):
        roots.append(Path(os.environ["APPDATA"]))
    for root in roots:
        candidates.extend(
            [
                root / "Claude/claude_desktop_config.json",
                root / "Code/User/mcp.json",
                root
                / "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            ]
        )
    return list(
        dict.fromkeys(path for path in candidates if path.is_file() and not path.is_symlink())
    )


async def run_mcp_config_scan(target: str, include_global: bool = False) -> ScanResult:
    """Inspect project MCP settings and, only when requested, known global client files."""
    result = ScanResult(tool="argus-mcp-config", scan_type=ScanType.MALWARE, target=target)
    rules = load_rules_from_files(MCP_RULE_FILES)
    paths = [(Path(target), False)]
    if include_global:
        paths.extend((path, True) for path in global_mcp_configs())
    seen_files: set[Path] = set()
    for path, is_global in paths:
        if path.is_file():
            resolved = path.resolve()
            if resolved in seen_files:
                continue
            seen_files.add(resolved)
        native = scan_path(path, rules=rules)
        for item in native.findings:
            severity = item.severity
            if severity == LangSeverity.MODERATE:
                severity = LangSeverity.MEDIUM
            result.findings.append(
                Finding(
                    title=item.title,
                    severity=Severity(severity.value),
                    scan_type=ScanType.MALWARE,
                    tool=result.tool,
                    file=str(path) if is_global else item.file,
                    line=item.line,
                    description=item.description,
                    rule_id=item.rule_id,
                    confidence=item.confidence,
                    fix_guidance=item.fix_guidance,
                )
            )
        result.metadata["files_scanned"] = int(result.metadata.get("files_scanned", 0)) + int(
            native.metadata.get("files_scanned", 0)
        )
        if is_global:
            result.metadata["global_files_scanned"] = int(
                result.metadata.get("global_files_scanned", 0)
            ) + int(native.metadata.get("files_scanned", 0))
        result.errors.extend(
            error
            for error in native.errors
            if not (include_global and error.startswith("No scannable files found."))
        )
    result.metadata["rule_pack"] = "mcp-config"
    result.metadata["include_global"] = include_global
    return result
