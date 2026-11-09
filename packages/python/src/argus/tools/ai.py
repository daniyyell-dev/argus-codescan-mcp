"""Built-in AI agent hooks, permissions and startup configuration scanner."""

from __future__ import annotations

import logging

from argus_languages.models import Severity as LangSeverity
from argus_languages.rules_loader import load_rules_from_files
from argus_languages.scanner import scan_path as _scan_path

from argus.models import Finding, ScanResult, ScanType, Severity

logger = logging.getLogger(__name__)

_SEV_MAP = {
    LangSeverity.CRITICAL: Severity.CRITICAL,
    LangSeverity.HIGH: Severity.HIGH,
    LangSeverity.MEDIUM: Severity.MEDIUM,
    LangSeverity.MODERATE: Severity.MEDIUM,
    LangSeverity.LOW: Severity.LOW,
    LangSeverity.INFO: Severity.INFO,
}

AI_RULE_FILES = ("ai-agent.yaml",)


async def run_ai_scan(target: str) -> ScanResult:
    """Scan project agent settings and scripts for risky execution and approval bypasses."""
    result = ScanResult(tool="argus-ai", scan_type=ScanType.MALWARE, target=target)

    try:
        rules = load_rules_from_files(AI_RULE_FILES)
        native = _scan_path(target, rules=rules)
    except Exception as exc:
        logger.exception("argus-ai scan failed")
        result.errors.append(f"argus-ai error: {exc}")
        return result

    for item in native.findings:
        result.findings.append(
            Finding(
                title=item.title,
                severity=_SEV_MAP.get(item.severity, Severity.INFO),
                scan_type=ScanType.MALWARE,
                tool="argus-ai",
                file=item.file,
                line=item.line,
                description=item.description or f"Language: {item.language}",
                rule_id=item.rule_id,
                data_classification=item.data_classification,
                confidence=getattr(item, "confidence", ""),
                context=getattr(item, "context", ""),
                fix_guidance=item.fix_guidance,
            )
        )

    result.errors.extend(native.errors)
    result.metadata.update(native.metadata)
    result.metadata["rule_pack"] = "ai-agent"
    return result
