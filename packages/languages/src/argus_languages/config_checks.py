"""Shared helpers for inspecting untrusted configuration without executing it."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from argus_languages.models import Finding
from argus_languages.rules_loader import LoadedRule

_JSONC_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/')
_TRAILING_COMMA = re.compile(r'"(?:\\.|[^"\\])*"|,(?=\s*[}\]])')


def parse_json_config(content: str) -> dict:
    """Parse JSON/JSONC, preserving strings, URLs and source line numbers."""

    def strip_comment(match: re.Match[str]) -> str:
        value = match.group()
        return value if value.startswith('"') else re.sub(r"[^\n]", " ", value)

    cleaned = _JSONC_TOKEN.sub(strip_comment, content)
    cleaned = _TRAILING_COMMA.sub(
        lambda match: " " if match.group() == "," else match.group(), cleaned
    )
    try:
        data = json.loads(cleaned)
    except (ValueError, TypeError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def config_strings(value: object) -> Iterator[str]:
    """Yield command strings from supported string, array and object forms."""
    pending = [value]
    visited: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, (dict, list)) and id(item) not in visited:
            visited.add(id(item))
            pending.extend(reversed(list(item.values()) if isinstance(item, dict) else item))


class ConfigFindings:
    """Build metadata-backed findings without including configuration values/secrets."""

    def __init__(self, relative: str, language: str, content: str, rules: list[LoadedRule]) -> None:
        self.relative = relative
        self.language = language
        self.content = content
        self.rules = {rule.id: rule for rule in rules}
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, int]] = set()

    def add(self, rule_id: str, location: str) -> None:
        """Report a rule at its configuration value/key, deduplicated per source line."""
        rule = self.rules.get(rule_id)
        if rule is None:
            return
        encoded = json.dumps(location, ensure_ascii=False)[1:-1]
        offset = self.content.find(encoded)
        if offset < 0:
            offset = self.content.find(location)
        line = self.content.count("\n", 0, max(0, offset)) + 1
        if (rule_id, line) in self.seen:
            return
        self.seen.add((rule_id, line))
        self.findings.append(
            Finding(
                title=rule.title,
                severity=rule.severity,
                tool="argus-languages",
                file=self.relative,
                line=line,
                rule_id=rule_id,
                language=self.language,
                confidence=rule.confidence,
                description=rule.title,
                fix_guidance=rule.fix_guidance,
            )
        )
