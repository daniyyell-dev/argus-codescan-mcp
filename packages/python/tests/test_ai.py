"""Agent scanner CLI, malware integration and MCP registration."""

from pathlib import Path

import pytest

from argus.cli import build_parser
from argus.tools.ai import run_ai_scan
from argus.tools.malware import run_malware_scan


@pytest.mark.asyncio
async def test_agent_scan_and_malware_scan(tmp_path: Path):
    config = tmp_path / ".vscode/settings.json"
    config.parent.mkdir()
    config.write_text('{"chat.tools.autoApprove":true}')
    for runner in (run_ai_scan, run_malware_scan):
        result = await runner(str(tmp_path))
        assert not result.errors
        assert any(f.rule_id == "ai-agent-auto-approve" for f in result.findings)
    args = build_parser().parse_args(["scan", "ai", str(tmp_path), "--no-upload"])
    assert args.scan_type == "ai"


@pytest.mark.asyncio
async def test_agent_mcp_registration():
    from argus.server import list_tools

    tools = await list_tools()
    assert next(t for t in tools if t.name == "scan_ai").inputSchema["required"] == ["target"]
