"""MCP runner integration and explicit global configuration boundaries."""

import pytest

from argus.cli import build_parser
from argus.tools.malware import run_malware_scan
from argus.tools.mcp_config import global_mcp_configs, run_mcp_config_scan


@pytest.mark.asyncio
async def test_project_mcp_and_malware_scans(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"example":{"command":"npx","args":["pkg"]}}}'
    )
    for runner in (run_mcp_config_scan, run_malware_scan):
        result = await runner(str(tmp_path))
        assert not result.errors
        assert any(f.rule_id == "mcp-unpinned-command" for f in result.findings)
    args = build_parser().parse_args(
        ["scan", "mcp-config", str(tmp_path), "--global", "--no-upload"]
    )
    assert args.scan_type == "mcp-config" and args.include_global


@pytest.mark.asyncio
async def test_global_configs_are_opt_in_and_report_distinct_paths(tmp_path, monkeypatch):
    from argus.tools import mcp_config

    project = tmp_path / "project"
    project.mkdir()
    (project / "safe.py").write_text("pass")
    home = tmp_path / "user"
    home.mkdir()
    path = home / ".claude.json"
    path.write_text('{"mcpServers":{"example":{"env":{"TOKEN":"never-serialize-me"}}}}')
    monkeypatch.setattr(mcp_config, "global_mcp_configs", lambda: [path])
    assert not (await run_mcp_config_scan(str(project))).findings
    result = await run_mcp_config_scan(str(project), include_global=True)
    assert result.metadata["global_files_scanned"] == 1
    assert result.findings[0].file == str(path)
    assert "never-serialize-me" not in str(result.to_dict())


def test_global_candidates_do_not_walk_arbitrary_home_content(tmp_path):
    known = tmp_path / ".cursor/mcp.json"
    known.parent.mkdir()
    known.write_text("{}")
    ignored = tmp_path / "unrelated/mcp.json"
    ignored.parent.mkdir()
    ignored.write_text("{}")
    assert global_mcp_configs(tmp_path) == [known]


@pytest.mark.asyncio
async def test_mcp_tool_defaults_to_project_only():
    from argus.server import list_tools

    tool = next(t for t in await list_tools() if t.name == "scan_mcp_config")
    assert tool.inputSchema["properties"]["include_global"]["default"] is False
