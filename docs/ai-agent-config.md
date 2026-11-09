# Project agent configuration

`argus scan ai PATH` and the `scan_ai` MCP tool inspect project agent settings,
workspace tasks, development-container startup commands, and approval-bypass
flags in scripts. The same rules run in the code and malware scans.

Supported files are `.claude/settings.json`, `.claude/settings.local.json`,
`.vscode/settings.json`, `.vscode/tasks.json` and
`.devcontainer/devcontainer.json`, plus the scripts table in `package.json`.
JSON comments and trailing commas are accepted.
Discovery permits only these named files in the hidden configuration directories;
other hidden content and project symlinks remain excluded.

- SessionStart and PreToolUse command hooks receive a low-severity review finding.
  A formatter alone does not receive a high-severity finding.
- Hooks that download, decode, or contact network destinations receive high-severity
  findings. Broad shell/web permission wildcards receive medium-severity findings.
- Workspace automatic approval/tasks and folder-open tasks receive medium-severity
  findings. Tasks and container startup commands piping network downloads into a
  shell receive high-severity findings.
- Agent CLI options that disable approvals or sandboxing receive high-severity
  findings in source/scripts. Markdown instructions are not scanned by this pack.

These are review heuristics, not proof of malicious intent. No configured command
is executed, no URL is requested, and no global user configuration is read.
Descriptions omit configuration values to avoid exposing inline secrets. Malformed
configuration is ignored rather than executed or treated as a validation failure.
Repository ignore comments and example-directory context cannot suppress or lower
these findings.

The CLI accepts the usual output, severity, fail-on and `--no-upload` options. MCP
`scan_ai` accepts `target`, `format`, `timeout` (reserved), and `fail_on`, matching the
other built-in scans. Results use the existing malware scan category and include
the `ai-agent` rule-pack metadata.
