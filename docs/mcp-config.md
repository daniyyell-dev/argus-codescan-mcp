# MCP server configuration review

```sh
argus scan mcp-config . --no-upload
argus scan mcp-config . --global --no-upload
```

The `scan_mcp_config` MCP tool offers the same checks. Project configuration also
participates in the code and malware scans. No server is started, package installed,
command executed, or remote endpoint contacted.

Supported project files are `.mcp.json`, `mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `.gemini/settings.json`, `claude_desktop_config.json`,
`cline_mcp_settings.json` and `.continue/config.json`, `.yaml` or `.yml`.
JSON comments/trailing commas and Continue YAML are supported. Server maps under
`mcpServers` or VS Code's `servers`, and Continue's server lists, are inspected.
Unrelated metadata and arbitrary hidden files are excluded.

| Finding | Severity |
| --- | --- |
| Unpinned npx, uvx, pipx run or Docker image operand | Medium |
| Shell invocation with a download command | High |
| Inline token, credential header, secret environment value or URL credential | High |
| Plain HTTP or raw-IP server endpoint | Medium |
| One-edit/transposition lookalike of a small known-package list | Low, low-confidence review |

Exact npm versions, exact Python versions (`==`, or uvx's `@` shorthand), Docker
tags other than common floating tags, and SHA-256 image digests are accepted.
Prefer Docker digests because tags can still be changed by their publisher.
Registry/cache options and explicit `--package`, `--from` and `--spec` operands
are distinguished from executable arguments. Unknown wrappers are outside this
heuristic's coverage.

Environment/input references such as `${env:GITHUB_TOKEN}` are accepted; literal
credentials are reported without their values appearing in findings. Existing
provider-token patterns are reused. HTTP loopback endpoints also receive a review
finding: local services can be legitimate, but are not silently exempted. Similarity
does not establish malicious intent, and exact known names are not flagged.

Global configuration is opt-in. `--global` adds existing named configs under the
user's `.cursor`, `.gemini` and `.continue` directories, `.claude.json`, and the
Claude/VS Code client configuration paths under macOS Application Support, Linux
`.config`, or Windows AppData. It never recursively walks the home directory, and
does not follow config-file symlinks. Global finding paths identify the original
file. The MCP tool uses `include_global: true` for the same explicit behavior;
it defaults to false. Other parameters are `target`, `format`, `timeout` (reserved),
and `fail_on`.

Malformed/unsupported configuration is skipped. Findings remain review heuristics,
not a completeness guarantee or an assertion that a server is safe. Repository
ignore comments and example-directory context cannot suppress or downgrade them.
