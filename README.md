# mcpaudit 🔍

**A security scanner for the MCP servers you've already installed.**

MCP servers run with your privileges — they can shell out, write files, and hold your API tokens. Most people wire up a handful from random repos and never look back. `mcpaudit` reads your existing client configs and tells you, in one command, where the risk is.

[![npm version](https://img.shields.io/npm/v/@bitofacoder/mcpaudit.svg)](https://www.npmjs.com/package/@bitofacoder/mcpaudit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Model Context Protocol](https://img.shields.io/badge/MCP-Security-red.svg)](https://github.com/modelcontextprotocol)

## Quick start

No install required:

```bash
npx @bitofacoder/mcpaudit
```

It auto-discovers configs for **Claude Desktop, Claude Code, Cursor, and Windsurf**, then prints a severity-ranked report.

```
  mcpaudit  security scan of your MCP servers

  Scanned 2 config file(s), 5 server(s):
    • ~/Library/Application Support/Claude/claude_desktop_config.json
    • ~/.cursor/mcp.json

   HIGH  github (Claude Desktop)
        Secret "GITHUB_TOKEN" is stored in plaintext in the config file.
        Anyone with read access to this file can read the credential...
        rule: plaintext-secret

   MED   scraper (Cursor)
        Server runs @latest — it can change code on every launch without review.
        rule: unpinned-package

  Summary: 1 high, 1 medium
```

## What it checks

**Static (default — reads configs only, launches nothing):**

| Rule | Severity | Catches |
| --- | --- | --- |
| `plaintext-secret` | high | API tokens / keys / passwords stored in the config file |
| `insecure-transport` | high | Remote servers over plaintext `http://` |
| `unpinned-package` | medium | `npx`/`uvx` servers on `@latest` or with no pinned version |
| `shell-wrapped-launch` | medium | Servers launched through `bash -c` / `sh -c` |
| `remote-server` | info | Remote servers that receive your context off-machine |

**Deep (`--deep` — actually launches each stdio server and lists its tools):**

| Rule | Severity | Catches |
| --- | --- | --- |
| `dangerous-tool` | high | Tools that can run shell commands, write/delete files, or eval code |

## Usage

```bash
npx @bitofacoder/mcpaudit                       # static scan of all discovered configs
npx @bitofacoder/mcpaudit --deep                # also launch each server and audit its tools
npx @bitofacoder/mcpaudit --config ./mcp.json   # audit an extra config file (repeatable)
npx @bitofacoder/mcpaudit --json                # machine-readable output
npx @bitofacoder/mcpaudit --fail-on-high        # exit 1 if any high-severity issue (for CI)
```

### In CI

Gate a repo's MCP config on every push:

```yaml
- run: npx -y @bitofacoder/mcpaudit --config .mcp.json --fail-on-high
```

## Why deep scan matters

A config tells you *what's installed*; only the running server tells you *what it can do*. `--deep` connects to each stdio server over the MCP protocol, lists its real tools, and flags the ones that can act on your host (`exec`, `write_file`, `eval`, …).

A well-designed server keeps those behind an explicit opt-in. For example, [omni-mcp-server](https://github.com/bitofacoder/omni-mcp-server) hides its shell-exec and file-write tools unless you set `OMNI_AGENT_MODE=true` — so `mcpaudit --deep` reports it clean by default, and flags it only once you've turned the dangerous tools on. That's the pattern to look for.

## Privacy

`mcpaudit` runs entirely locally. It reads your config files and (with `--deep`) launches servers on your own machine. **Nothing is sent anywhere.** It never prints secret *values* — only the names of the keys that are stored in plaintext.

## Contributing

New rules are welcome — each one is a small function in [`src/rules.ts`](src/rules.ts). Good candidates: known-malicious package denylist, over-broad filesystem roots, tool-description prompt-injection patterns. Open an issue to discuss bigger checks.

## License

MIT — see [LICENSE](LICENSE).
