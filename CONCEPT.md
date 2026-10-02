# tussh: concept and roadmap

tussh succeeds the herdr-ssh prototype (a Python herdr plugin). It keeps that plugin's read-only allowlist, its ssh hardening and the harness snippets. What changes: tussh is a standalone Go binary that manages its own connections (instead of reading `~/.ssh/config`), stores secrets in the keychain, and asks a human before running risky commands instead of simply blocking them.

## Architecture

| | Human | Agent |
|---|---|---|
| Entry point | `tussh` TUI (any terminal, optional herdr wrapper) | `tussh mcp` (stdio, started by the harness) |
| Connections | `~/.config/tussh/connections.json` + keychain | the same, filtered by access level |
| Sessions | interactive `ssh` via `tea.ExecProcess` | `run_command` only (non-interactive) |
| Tunnels | Tunnels tab | none |
| Approvals | Alerts tab and popup, `tussh approve/deny` | blocking `run_command` |

The TUI and any number of MCP processes share state only through files in the state dir: `approvals/`, `audit.jsonl`, `tunnels/`, `askpass/` and `tui/` (heartbeats that tell an MCP process whether a TUI is open).

## Decisions

- **Approval instead of hard deny.** A command that is not read-only on a `read-only` connection asks you instead of failing. The agent keeps working and you stay in control.
- **Sensitive rules override every level.** `trusted` means "routine work runs without asking", not "anything goes".
- **Fail closed.** A broken connections file exposes nothing. A broken rules file makes everything need approval. An unknown access level counts as `none`. Classifier uncertainty means approval.
- **Exclusive decision files** (`link(2)`) instead of locks, so human decisions and timeouts race safely across processes.
- **Askpass with one-time tokens**, so `tussh askpass` is not a general-purpose "print my password" command. It is not a security boundary against a same-user process, which could read the keychain directly. See the README.
- **Minimal MCP implementation** (about 250 lines) instead of an SDK. tussh only needs initialize, ping, tools/list, tools/call and cancellation, and it has no extra dependencies.
- **`~/.config` on macOS too**, because this is a terminal tool and the files should be easy to find.

## Out of scope for now

- Agents starting tunnels, or an interactive session for agents (`open_pane`)
- `request_status` / asynchronous approvals. Today `run_command` blocks until it is decided or times out, so a harness with a shorter tool timeout than the approval timeout gives up first.
- Approve-and-remember ("always allow this command on this connection"), and approving an edited command
- Switching off built-in rules, per-connection rule sets, and safe-pipe allowlisting for read-only (`| grep`, `| head`)
- Jump hosts and ProxyJump per connection (tussh can use the ssh config through `TUSSH_SSH_CONFIG`, but the form has no field for it)
- Editing ssh options per connection, `known_hosts` management in the TUI, and SFTP/scp helpers for agents
- A tamper-evident (hash-chained) audit log, log rotation, and including output in the log
- Tunnel supervision (restart on drop, restore after reboot)
- Windows support

## Open questions

- Should `trusted` also send read-only commands in the re-quoted (no-glob) form? Today it sends them as-is.
- Should `docker compose down` without `-v` stay sensitive? It removes containers but not data.
- Should a denied request let you attach a note for the agent? The queue already supports `Note`, but the TUI has no input for it.
