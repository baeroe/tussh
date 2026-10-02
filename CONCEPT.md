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

The TUI and any number of MCP processes share state only through files in the state dir: `approvals/`, `allow/` (remembered commands), `audit.jsonl`, `tunnels/`, `askpass/`, `used/` (last use per connection) and `tui/` (heartbeats that tell an MCP process whether a TUI is open). `connections.json` is written by the TUI and by the MCP tool `new_connection`, always as a locked read-modify-write (`flock` on `connections.json.lock` + atomic rename); the TUI reloads it when it changes.

## Decisions

- **Approval instead of hard deny.** A command that is not read-only on a `read-only` connection asks you instead of failing. The agent keeps working and you stay in control.
- **Sensitive rules override every level.** `trusted` means "routine work runs without asking", not "anything goes".
- **Fail closed.** A broken connections file exposes nothing. A broken rules file makes everything need approval. An unknown access level counts as `none`. Classifier uncertainty means approval.
- **Exclusive decision files** (`link(2)`) instead of locks, so human decisions and timeouts race safely across processes.
- **Askpass with one-time tokens**, so `tussh askpass` is not a general-purpose "print my password" command. It is not a security boundary against a same-user process, which could read the keychain directly. See the README.
- **Minimal MCP implementation** (about 250 lines) instead of an SDK. tussh only needs initialize, ping, tools/list, tools/call and cancellation, and it has no extra dependencies.
- **`~/.config` on macOS too**, because this is a terminal tool and the files should be easy to find.
- **A flat connection list, no groups or environments.** Favorites on top, then most recently used. Tags are free text for search; prod/staging go into the name or a tag. Old `group` values are migrated to tags.
- **Remembered approvals are exact.** "Approve & remember" allows one exact command string on one connection until an expiry (default 8 h). No patterns or prefixes: anything that differs asks again. The entries are files in the state dir, so the separate MCP processes check them before creating a request.
- **Last use lives in the state dir**, not in `connections.json`, so frequent agent runs never write the connection file.
- **Agents may propose connections, never trust.** `new_connection` lets an agent add name, host, port, user, description, tags and tunnels. Access level, auth method, key file and secrets are not in the schema and are rejected if sent. The connection starts at `none` with `needs_setup`, so it is invisible to agents until the user sets it up; the user is notified like for an approval.
- **Reachability is a plain TCP connect** to host:port (no ssh, no login), in the background every 45 s and on `r`.
- **ANSI palette colors only**, so the TUI follows the terminal theme. Icons are limited to characters whose width all width tables agree on (default-emoji-presentation emoji are 2 cells, symbols 1), so columns stay aligned in Ghostty, herdr and elsewhere: 👀 stands for read-only and ⌛ for timeout instead of 👁/⏱, whose width depends on the terminal.

## Out of scope for now

- Agents starting tunnels, or an interactive session for agents (`open_pane`)
- Agents editing or deleting connections (they can only add new ones with `new_connection`)
- `request_status` / asynchronous approvals. Today `run_command` blocks until it is decided or times out, so a harness with a shorter tool timeout than the approval timeout gives up first.
- Approving an edited command, and remembering command patterns or prefixes (remembering is exact-match only)
- Switching off built-in rules, per-connection rule sets, and safe-pipe allowlisting for read-only (`| grep`, `| head`)
- Jump hosts and ProxyJump per connection (tussh can use the ssh config through `TUSSH_SSH_CONFIG`, but the form has no field for it)
- Editing ssh options per connection, `known_hosts` management in the TUI, and SFTP/scp helpers for agents
- A tamper-evident (hash-chained) audit log and log rotation (output is now logged, bounded to 4 kB per stream)
- Tunnel supervision (restart on drop, restore after reboot)
- Windows support

## Done

- TUI redesign: two panes (list and details) with a single-column layout below 90 columns, header with status chips, a help overlay, ANSI palette colors, the connection form as a sectioned dialog with a connection test (Ctrl+T)
- Favorites, last-used ordering, tags (with migration of the old `group` field), fuzzy search
- Background reachability check
- Alerts as cards with a countdown, deny with a note for the agent, approve & remember with revocation in the detail pane
- History as a filterable table with a detail pane and bounded output in the audit log (the connection's own secret is redacted; can be switched off)
- Setup shows paths with `~` and detects existing registrations by reading the harness configs
- Key file autocomplete in the form (detected keys, path completion, validation hint)
- `new_connection` MCP tool: agents add connections at level `none` that the user sets up

## Open questions

- Should `trusted` also send read-only commands in the re-quoted (no-glob) form? Today it sends them as-is.
- Should `docker compose down` without `-v` stay sensitive? It removes containers but not data.
- Should "approve & remember" also offer "until the end of the day" next to the fixed TTL?
- Reachability dials the `host` field. Connections that only work through an ssh config alias or a jump host show as unreachable; should the check use `ssh -G` to resolve them, or be switchable per connection?
- Registration detection only reads user-level configs. Project-level registrations (`.mcp.json`, project settings) are not shown.
