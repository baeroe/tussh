# tussh

A terminal SSH connection manager for **you** and an MCP server for your **AI agents**. Both work from one connection list, and each connection has its own access rules for agents.

- **You** run `tussh` in any terminal. You can add, edit and delete SSH connections (password or key), press **Enter** to open an interactive session, start and stop port forwards, approve or deny agent requests, and read the audit history.
- **Agents** connect through `tussh mcp` (stdio). They only see the connections you shared with them. Each command is run automatically, sent to you for approval, or refused, depending on the connection's **access level** and on the **sensitive command rules**.

tussh is a single Go binary and needs nothing else at runtime. It works without [herdr](https://herdr.dev). If you use herdr, [herdr-tussh](https://github.com/baeroe/herdr-tussh) adds key bindings, and an approval popup appears when an agent is waiting for you.

## Why

When an agent can `ssh` into your servers, it holds the same rights you do. tussh puts a policy layer in between: read-only commands can run automatically, risky ones need your approval, and connections you never shared stay invisible to agents. Every agent request is logged.

## Access levels

You set the level per connection (TUI: **l** cycles through the levels, or use the edit form). New connections start at `none`.

| Level | Read-only command | Any other command | Sensitive command |
|---|---|---|---|
| `none` | hidden: the agent cannot see or use the connection | hidden | hidden |
| `read-only` | runs automatically | needs approval | needs approval |
| `approve-each` | needs approval | needs approval | needs approval |
| `trusted` | runs automatically | runs automatically | needs approval |

**Read-only** uses the strict allowlist from herdr-ssh:

- The command must be a single command from the allowlist: `cat head tail wc grep egrep fgrep zcat ls stat file readlink realpath basename dirname md5sum sha1sum sha256sum cut echo pwd which df du free uptime uname whoami id groups w who last nproc lscpu lsblk vmstat ps pgrep lsof netstat ss tree sort find hostname date journalctl systemctl docker`.
- Some of these have argument restrictions: `find` without `-exec`/`-delete`/`-fprint*`, `systemctl` only for status-style subcommands, `docker` only for `ps`/`images`/`logs`/`inspect`/`version`/`info`/`stats --no-stream`, and so on.
- Any of `;` `&` `|` `<` `>` `` ` `` `$` `\`, a newline or a NUL byte anywhere in the command means it is **not read-only**. Such a command is not blocked. It goes to approval instead.
- When a read-only command runs automatically, it is re-quoted word by word. For example, `ls *.log` lists a file literally named `*.log` and does not expand a glob.

On `trusted` connections, and for every approved command, tussh sends exactly the command you saw to the remote shell.

## Sensitive commands

The sensitive command rules apply at **every** level. A command that matches always needs approval, even on `trusted`.

| Category | Examples |
|---|---|
| `secrets` | `.env*`, `*.pem`, `*.key`, `id_rsa`/`id_ed25519`, `/etc/shadow`, `credentials`, `.pgpass`, `.my.cnf`, `env.php`, `wp-config.php`, `env`/`printenv`, `ps e`, `/proc/*/environ`, `docker inspect`, `docker compose config`, `*_history` |
| `delete` | `rm`, `rmdir`, `unlink`, `shred`, `truncate`, `find -delete`, `find -exec rm`, `git clean`, `git reset --hard`, `git push --force`, `rsync --delete`, `dd of=`, `mkfs`, `fdisk` |
| `database` | `DROP …`, `TRUNCATE`, `DELETE FROM` (with or without `WHERE`), `UPDATE … SET` without `WHERE`, destructive statements in `mysql`/`psql`/`sqlite3`/`mongosh`/`redis-cli` invocations, `dropdb`, `artisan migrate:fresh`, `db:wipe`, `doctrine:schema:drop` |
| `docker` | `docker rm`/`rmi`, `… prune`, `volume rm`, `compose down` (with or without `-v`), `compose rm`, `kubectl delete/apply/…`, `helm uninstall/upgrade` |
| `system` | `systemctl stop/restart/disable/…`, `service X stop`, `reboot`, `shutdown`, `kill`/`pkill`/`killall`, `docker stop/kill/restart`, `crontab` (except `-l`), firewall changes, user and password changes |
| `permissions` | `chmod -R`/`chown -R`, world-writable modes (`777`, `o+w`, …), any permission change on a system path |
| `packages` | `apt remove/purge/autoremove`, `yum/dnf remove`, `apk del`, `pacman -R`, `pip uninstall`, `npm uninstall -g`, `brew uninstall`, `dpkg -r`, `rpm -e` |
| `system-write` | redirects (`>`, `>>`, `&>`) into `/etc`, `/usr`, `/var/lib`, `/var/log`, `/dev/sd*`, … or `authorized_keys`, `tee` and `sed -i` on such paths, and `cp`/`mv`/`ln` into such paths |
| `remote-code` | `curl … \| sh`, `wget … \| bash`, `bash <(curl …)`, `sh -c "$(curl …)"` |
| `unsure` | `sh -c`, `eval`, `python -c`, `perl -e`, `base64 -d`, pipes into a shell, `$(…)`, backticks, `<(…)`, `$'…'`, here-docs into a shell, `su`, `sudo -i`, a variable used as the command, unparseable quoting, and an invalid rules file |

Rules are checked against every simple command in the line, so `ls && rm x` is caught. Wrappers such as `sudo`, `env`, `nohup`, `timeout`, `xargs`, `nice`, `command` and `VAR=x` prefixes are unwrapped first. Commands run inside `docker exec`, `docker compose exec`, `kubectl exec` or `ssh` are checked as well. Paths are resolved to the base command name (`/bin/rm` counts as `rm`), and quotes and backslashes are removed before matching (`"r"m` and `r\m` count as `rm`).

**When in doubt, tussh asks.** If the classifier cannot see what a command really does, it reports an `unsure` finding, and the command needs approval.

### Your own rules: `~/.config/tussh/rules.json`

```json
{
  "rules": [
    { "id": "terraform-destroy", "description": "terraform destroy", "category": "infra",
      "command": "terraform", "args_pattern": "\\bdestroy\\b" },
    { "id": "prod-deploy", "description": "production deploy script", "pattern": "deploy\\.sh\\s+prod" },
    { "id": "maintenance", "command": ["artisan", "console"], "args_pattern": "^down$" }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Shown in approvals and the audit log. Defaults to `user-N`. |
| `description`, `category` | Shown in the approval request. The category defaults to `user`. |
| `pattern` | An [RE2](https://github.com/google/re2/wiki/Syntax) regex matched against the whole command line |
| `command` | A command name or a list of names, matched against each simple command (after unwrapping, by base name) |
| `args_pattern` | Optional, needs `command`. A regex matched against that command's arguments, joined by spaces. |
| `case_sensitive` | Defaults to `false`, so patterns ignore case. |

Each rule needs `pattern`, `command`, or both. User rules only add approvals. They cannot switch off a built-in rule.

If the file is invalid (broken JSON, an unknown field or a bad regex), **every** agent command needs approval until you fix it, and the TUI shows a warning.

## Approval flow

1. An agent calls `run_command`. tussh classifies the command and applies the access level.
2. If the command needs approval, tussh writes a request to `~/.local/state/tussh/approvals/` (files with mode 0600 and atomic writes), and the MCP call **blocks**.
3. The TUI's **Alerts** tab lists the pending requests with the connection, the command, why approval is needed, the requesting agent (MCP `clientInfo`) and the agent's optional justification. When a new request arrives while the TUI is open, a **popup** appears. Keys: **a** approve, **d** deny, **Esc** later.
4. If no TUI is open, tussh sends a macOS notification (`osascript`). If herdr is available (`$HERDR_BIN_PATH`, `herdr` on PATH or `~/.local/bin/herdr`), tussh also invokes the `herdr-tussh.alerts` action, which opens `tussh alerts` as a popup inside herdr. Both fail silently.
5. Without a decision within **120 s**, the request is denied automatically, and the agent gets a clear message. You can change the timeout with `approval_timeout_seconds` in `~/.config/tussh/settings.json` or the `TUSSH_APPROVAL_TIMEOUT` environment variable.

Exactly one decision wins. Decisions are created exclusively with `link(2)`, so a late approval cannot race with the timeout. You can also approve requests from a shell: `tussh pending`, `tussh approve ID`, `tussh deny ID`. `tussh alerts` opens the TUI directly on the Alerts tab. `tussh alerts --popup` also quits once every request it showed is decided (used by the herdr popup).

`~/.config/tussh/settings.json` (optional):

```json
{ "approval_timeout_seconds": 120, "disable_notifications": false, "disable_herdr": false }
```

## Audit log

tussh appends every agent request to `~/.local/state/tussh/audit.jsonl`. Each entry records the time, connection, access level, command, decision (`auto`, `approved`, `denied`, `timeout` or `blocked`), who decided, the reasons, the agent, the justification, the exit code, whether the command timed out, and its duration. Command output is not logged. You can browse the log in the **History** tab (**Enter** shows details).

## Connections and secrets

- Connections are stored in `~/.config/tussh/connections.json` (mode 0600). Each one has a name, host, port, user, auth (`key` or `password`), a key path, an optional group and description, the access level and tunnels. **The file contains no secrets.**
- **Passwords and key passphrases** are stored in the macOS Keychain under the service `tussh` (via [go-keyring](https://github.com/zalando/go-keyring); on Linux, the Secret Service).
- **Password auth works without prompts.** tussh starts `ssh` with `SSH_ASKPASS=<tussh binary>` and `SSH_ASKPASS_REQUIRE=force`, which requires OpenSSH 8.4 or later. ssh then calls tussh back, and tussh reads the secret from the keychain. Each ssh process gets a one-time token file in the state dir, and the askpass mode only answers for a live token. Secrets never appear in arguments, logs or the UI.
- Key connections without a passphrase use `BatchMode=yes`. An empty key path means ssh's own defaults (ssh-agent, `~/.ssh/id_*`).
- Host keys must already be known. Agent runs never accept a new host key, so connect once yourself from the TUI first. In interactive sessions, ssh asks you as usual.
- **Import:** press **i** on the Connections tab to pick hosts from `~/.ssh/config`. tussh only reads that file. It resolves each host with `ssh -G` and imports it with access level `none`.

Paths can be overridden with `TUSSH_CONFIG_DIR` and `TUSSH_STATE_DIR` (or `XDG_CONFIG_HOME`/`XDG_STATE_HOME`). The tests use `TUSSH_KEYRING=file:<path>`, a plaintext file backend. **Use it for testing only.**

## TUI

| Tab | Keys |
|---|---|
| Connections | **Enter** connect (interactive `ssh` in this terminal; you return to the TUI afterwards) · **n** new · **e** edit · **x** delete (with confirmation; also removes the stored secrets) · **l** cycle the agent access level · **i** import from `~/.ssh/config` |
| Tunnels | **Enter** start or stop. Tunnels run as background `ssh -N -L` processes, tracked by pid files in the state dir, so they keep running after the TUI exits. Define them in the connection form as `name=local:host:port, …`. Agents cannot start tunnels. |
| Alerts | **a** approve · **d** deny · **Enter** details |
| History | **Enter** details |
| Setup | **Enter** copies the registration snippet |
| all | **Tab**/**Shift+Tab** or **1-5** switch tabs · **q** quit |

In the form: **Tab**/**↑↓** move between fields, **←→** change a choice, **Ctrl+S** save, **Esc** cancel. Leave the password or passphrase field empty to keep the stored value.

## MCP setup

Register once per harness. The **Setup** tab shows the same snippets with your real binary path and copies them to the clipboard.

| Harness | Command / config |
|---|---|
| Claude Code | `claude mcp add --scope user tussh -- ~/.local/bin/tussh mcp` |
| Codex CLI | `codex mcp add tussh -- ~/.local/bin/tussh mcp`, or in `~/.codex/config.toml`: `[mcp_servers.tussh]` with `command = "…/tussh"` and `args = ["mcp"]` |
| Gemini CLI | `gemini mcp add -s user tussh ~/.local/bin/tussh mcp`, or `{"mcpServers": {"tussh": {"command": "…/tussh", "args": ["mcp"]}}}` in `~/.gemini/settings.json` |
| opencode | `{"mcp": {"tussh": {"type": "local", "command": ["…/tussh", "mcp"], "enabled": true}}}` in `~/.config/opencode/opencode.json` |
| Cursor | `{"mcpServers": {"tussh": {"type": "stdio", "command": "…/tussh", "args": ["mcp"]}}}` in `~/.cursor/mcp.json` |

Use the absolute path (shown in the Setup tab). These formats were checked against each harness's docs in October 2026. Two details are unverified: whether Gemini's `mcp add` defaults to stdio for a path, and whether Cursor still accepts entries without `"type"`.

MCP tools:

| Tool | Does |
|---|---|
| `list_connections` | Returns the name, group, description and access level of every connection that is not `none`. It returns no hosts, users or secrets. |
| `run_command(connection, command, justification?, timeout?)` | Classifies the command, then runs it, waits for approval, or refuses it. It runs `ssh -T` with `ConnectTimeout=10`, `ClearAllForwardings=yes`, `ControlPath=none` and `ForwardAgent=no`, and with stdin closed. The remote timeout defaults to 30 s (max 600 s), and on timeout the whole process group is killed. stdout and stderr are capped at 20 kB each (head and tail are kept). Returns `exit_code`, `stdout`, `stderr`, `timed_out`, `truncated` and `decision`. |

There is deliberately no tool for interactive sessions or tunnels. A broken `connections.json` exposes nothing (fail closed).

## Security notes

- **The only hard boundary is on the server.** tussh limits what *this MCP server* does. It is not a sandbox. An agent with a local shell can run `ssh` itself. It can also read what the user account can read, and that includes the Keychain items tussh created (for example with `security find-generic-password`). For real limits, give agents a dedicated remote user with minimal rights, `sudo` restrictions, forced commands or `restrict` in `authorized_keys`, and read-only database users.
- **The classifier is best-effort.** It only sees the command line, not the contents of scripts (`./deploy.sh`) or what a program does at runtime. It is conservative: when it is unsure, it asks. Treat `trusted` as "mostly delegated".
- **Permission-skipping flags.** Harnesses started with `--dangerously-skip-permissions`, `--yolo` or similar approve every MCP call on their side. tussh's own approvals still apply, but such agents also have a local shell (see the first point).
- **Use separate keys per area.** Use different keys for company, client and private servers, so revoking one area does not affect the others.
- The askpass token, the approval files and the audit log all live in the state dir with mode 0600.

## Install

Requires Go 1.26+ and OpenSSH 8.4+.

```sh
make install          # builds to ~/.local/bin/tussh
# or: go build -o ~/.local/bin/tussh .
```

`make build` builds `bin/tussh`, and `make test` runs all tests.

## Tests

```sh
make test             # gofmt + go vet + go test -race ./... (incl. the docker integration test)
make test-unit        # same without the integration test (TUSSH_INTEGRATION=0)
```

| Where | Covers |
|---|---|
| `internal/classify` | The read-only allow/deny/bypass cases ported from herdr-ssh, re-quoting, about 150 sensitive and not-sensitive cases, user rules, fail-closed invalid rules |
| `internal/policy` | The access-level decision matrix and which command is sent |
| `internal/approval` | Submit/resolve, 30 concurrent resolvers with exactly one winner, wait/timeout/cancel, no partial reads during atomic writes, stale cleanup, TUI presence |
| `internal/config`, `internal/secrets` | Validation (no argv injection), 0600 store without secrets, the in-memory and file keyrings |
| `internal/sshrun` | ssh argv per auth/mode, exit codes, truncation, timeout kills the process group, askpass tokens |
| `internal/tui` | Model-level tests: forms (secrets go to the keyring), level cycling, delete, the approval popup, Alerts, Setup copy, ssh config import |
| `e2e_test.go` | The real binary as a stdio MCP subprocess: handshake, list, auto/approve/deny/timeout/cancel, askpass through the binary, fail-closed config, audit log |
| `integration_test.go` | A throwaway `alpine` sshd container with a **password user and a key user**: password auth via askpass, key auth, read-only auto, approve and deny with real effects, sensitive commands on trusted, remote timeout, approval timeout, a tunnel. Skipped without docker or with `TUSSH_INTEGRATION=0`. The container, the key and the temp dirs are removed afterwards. |

No test touches `~/.ssh`, the real Keychain or a running herdr. CI (`.github/workflows/tests.yml`, job `tests`) runs everything on ubuntu, including the integration test.

## License

MIT, see [LICENSE](LICENSE).
