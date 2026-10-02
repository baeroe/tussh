#!/usr/bin/env bash
# Regenerates the README screenshots in docs/screenshots/ from the VHS tapes in docs/tapes/.
#
#   make screenshots                    # all tapes
#   bash docs/screenshots.sh alerts     # only docs/tapes/alerts.tape
#
# Needs go, vhs (brew install vhs; pulls ttyd and ffmpeg), ssh-keygen and optionally pngquant/oxipng.
#
# Everything runs in a throwaway sandbox: HOME, the tussh config/state dirs, a file keyring (never the real
# Keychain) and an ~/.ssh with freshly generated demo keys. The demo data comes from docs/demo/seed.go
# (connections, last use, a remembered command, audit log) plus a real `tussh mcp` process that adds an
# agent-created connection and leaves two approval requests pending. All hosts are *.example names.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"

sandbox=$(mktemp -d /tmp/tussh-demo.XXXXXX)
mcp_pid=
cleanup() {
	exec 3>&- 2>/dev/null || true
	[ -n "$mcp_pid" ] && kill "$mcp_pid" 2>/dev/null || true
	rm -rf "$sandbox"
}
trap cleanup EXIT

demo_home="$sandbox/home"
export TUSSH_CONFIG_DIR="$demo_home/.config/tussh"
export TUSSH_STATE_DIR="$demo_home/.local/state/tussh"
export TUSSH_KEYRING="file:$sandbox/keyring.json"
export TUSSH_SSH_DIR="$demo_home/.ssh"
export TUSSH_NO_NOTIFY=1
export TUSSH_APPROVAL_TIMEOUT=900
unset XDG_CONFIG_HOME XDG_STATE_HOME SSH_AUTH_SOCK
mkdir -p "$demo_home/.local/bin" "$demo_home/.ssh"
chmod 700 "$demo_home/.ssh"

# build and seed with the real HOME (Go caches), everything else only sees the sandbox HOME.
# The binary goes under the sandbox HOME, so the Setup tab shows ~/.local/bin/tussh.
go build -trimpath -o "$demo_home/.local/bin/tussh" .
go build -trimpath -o "$sandbox/bin/tussh-demo" docs/demo/tui.go
go run docs/demo/seed.go
real_home=$HOME
export HOME="$demo_home" TUSSH_DEMO_HOME="$demo_home"
export PATH="$HOME/.local/bin:$sandbox/bin:$PATH"

# demo keys for the key file suggestions in the form
ssh-keygen -q -t ed25519 -N '' -C 'me@laptop' -f "$HOME/.ssh/id_ed25519"
ssh-keygen -q -t ed25519 -N 'demo-passphrase' -C 'deploy@acme' -f "$HOME/.ssh/acme_deploy"
ssh-keygen -q -t rsa -b 3072 -N '' -C 'me@homelab' -f "$HOME/.ssh/homelab_rsa"

# a Claude Code registration, so the Setup tab shows a detected harness
printf '{"mcpServers":{"tussh":{"type":"stdio","command":"%s","args":["mcp"]}}}\n' "$HOME/.local/bin/tussh" >"$HOME/.claude.json"

# a real MCP session: one agent-created connection, two requests that stay pending while the tapes run
mkfifo "$sandbox/mcp.in"
tussh mcp <"$sandbox/mcp.in" >"$sandbox/mcp.out" 2>&1 &
mcp_pid=$!
exec 3>"$sandbox/mcp.in"
send() { printf '%s\n' "$1" >&3; }
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"claude-code","version":"2.1.4"}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized"}'
send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"new_connection","arguments":{"name":"monitoring","host":"metrics.acme.example","user":"ops","description":"Prometheus and Grafana for the shop","tags":["acme","prod"],"tunnels":["grafana=3001:localhost:3000"]}}}'
sleep 1
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_command","arguments":{"connection":"shop-db","command":"mysql shop -e \"DELETE FROM sessions WHERE updated_at < NOW() - INTERVAL 30 DAY\"","justification":"The sessions table has 4 GB of stale rows"}}}'
sleep 1
send '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_command","arguments":{"connection":"shop-prod","command":"systemctl restart php8.3-fpm","justification":"PHP-FPM workers hang since the deploy and /checkout returns 502. A restart frees them."}}}'
for _ in $(seq 50); do
	[ "$(find "$TUSSH_STATE_DIR/approvals" -name '*.json' ! -name '*.decision.json' 2>/dev/null | wc -l)" -ge 2 ] && break
	sleep 0.2
done
tussh pending

tapes=("$@")
if [ ${#tapes[@]} -eq 0 ]; then
	for f in docs/tapes/*.tape; do
		[ "$(basename "$f")" = config.tape ] || tapes+=("$(basename "$f" .tape)")
	done
fi
for t in "${tapes[@]}"; do
	echo "== $t"
	HOME="$real_home" vhs "docs/tapes/$t.tape" # VHS keeps its browser in the real HOME; the tapes switch to the sandbox
done
rm -rf .vhs

cd "$repo/docs/screenshots"
command -v pngquant >/dev/null && pngquant --force --skip-if-larger --quality 80-95 --ext .png ./*.png || true
command -v oxipng >/dev/null && oxipng -q -o 4 --strip safe ./*.png || true
ls -lh "$repo/docs/screenshots"
