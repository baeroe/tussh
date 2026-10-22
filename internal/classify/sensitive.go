package classify

import (
	"path"
	"regexp"
	"strings"
)

// Rule categories.
const (
	CatSecrets     = "secrets"
	CatDelete      = "delete"
	CatDatabase    = "database"
	CatDocker      = "docker"
	CatSystem      = "system"
	CatPermissions = "permissions"
	CatPackages    = "packages"
	CatSystemWrite = "system-write"
	CatRemoteCode  = "remote-code"
	CatUnsure      = "unsure"
	CatUser        = "user"
)

// Finding is one matched sensitive rule.
type Finding struct {
	RuleID      string `json:"rule"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

// simple is one simple command after unwrapping wrappers like sudo/env/nohup.
type simple struct {
	name string   // basename of the command word
	args []string // remaining words
	seg  segment
	cwd  string // working directory followed from earlier cd segments ("" = login directory)
}

// cmdRule matches simple commands.
type cmdRule struct {
	id, cat, desc string
	match         func(c simple) bool
}

// reRule matches the raw command line.
type reRule struct {
	id, cat, desc string
	re            *regexp.Regexp
}

var (
	updateSetRE = regexp.MustCompile("(?is)\\bupdate\\s+[\\w.`\"]+\\s+set\\b")
	whereRE     = regexp.MustCompile(`(?i)\bwhere\b`)
)

// updateWithoutWhere flags an SQL UPDATE ... SET with no WHERE after it.
func updateWithoutWhere(cmd string) bool {
	loc := updateSetRE.FindStringIndex(cmd)
	return loc != nil && !whereRE.MatchString(cmd[loc[1]:])
}

func ci(expr string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + expr) }

// --- wrappers --------------------------------------------------------------------

// wrappers maps a command that runs another command to its options that take a value. skipPositional is the
// number of positional words between the wrapper's options and the wrapped command (timeout DURATION, chroot DIR).
var wrappers = map[string]struct {
	valueOpts      []string
	skipPositional int
}{
	"sudo":     {[]string{"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout"}, 0},
	"doas":     {[]string{"-u", "-C"}, 0},
	"env":      {[]string{"-u", "--unset", "-C", "--chdir"}, 0},
	"nohup":    {nil, 0},
	"time":     {[]string{"-f", "-o", "--format", "--output"}, 0},
	"nice":     {[]string{"-n", "--adjustment"}, 0},
	"ionice":   {[]string{"-c", "-n", "-p", "--class", "--classdata"}, 0},
	"timeout":  {[]string{"-s", "-k", "--signal", "--kill-after"}, 1},
	"stdbuf":   {[]string{"-i", "-o", "-e"}, 0},
	"command":  {nil, 0},
	"builtin":  {nil, 0},
	"exec":     {[]string{"-a"}, 0},
	"xargs":    {[]string{"-I", "-n", "-P", "-d", "-a", "-L", "-s", "-E", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"}, 0},
	"watch":    {[]string{"-n", "--interval", "-d"}, 0},
	"unbuffer": {nil, 0},
	"setsid":   {nil, 0},
	"chroot":   {[]string{"--userspec", "--groups"}, 1},
	"flock":    {[]string{"-w", "--timeout", "-E", "--conflict-exit-code"}, 1},
	"runuser":  {[]string{"-u", "-g", "-G", "--user", "--group"}, 0},
	"chrt":     {nil, 1},
	"taskset":  {nil, 1},
	// shell keywords in front of a command (segments split at ; and newlines, not at keywords)
	"do":    {nil, 0},
	"then":  {nil, 0},
	"else":  {nil, 0},
	"elif":  {nil, 0},
	"if":    {nil, 0},
	"while": {nil, 0},
	"until": {nil, 0},
	"!":     {nil, 0},
}

var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// unwrap strips assignments and wrapper commands. A wrapper without a wrapped command is returned itself
// (so a bare "env" is still visible as "env").
func unwrap(words []string) []string {
	for len(words) > 0 {
		for len(words) > 0 && assignRE.MatchString(words[0]) {
			words = words[1:]
		}
		if len(words) == 0 {
			return nil
		}
		w, ok := wrappers[path.Base(words[0])]
		if !ok {
			return words
		}
		rest := words[1:]
		valueOpt := map[string]bool{}
		for _, o := range w.valueOpts {
			valueOpt[o] = true
		}
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") && rest[0] != "-" {
			o := rest[0]
			rest = rest[1:]
			if o == "--" {
				break
			}
			if valueOpt[o] && len(rest) > 0 {
				rest = rest[1:]
			}
		}
		for len(rest) > 0 && assignRE.MatchString(rest[0]) {
			rest = rest[1:] // env FOO=1 cmd, sudo FOO=1 cmd
		}
		if len(rest) <= w.skipPositional {
			return words // wrapper alone
		}
		words = rest[w.skipPositional:]
	}
	return words
}

func toSimple(words []string, seg segment, cwd string) (simple, bool) {
	words = unwrap(words)
	if len(words) == 0 {
		return simple{}, false
	}
	return simple{name: path.Base(words[0]), args: words[1:], seg: seg, cwd: cwd}, true
}

// executors run a further command given as trailing words (docker exec CTR CMD...). Their trailing words are
// checked as commands too, at every position, so "docker exec web rm -rf /x" is caught.
func isExecutor(c simple) bool {
	sub := firstPositional(c.args)
	switch c.name {
	case "docker", "podman", "nerdctl":
		if sub == "exec" || sub == "run" {
			return true
		}
		if sub == "compose" {
			s2 := firstPositional(afterFirst(c.args, "compose"))
			return s2 == "exec" || s2 == "run"
		}
	case "docker-compose", "podman-compose":
		return sub == "exec" || sub == "run"
	case "kubectl", "oc":
		return sub == "exec" || sub == "run" || sub == "debug"
	case "ssh", "nsenter", "lxc-attach", "incus", "lxc", "vagrant", "multipass":
		return true
	}
	return false
}

func firstPositional(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// positionals returns args that do not start with "-".
func positionals(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func afterFirst(args []string, word string) []string {
	for i, a := range args {
		if a == word {
			return args[i+1:]
		}
	}
	return nil
}

func hasArg(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n || (strings.HasPrefix(n, "--") && strings.HasPrefix(a, n+"=")) {
				return true
			}
		}
	}
	return false
}

// hasShort reports whether a short option cluster (-rf) contains any of the letters.
func hasShort(args []string, letters string) bool {
	for _, a := range args {
		if shortClusterHas(a, letters) {
			return true
		}
	}
	return false
}

func in(s string, list ...string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}

// --- system paths ------------------------------------------------------------------

var systemPathRE = regexp.MustCompile(`^(/etc|/usr|/bin|/sbin|/lib|/lib32|/lib64|/boot|/sys|/proc|/root|/opt|/srv|/var/spool|/var/lib|/var/log|/var/www|/dev)(/|$)`)

var harmlessDev = regexp.MustCompile(`^/dev/(null|stdout|stderr|stdin|tty|fd/\d+|zero|u?random)$`)

func isSystemPath(p string) bool {
	p = strings.Trim(p, `"'`)
	if strings.Contains(p, "authorized_keys") || strings.Contains(p, ".ssh/") {
		return true
	}
	if p == "/" {
		return true
	}
	if harmlessDev.MatchString(p) {
		return false
	}
	return systemPathRE.MatchString(p)
}

// cwdUnknown marks a working directory the classifier cannot follow (cd "$DIR", cd -, cd ../..).
const cwdUnknown = "?"

// nextCwd follows cd/pushd, so relative paths after "cd /etc/nginx" are checked as system paths too.
// "" is the login directory, which tussh treats like any non-system directory.
func nextCwd(cwd string, words []string) string {
	words = unwrap(words)
	if len(words) == 0 || !in(path.Base(words[0]), "cd", "pushd", "chdir") {
		return cwd
	}
	if in("-", words[1:]...) {
		return cwdUnknown
	}
	p := positionals(words[1:])
	if len(p) == 0 {
		return ""
	}
	d := strings.Trim(p[0], `"'`)
	switch {
	case d == "~" || strings.HasPrefix(d, "~/") && !strings.Contains(d, ".."):
		return ""
	case strings.ContainsAny(d, "$`~*?["):
		return cwdUnknown
	case path.IsAbs(d):
		return path.Clean(d)
	case cwd == "":
		if strings.Contains(d, "..") {
			return cwdUnknown // may climb out of the login directory into a system path
		}
		return ""
	case cwd == cwdUnknown:
		return cwdUnknown
	}
	return path.Join(cwd, d)
}

// isSystemPathIn is isSystemPath for a path argument, with relative paths resolved against a followed cd.
// After a cd the classifier cannot follow, every relative path counts as a system path.
func isSystemPathIn(cwd, p string) bool {
	if isSystemPath(p) {
		return true
	}
	p = strings.Trim(p, `"'`)
	if cwd == "" || p == "" || path.IsAbs(p) || strings.HasPrefix(p, "~") {
		return false
	}
	if cwd == cwdUnknown {
		return true
	}
	return isSystemPath(path.Join(cwd, p))
}

func (c simple) isSystemPath(p string) bool { return isSystemPathIn(c.cwd, p) }

// --- built-in rules ------------------------------------------------------------------

var (
	psValueOpts  = []string{"-o", "-O", "-u", "-U", "-g", "-G", "-p", "-q", "-t", "-C", "-s", "-k", "-N", "--format", "--pid", "--ppid", "--user", "--User", "--group", "--Group", "--sort", "--tty", "--sid", "--quick-pid", "--cols", "--columns", "--rows", "--lines", "--width"}
	bsdClusterRE = regexp.MustCompile(`^[A-Za-z]+$`)
)

var dbClients = []string{"mysql", "mariadb", "psql", "sqlite3", "sqlite", "mongo", "mongosh", "redis-cli", "clickhouse-client", "cqlsh", "sqlcmd", "usql"}

var dbDestructiveRE = ci(`\b(drop|truncate|delete|flushall|flushdb|dropdatabase|deletemany|deleteone|unlink)\b`)

var builtinCmdRules = []cmdRule{
	// secrets
	{"env-dump", CatSecrets, "prints environment variables (may contain secrets)", func(c simple) bool {
		switch c.name {
		case "printenv":
			return true
		case "env":
			return len(positionals(c.args)) == 0
		case "set", "export", "declare", "typeset":
			return len(c.args) == 0 || hasArg(c.args, "-p", "-x")
		case "compgen":
			return hasArg(c.args, "-v", "-e")
		}
		return false
	}},
	{"ps-environ", CatSecrets, "ps with 'e' shows process environments (may contain secrets)", func(c simple) bool {
		if c.name != "ps" {
			return false
		}
		value := false // the word is the value of the previous option (-o pid,etime / -u user / BSD o)
		for _, a := range c.args {
			if value {
				value = false
				continue
			}
			if strings.HasPrefix(a, "-") {
				value = in(a, psValueOpts...)
				continue
			}
			// a BSD option cluster (aux, auxe, e): letters only; a value letter takes the rest or the next word
			if !bsdClusterRE.MatchString(a) {
				continue
			}
			for i, l := range a {
				if l == 'e' {
					return true
				}
				if strings.ContainsRune("oOpqtUk", l) {
					value = i == len(a)-1
					break
				}
			}
		}
		return false
	}},
	{"docker-inspect", CatSecrets, "docker inspect / compose config can print container environment (secrets)", func(c simple) bool {
		if !in(c.name, "docker", "podman", "nerdctl", "docker-compose") {
			return false
		}
		p := positionals(c.args)
		return (len(p) > 0 && p[0] == "inspect") || (len(p) > 1 && p[1] == "inspect") ||
			(len(p) > 1 && p[0] == "compose" && p[1] == "config") || (c.name == "docker-compose" && len(p) > 0 && p[0] == "config")
	}},
	// deletion
	{"rm", CatDelete, "deletes files (rm/rmdir/unlink/shred/truncate)", func(c simple) bool {
		return in(c.name, "rm", "rmdir", "unlink", "shred", "srm", "wipe", "truncate", "trash", "trash-put")
	}},
	{"find-delete", CatDelete, "find -delete or -exec rm", func(c simple) bool {
		if c.name != "find" {
			return false
		}
		for i, a := range c.args {
			if a == "-delete" {
				return true
			}
			if in(a, "-exec", "-execdir", "-ok", "-okdir") && i+1 < len(c.args) && in(path.Base(c.args[i+1]), "rm", "rmdir", "unlink", "shred", "truncate") {
				return true
			}
		}
		return false
	}},
	{"git-destructive", CatDelete, "git clean / reset --hard / push --force / branch -D (discards or deletes work)", func(c simple) bool {
		if c.name != "git" {
			return false
		}
		sub := firstPositional(c.args)
		rest := afterFirst(c.args, sub)
		switch sub {
		case "clean":
			return true
		case "reset":
			return hasArg(rest, "--hard")
		case "push":
			return hasArg(rest, "--force", "--force-with-lease", "--delete", "--mirror") || hasShort(rest, "fd")
		case "branch":
			return hasArg(rest, "-D", "--delete") || hasShort(rest, "D")
		case "checkout":
			return hasArg(rest, "--", ".", "-f", "--force")
		case "stash":
			return in(firstPositional(rest), "clear", "drop")
		}
		return false
	}},
	{"rsync-delete", CatDelete, "rsync with --delete", func(c simple) bool {
		if c.name != "rsync" {
			return false
		}
		for _, a := range c.args {
			if strings.HasPrefix(a, "--delete") || a == "--remove-source-files" {
				return true
			}
		}
		return false
	}},
	{"disk", CatDelete, "disk/filesystem destructive command (dd, mkfs, fdisk, wipefs, ...)", func(c simple) bool {
		if c.name == "dd" {
			for _, a := range c.args {
				if strings.HasPrefix(a, "of=") {
					return true
				}
			}
			return false
		}
		if strings.HasPrefix(c.name, "mkfs") || strings.HasPrefix(c.name, "mkswap") {
			return true
		}
		if in(c.name, "zfs", "zpool") {
			return in(firstPositional(c.args), "destroy", "rollback")
		}
		return in(c.name, "fdisk", "sfdisk", "gdisk", "sgdisk", "parted", "wipefs", "lvremove", "vgremove", "pvremove", "blkdiscard", "cryptsetup")
	}},
	// databases
	{"db-drop-cmd", CatDatabase, "drops a database or user (dropdb/dropuser/mysqladmin drop)", func(c simple) bool {
		if in(c.name, "dropdb", "dropuser", "dropdb.exe") {
			return true
		}
		return c.name == "mysqladmin" && hasArg(c.args, "drop")
	}},
	{"db-client-destructive", CatDatabase, "DROP/TRUNCATE/DELETE/FLUSH in a database client invocation", func(c simple) bool {
		if !in(c.name, dbClients...) {
			return false
		}
		return dbDestructiveRE.MatchString(strings.Join(c.args, " "))
	}},
	// docker / containers
	{"docker-destructive", CatDocker, "docker/compose destructive operation (rm, rmi, prune, down, volume rm, ...)", func(c simple) bool {
		if !in(c.name, "docker", "podman", "nerdctl", "docker-compose", "podman-compose") {
			return false
		}
		p := positionals(c.args)
		if len(p) == 0 {
			return false
		}
		compose := c.name == "docker-compose" || c.name == "podman-compose"
		if !compose && p[0] == "compose" {
			compose = true
			p = p[1:]
		}
		if len(p) == 0 {
			return false
		}
		if compose {
			return in(p[0], "down", "rm")
		}
		if in(p[0], "rm", "rmi") {
			return true
		}
		if in(p[0], "container", "image", "volume", "network", "builder", "system", "buildx", "plugin", "secret", "config", "context", "swarm", "service", "stack", "node") && len(p) > 1 {
			return in(p[1], "rm", "remove", "prune", "kill", "leave", "disable")
		}
		return p[0] == "prune"
	}},
	{"kubernetes-destructive", CatDocker, "kubectl/helm changes or deletes cluster resources", func(c simple) bool {
		sub := firstPositional(c.args)
		switch c.name {
		case "kubectl", "oc":
			return in(sub, "delete", "drain", "cordon", "replace", "scale", "patch", "apply", "edit", "rollout", "annotate", "label", "taint")
		case "helm":
			return in(sub, "uninstall", "delete", "rollback", "upgrade", "install")
		}
		return false
	}},
	// services / system
	{"service-stop", CatSystem, "stops/restarts/disables a service or container", func(c simple) bool {
		sub := firstPositional(c.args)
		switch c.name {
		case "systemctl":
			return in(sub, "stop", "restart", "try-restart", "reload-or-restart", "try-reload-or-restart", "disable", "mask",
				"kill", "reboot", "poweroff", "halt", "isolate", "emergency", "rescue", "kexec", "suspend", "hibernate", "daemon-reexec", "set-default", "edit", "revert", "reset-failed", "preset", "preset-all", "link")
		case "service":
			p := positionals(c.args)
			return len(p) > 1 && in(p[1], "stop", "restart", "force-reload", "force-stop")
		case "rc-service":
			p := positionals(c.args)
			return len(p) > 1 && in(p[1], "stop", "restart", "zap")
		case "docker", "podman", "nerdctl":
			p := positionals(c.args)
			if len(p) > 1 && p[0] == "compose" {
				return in(p[1], "stop", "kill", "restart", "pause")
			}
			if len(p) > 1 && p[0] == "container" {
				return in(p[1], "stop", "kill", "restart", "pause")
			}
			return in(sub, "stop", "kill", "restart", "pause")
		case "docker-compose", "podman-compose":
			return in(sub, "stop", "kill", "restart", "pause")
		case "supervisorctl":
			return in(sub, "stop", "restart", "shutdown", "remove", "reload")
		case "pm2":
			return in(sub, "stop", "delete", "kill", "restart", "reload", "flush")
		case "launchctl":
			return in(sub, "unload", "stop", "remove", "bootout", "disable", "kill")
		}
		return false
	}},
	{"power", CatSystem, "reboot/shutdown", func(c simple) bool {
		if in(c.name, "reboot", "shutdown", "poweroff", "halt") {
			return true
		}
		return in(c.name, "init", "telinit") && len(c.args) > 0 && in(c.args[0], "0", "1", "6", "s", "S")
	}},
	{"kill", CatSystem, "kills processes (kill/pkill/killall)", func(c simple) bool {
		return in(c.name, "kill", "pkill", "killall", "killall5", "skill", "xkill")
	}},
	{"crontab", CatSystem, "replaces or removes a crontab", func(c simple) bool {
		return c.name == "crontab" && !hasArg(c.args, "-l")
	}},
	{"firewall", CatSystem, "changes firewall rules", func(c simple) bool {
		switch c.name {
		case "iptables", "ip6tables", "iptables-legacy", "iptables-nft":
			return hasArg(c.args, "-F", "--flush", "-X", "--delete-chain", "-D", "--delete", "-P", "--policy", "-A", "--append", "-I", "--insert", "-R", "--replace", "-Z")
		case "nft":
			return in(firstPositional(c.args), "flush", "delete", "add", "insert", "replace", "destroy", "-f")
		case "ufw":
			return in(firstPositional(c.args), "disable", "reset", "delete", "deny", "reject", "allow", "limit", "default", "enable")
		case "firewall-cmd":
			return true
		}
		return false
	}},
	{"users", CatSystem, "changes users, groups or passwords", func(c simple) bool {
		return in(c.name, "userdel", "deluser", "groupdel", "delgroup", "passwd", "chpasswd", "usermod", "useradd", "adduser", "groupmod", "gpasswd", "chage", "visudo", "vipw")
	}},
	{"mount-net", CatSystem, "unmounts filesystems or takes interfaces down", func(c simple) bool {
		if in(c.name, "umount", "swapoff", "ifdown") {
			return true
		}
		if c.name == "ip" {
			return hasArg(c.args, "down", "del", "delete", "flush")
		}
		return c.name == "sysctl" && hasArg(c.args, "-w", "--write", "-p", "--load")
	}},
	// permissions
	{"perm-recursive", CatPermissions, "recursive or world-writable permission/ownership change", func(c simple) bool {
		if !in(c.name, "chmod", "chown", "chgrp", "setfacl", "chattr") {
			return false
		}
		if hasArg(c.args, "--recursive") || hasShort(c.args, "R") {
			return true
		}
		for _, a := range c.args {
			if in(a, "777", "0777", "666", "0666", "a+rwx", "a+w", "o+w", "ugo+rwx", "+w") {
				return true
			}
		}
		return false
	}},
	{"perm-system", CatPermissions, "permission/ownership change on a system path", func(c simple) bool {
		if !in(c.name, "chmod", "chown", "chgrp", "setfacl", "chattr") {
			return false
		}
		for _, a := range positionals(c.args) {
			if c.isSystemPath(a) {
				return true
			}
		}
		return false
	}},
	// packages
	{"pkg-remove", CatPackages, "removes packages", func(c simple) bool {
		sub := firstPositional(c.args)
		switch c.name {
		case "apt", "apt-get", "aptitude":
			return in(sub, "remove", "purge", "autoremove", "autopurge")
		case "yum", "dnf", "microdnf", "tdnf":
			return in(sub, "remove", "erase", "autoremove")
		case "apk":
			return in(sub, "del")
		case "pacman", "yay":
			for _, a := range c.args {
				if strings.HasPrefix(a, "-R") || a == "--remove" {
					return true
				}
			}
		case "zypper":
			return in(sub, "remove", "rm")
		case "snap", "flatpak", "brew", "port":
			return in(sub, "remove", "uninstall", "rm")
		case "pip", "pip3", "pipx", "gem", "cargo":
			return in(sub, "uninstall")
		case "npm", "pnpm", "yarn":
			return in(sub, "uninstall", "remove", "rm", "un", "r") && hasArg(c.args, "-g", "--global")
		case "dpkg":
			return hasArg(c.args, "-r", "-P", "--remove", "--purge")
		case "rpm":
			return hasArg(c.args, "-e", "--erase") || hasShort(c.args, "e")
		case "composer":
			return sub == "global" && in(firstPositional(afterFirst(c.args, "global")), "remove")
		}
		return false
	}},
	// writes to system paths (non-redirect)
	{"write-system", CatSystemWrite, "writes to a system path or ssh authorized_keys", func(c simple) bool {
		switch c.name {
		case "tee":
			for _, a := range positionals(c.args) {
				if c.isSystemPath(a) {
					return true
				}
			}
		case "sed", "perl":
			if hasArg(c.args, "-i", "--in-place") || hasShort(c.args, "i") {
				for _, a := range positionals(c.args) {
					if c.isSystemPath(a) {
						return true
					}
				}
			}
		case "cp", "mv", "install", "ln", "rsync", "scp":
			p := positionals(c.args)
			if len(p) > 0 && c.isSystemPath(p[len(p)-1]) {
				return true
			}
			if c.name == "mv" {
				for _, a := range p {
					if c.isSystemPath(a) {
						return true // moving away from a system path
					}
				}
			}
		case "dd":
			for _, a := range c.args {
				if strings.HasPrefix(a, "of=") && c.isSystemPath(a[3:]) {
					return true
				}
			}
		}
		return false
	}},
	// opaque commands
	{"shell-c", CatUnsure, "runs a command string through another interpreter (sh -c, eval, python -c, ...); the classifier cannot see inside", func(c simple) bool {
		switch c.name {
		case "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "busybox":
			return hasArg(c.args, "-c") || hasShort(c.args, "c") || len(c.args) == 0
		case "eval", "source", ".", "alias", "function", "trap":
			return true
		case "su":
			return true
		case "sudo":
			return hasArg(c.args, "-s", "-i", "--shell", "--login", "-e", "--edit")
		case "python", "python2", "python3", "pypy", "pypy3":
			return hasArg(c.args, "-c") || len(c.args) == 0
		case "perl", "ruby":
			return hasArg(c.args, "-e", "-E") || len(c.args) == 0
		case "node", "nodejs", "deno", "bun":
			return hasArg(c.args, "-e", "--eval", "-p", "--print", "eval")
		case "php":
			return hasArg(c.args, "-r") || len(c.args) == 0
		case "awk", "gawk", "mawk", "nawk":
			for _, a := range c.args {
				if strings.Contains(a, "system(") || strings.Contains(a, "| getline") || strings.Contains(a, "print >") {
					return true
				}
			}
		case "base64":
			return hasArg(c.args, "-d", "--decode", "-D")
		case "xxd":
			return hasArg(c.args, "-r")
		}
		return strings.HasPrefix(c.name, "$")
	}},
}

var builtinReRules = []reRule{
	{"secret-files", CatSecrets, "reads or touches a secret file (.env, keys, certificates, credentials, shadow)", ci(
		`(^|[\s/'"=:<>])\.env(rc|\.[\w.-]+)?($|[\s'";|&)<>])` +
			`|\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk|asc|gpg)\b` +
			`|\bid_(rsa|dsa|ecdsa|ed25519)` + `|ssh_host_\w*key` + `|\bprivate[_-]?key` +
			`|/etc/(shadow|gshadow|sudoers|master\.passwd|environment)\b` +
			`|\bcredentials?\b|\.git-credentials|\.pgpass|\.my\.cnf|\.netrc|\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|\.htpasswd|\bauth\.json\b` +
			`|\bsecrets?\b|/proc/[^/\s]+/environ|_history\b` +
			`|\benv\.php\b|\bwp-config\.php\b|\bparameters\.ya?ml\b|\bsettings\.php\b|\bvault\b`)},
	{"sql-drop", CatDatabase, "SQL DROP / TRUNCATE TABLE / ALTER ... DROP", ci(
		`\bdrop\s+(table|database|schema|index|view|user|role|function|procedure|trigger|sequence|materialized|keyspace|collection|owned)\b` +
			`|\btruncate\s+(table\s+)?[\w"` + "`" + `]` + `|\balter\s+table\b.*\bdrop\b`)},
	{"sql-delete", CatDatabase, "SQL DELETE (flagged with or without WHERE)", ci(`\bdelete\s+from\b`)},
	{"framework-db", CatDatabase, "framework command that wipes or rolls back the database", ci(
		`\bmigrate:(fresh|reset|rollback|refresh)\b|\bdb:(wipe|drop|reset)\b|\bdoctrine:(schema|database):drop\b|\bdoctrine:schema:update\b.*--force|\bflushall\b|\bflushdb\b`)},
	{"remote-code", CatRemoteCode, "downloads and executes code (curl|sh)", ci(
		`\b(curl|wget|fetch)\b.*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b` +
			`|\b(curl|wget|fetch)\b.*\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|php|node)\b` +
			`|\b(ba|z|da|k)?sh\s+<\(\s*(curl|wget)` + `|\$\(\s*(curl|wget)`)},
	{"pipe-to-shell", CatUnsure, "pipes into a shell or interpreter", ci(`\|\s*(sudo\s+(-\S+\s+)*)?((ba|z|da|k)?sh|python[0-9.]*|perl|ruby|php|node|xargs\s+(ba|z|da|k)?sh)(\s|$)`)},
	{"substitution", CatUnsure, "command substitution, process substitution or ANSI-C quoting hides the real command", regexp.MustCompile(`\$\(|` + "`" + `|<\(|>\(|\$'`)},
	{"heredoc-shell", CatUnsure, "feeds a here-document into a shell", ci(`\b(ba|z|da|k)?sh\s*<<`)},
}

// redirectRule flags > / >> into system paths.
func redirectFindings(seg segment, cwd string) []Finding {
	for _, t := range seg.redirects {
		if isSystemPathIn(cwd, t) {
			return []Finding{{"redirect-system", CatSystemWrite, "redirects output into a system path or authorized_keys (" + t + ")"}}
		}
	}
	return nil
}
