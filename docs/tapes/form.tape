# Connection form: a new connection, the key file field lists the keys found in ~/.ssh.
Output ".vhs/form.gif"
Source "docs/tapes/config.tape"

Hide
Type "tussh-demo" Enter
Sleep 2s
Type "n"
Sleep 300ms
Type "nas-backup"
Tab
Type "backup.homelab.example"
Tab 2
Type "backup"
Tab
Type "Nightly restic backups"
Tab
Type "homelab"
Tab 2
Sleep 500ms
Show
Sleep 300ms
Screenshot "docs/screenshots/form.png"
