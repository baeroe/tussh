# Alerts tab: two pending agent requests, the selected one as a card.
Output ".vhs/alerts.gif"
Source "docs/tapes/config.tape"

Hide
Type "tussh-demo alerts" Enter
Sleep 2.5s
Show
Sleep 300ms
Screenshot "docs/screenshots/alerts.png"
