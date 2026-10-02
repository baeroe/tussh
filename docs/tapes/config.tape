# Shared settings, included by the other tapes (Source). Run the tapes through docs/screenshots.sh.
Set Shell bash
Set FontFamily "Menlo"
Set FontSize 16
Set Width 1400
Set Height 700
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 40ms
Set CursorBlink false

# switch to the sandbox HOME prepared by docs/screenshots.sh
Hide
Type 'export HOME="$TUSSH_DEMO_HOME" && cd && clear' Enter
Sleep 300ms
Show
