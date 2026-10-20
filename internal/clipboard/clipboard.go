// Package clipboard copies text with the OSC 52 escape sequence, which works
// inside tmux and over ssh because the terminal emulator does the copying.
package clipboard

import (
	"encoding/base64"
	"io"
	"strings"
)

// Env says which multiplexer, if any, sits between reclaim and the terminal.
type Env struct {
	Tmux   bool // $TMUX set
	Screen bool // $STY set
}

// Sequence returns the escape sequence that copies text to the clipboard.
func Sequence(text string, env Env) string {
	seq := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\x07"
	switch {
	case env.Tmux:
		// DCS passthrough: ESCs inside are doubled. tmux forwards it when
		// allow-passthrough is on; with set-clipboard on, tmux handles the
		// plain sequence itself, so send both.
		return seq + "\x1bPtmux;" + strings.ReplaceAll(seq, "\x1b", "\x1b\x1b") + "\x1b\\"
	case env.Screen:
		return "\x1bP" + seq + "\x1b\\"
	}
	return seq
}

// Copy writes the sequence to w, normally the terminal.
func Copy(w io.Writer, text string, env Env) error {
	_, err := io.WriteString(w, Sequence(text, env))
	return err
}

// Hint is shown after copying inside a multiplexer.
func Hint(env Env) string {
	if env.Tmux {
		return "inside tmux, copying needs `set -g set-clipboard on` (or allow-passthrough on)"
	}
	return ""
}
