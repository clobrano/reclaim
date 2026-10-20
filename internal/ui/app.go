package ui

import (
	"strings"
	"time"

	"github.com/clobrano/reclaim/internal/term"
)

// Run drives the model on a real terminal until the user quits.
func Run(t *term.Terminal, m *Model, interval time.Duration, refreshNames func()) {
	msgs := make(chan any, 16)
	run := func(cmds []Cmd) bool {
		for _, c := range cmds {
			switch {
			case c.Quit:
				return true
			case c.Write != "":
				t.Write([]byte(c.Write))
			case c.Run != nil:
				go func(f func() any) { msgs <- f() }(c.Run)
			case c.Foreground != nil:
				t.Suspend()
				res := c.Foreground()
				t.Resume()
				msgs <- res
			}
		}
		return false
	}
	draw := func() {
		w, h := t.Size()
		m.SetSize(w, h)
		lines := m.Render()
		var b strings.Builder
		b.WriteString("\x1b[H")
		for i, l := range lines {
			if i > 0 {
				b.WriteString("\r\n")
			}
			b.WriteString(l)
		}
		b.WriteString("\x1b[J")
		t.Write([]byte(b.String()))
	}

	if refreshNames != nil {
		go func() {
			for {
				refreshNames()
				time.Sleep(30 * time.Second)
			}
		}()
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	// Redraw every second so status messages expire and busy markers move.
	redraw := time.NewTicker(time.Second)
	defer redraw.Stop()

	if run(m.Init()) {
		return
	}
	draw()
	for {
		var quit bool
		select {
		case ev := <-t.Events:
			if ev.Resize {
				t.Write([]byte("\x1b[2J"))
			} else {
				quit = run(m.Key(ev.Key))
			}
		case msg := <-msgs:
			quit = run(m.Handle(msg))
		case <-tick.C:
			quit = run(m.Tick())
		case <-redraw.C:
		}
		if quit {
			return
		}
		draw()
	}
}
