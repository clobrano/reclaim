// Package protect decides which groups need an explicit override before
// reclaim stops them.
package protect

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/model"
)

// Reason explains why a group is protected.
type Reason struct {
	// Hard reasons cannot be overridden: PID 1 and reclaim itself.
	Hard bool
	PID  int
	Text string
}

// defaultComms are protected by default, by the comm of a member process.
// The kernel truncates comm to 15 characters.
var defaultComms = map[string]string{
	"sshd":            "sshd",
	"gnome-shell":     "compositor",
	"kwin_wayland":    "compositor",
	"kwin_x11":        "compositor",
	"sway":            "compositor",
	"Hyprland":        "compositor",
	"mutter":          "compositor",
	"weston":          "compositor",
	"river":           "compositor",
	"labwc":           "compositor",
	"wayfire":         "compositor",
	"niri":            "compositor",
	"cosmic-comp":     "compositor",
	"Xorg":            "display server",
	"Xwayland":        "display server",
	"gnome-session-b": "session",
	"ksmserver":       "session",
	"plasmashell":     "session",
	"gdm-session-wor": "session",
	"systemd-logind":  "session",
	"gdm":             "display manager",
	"sddm":            "display manager",
	"lightdm":         "display manager",
	"login":           "session",
	"dbus-daemon":     "session bus",
	"dbus-broker":     "session bus",
}

// SystemDefault reports whether a comm is protected by default regardless of
// configuration. The sudo helper uses it as a last line of defence.
func SystemDefault(comm string) bool {
	_, ok := defaultComms[comm]
	return ok
}

// Protector checks groups against the protection rules.
type Protector struct {
	cfg        config.Protect
	selfPID    int
	ancestors  map[int]int // pid → distance from reclaim (1 = parent)
	tmuxServer int
}

// New builds a protector for the current process tree.
func New(cfg config.Protect, snap *model.Snapshot) *Protector {
	p := &Protector{cfg: cfg, selfPID: snap.SelfPID, ancestors: map[int]int{}}
	pid, depth := snap.SelfPID, 0
	for pid > 1 && depth < 64 {
		proc, ok := snap.Procs[pid]
		if !ok {
			break
		}
		pid = proc.PPID
		depth++
		if pid > 1 {
			p.ancestors[pid] = depth
		}
	}
	p.tmuxServer = TmuxServer(os.Getenv("TMUX"))
	return p
}

// TmuxServer extracts the server PID from $TMUX ("socket,pid,session").
func TmuxServer(env string) int {
	parts := strings.Split(env, ",")
	if len(parts) < 2 {
		return 0
	}
	pid, _ := strconv.Atoi(parts[1])
	return pid
}

func (p *Protector) disabled(name string) bool {
	return slices.Contains(p.cfg.DisableDefaults, name)
}

// Check returns the reasons a group is protected, or nil.
func (p *Protector) Check(g *model.Group) []Reason {
	var out []Reason
	seen := map[string]bool{}
	add := func(r Reason) {
		if !seen[r.Text] {
			seen[r.Text] = true
			out = append(out, r)
		}
	}
	for _, rule := range p.cfg.Cgroups {
		if g.Cgroup != "" && globMatch(rule, g.Cgroup) {
			add(Reason{Text: fmt.Sprintf("cgroup matches protected pattern %q", rule)})
		}
	}
	if slices.Contains(p.cfg.Names, g.Name) {
		add(Reason{Text: fmt.Sprintf("%q is in your protected names", g.Name)})
	}
	for _, proc := range g.Procs {
		switch {
		case proc.PID == 1:
			add(Reason{Hard: true, PID: 1, Text: "contains PID 1 (init)"})
		case proc.PID == p.selfPID:
			add(Reason{Hard: true, PID: proc.PID, Text: "contains reclaim itself"})
		}
		if d, ok := p.ancestors[proc.PID]; ok && !p.disabled("ancestors") {
			add(Reason{PID: proc.PID, Text: ancestorText(proc, d)})
		}
		if proc.PID == p.tmuxServer && p.tmuxServer > 0 && !p.disabled("tmux") {
			add(Reason{PID: proc.PID, Text: fmt.Sprintf("contains the tmux server running reclaim (pid %d)", proc.PID)})
		}
		if what, ok := defaultComms[proc.Comm]; ok && !p.disabled(proc.Comm) {
			add(Reason{PID: proc.PID, Text: fmt.Sprintf("contains %s (%s, pid %d)", proc.Comm, what, proc.PID)})
		}
		if isUserManager(proc) && !p.disabled("systemd --user") {
			add(Reason{PID: proc.PID, Text: fmt.Sprintf("contains your systemd --user manager (pid %d)", proc.PID)})
		}
		if slices.Contains(p.cfg.Names, proc.Comm) {
			add(Reason{PID: proc.PID, Text: fmt.Sprintf("contains %s, in your protected names", proc.Comm)})
		}
		if proc.Exe != "" && slices.Contains(p.cfg.Exes, proc.Exe) {
			add(Reason{PID: proc.PID, Text: fmt.Sprintf("contains %s, in your protected executables", proc.Exe)})
		}
		if g.Cgroup == "" {
			for _, rule := range p.cfg.Cgroups {
				if globMatch(rule, proc.Cgroup) {
					add(Reason{PID: proc.PID, Text: fmt.Sprintf("pid %d's cgroup matches protected pattern %q", proc.PID, rule)})
				}
			}
		}
	}
	return out
}

// Hard reports whether any reason is hard.
func Hard(rs []Reason) bool {
	return slices.ContainsFunc(rs, func(r Reason) bool { return r.Hard })
}

func ancestorText(p *model.Process, depth int) string {
	switch depth {
	case 1:
		return fmt.Sprintf("contains %s (pid %d), the parent of reclaim: probably your shell", p.Comm, p.PID)
	case 2:
		return fmt.Sprintf("contains %s (pid %d), your shell's parent: probably your terminal", p.Comm, p.PID)
	}
	return fmt.Sprintf("contains %s (pid %d), an ancestor of reclaim", p.Comm, p.PID)
}

func isUserManager(p *model.Process) bool {
	return p.PID != 1 && p.Comm == "systemd" && strings.Contains(p.Cgroup, "/user@")
}

// globMatch matches a cgroup path against a pattern where * may span "/".
func globMatch(pattern, s string) bool {
	if ok, _ := path.Match(pattern, s); ok {
		return true
	}
	return wildcard(pattern, s)
}

// wildcard is a "*"-only matcher in which "*" matches any run of characters.
func wildcard(p, s string) bool {
	for len(p) > 0 {
		if p[0] == '*' {
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if p == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if wildcard(p, s[i:]) {
					return true
				}
			}
			return false
		}
		if s == "" || (p[0] != '?' && p[0] != s[0]) {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return s == ""
}
