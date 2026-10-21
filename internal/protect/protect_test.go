package protect

import (
	"strings"
	"testing"

	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/model"
)

func snap() *model.Snapshot {
	procs := []*model.Process{
		{PID: 1, PPID: 0, Comm: "systemd", Cgroup: "/init.scope"},
		{PID: 50, PPID: 1, Comm: "sshd", Cgroup: "/system.slice/sshd.service"},
		{PID: 900, PPID: 1, Comm: "systemd", Cgroup: "/user.slice/user-1000.slice/user@1000.service/init.scope"},
		{PID: 1100, PPID: 900, Comm: "kitty", Cgroup: "/u/app-kitty-1.scope"},
		{PID: 1101, PPID: 1100, Comm: "zsh", Cgroup: "/u/app-kitty-1.scope"},
		{PID: 1102, PPID: 1101, Comm: "reclaim", Cgroup: "/u/app-kitty-1.scope"},
		{PID: 2000, PPID: 900, Comm: "code", Exe: "/usr/share/code/code", Cgroup: "/u/app-gnome-code-4711.scope"},
		{PID: 3000, PPID: 900, Comm: "keepassxc", Exe: "/usr/bin/keepassxc", Cgroup: "/u/app-gnome-keepassxc-5.scope"},
	}
	s := &model.Snapshot{SelfPID: 1102, Procs: map[int]*model.Process{}}
	for _, p := range procs {
		s.Procs[p.PID] = p
	}
	return s
}

func group(s *model.Snapshot, name, cg string, pids ...int) *model.Group {
	g := &model.Group{Name: name, Cgroup: cg}
	for _, pid := range pids {
		g.Procs = append(g.Procs, s.Procs[pid])
	}
	return g
}

func joined(rs []Reason) string {
	var b []string
	for _, r := range rs {
		b = append(b, r.Text)
	}
	return strings.Join(b, "; ")
}

func TestDefaults(t *testing.T) {
	s := snap()
	p := New(config.Protect{}, s)

	if rs := p.Check(group(s, "code", "/u/app-gnome-code-4711.scope", 2000)); rs != nil {
		t.Fatalf("code protected: %s", joined(rs))
	}
	term := p.Check(group(s, "kitty", "/u/app-kitty-1.scope", 1100, 1101, 1102))
	if !Hard(term) || !strings.Contains(joined(term), "probably your terminal") || !strings.Contains(joined(term), "reclaim itself") {
		t.Fatalf("terminal: %s", joined(term))
	}
	if rs := p.Check(group(s, "init", "/init.scope", 1)); !Hard(rs) {
		t.Fatal("PID 1 must be hard-protected")
	}
	sshd := p.Check(group(s, "sshd", "/system.slice/sshd.service", 50))
	if len(sshd) != 1 || Hard(sshd) {
		t.Fatalf("sshd: %s", joined(sshd))
	}
	if rs := p.Check(group(s, "systemd --user", "", 900)); len(rs) == 0 {
		t.Fatal("user manager unprotected")
	}
}

func TestConfigured(t *testing.T) {
	s := snap()
	p := New(config.Protect{
		Exes:            []string{"/usr/bin/keepassxc"},
		Cgroups:         []string{"*/app-gnome-code-*.scope"},
		DisableDefaults: []string{"sshd"},
	}, s)
	if rs := p.Check(group(s, "keepassxc", "/u/app-gnome-keepassxc-5.scope", 3000)); len(rs) != 1 {
		t.Fatalf("exe: %s", joined(rs))
	}
	if rs := p.Check(group(s, "code", "/u/app-gnome-code-4711.scope", 2000)); len(rs) != 1 {
		t.Fatalf("cgroup glob: %s", joined(rs))
	}
	if rs := p.Check(group(s, "sshd", "/system.slice/sshd.service", 50)); rs != nil {
		t.Fatalf("sshd default not disabled: %s", joined(rs))
	}
	byName := New(config.Protect{Names: []string{"code"}}, s)
	if rs := byName.Check(group(s, "code", "/u/app-gnome-code-4711.scope", 2000)); len(rs) == 0 {
		t.Fatal("name rule")
	}
}

func TestTmuxServer(t *testing.T) {
	if TmuxServer("/tmp/tmux-1000/default,4242,0") != 4242 || TmuxServer("") != 0 {
		t.Fatal("tmux")
	}
}

func TestGlob(t *testing.T) {
	if !globMatch("*/app-*-code-*.scope", "/user.slice/u/app.slice/app-gnome-code-1.scope") {
		t.Fatal("deep glob")
	}
	if globMatch("*/foo.scope", "/bar.scope") {
		t.Fatal("false positive")
	}
}
