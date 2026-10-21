package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clobrano/reclaim/internal/action"
	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/clipboard"
	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/group"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/term"
)

const gib = 1 << 30

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

func screen(m *Model) string {
	var b strings.Builder
	for _, l := range m.Render() {
		b.WriteString(ansi.ReplaceAllString(l, ""))
		b.WriteByte('\n')
	}
	return b.String()
}

// drive runs commands synchronously, feeding results back to the model.
func drive(t *testing.T, m *Model, cmds []Cmd) (writes []string, quit bool) {
	t.Helper()
	for len(cmds) > 0 {
		c := cmds[0]
		cmds = cmds[1:]
		switch {
		case c.Quit:
			quit = true
		case c.Write != "":
			writes = append(writes, c.Write)
		case c.Run != nil:
			cmds = append(cmds, m.Handle(c.Run())...)
		case c.Foreground != nil:
			t.Fatal("unexpected foreground command")
		}
	}
	return writes, quit
}

func keys(t *testing.T, m *Model, ks ...string) []string {
	t.Helper()
	var writes []string
	for _, k := range ks {
		var key term.Key
		switch k {
		case "enter", "esc", "tab", "down", "up", "backspace", "ctrl+c":
			key = term.Key{Name: k}
		default:
			key = term.Key{Rune: []rune(k)[0]}
		}
		w, _ := drive(t, m, m.Key(key))
		writes = append(writes, w...)
	}
	return writes
}

// fakeSnap is a cgroup v2 host with an editor, a terminal and a VM, where
// the editor's footprint grows on every sample and PSI is high.
type fakeSnap struct {
	n    int
	time time.Time
}

func (f *fakeSnap) sample() (*model.Snapshot, error) {
	f.n++
	f.time = f.time.Add(15 * time.Second)
	mk := func(pid, ppid int, comm, cg string, uss uint64) *model.Process {
		return &model.Process{PID: pid, PPID: ppid, Comm: comm, Cgroup: cg, StartTime: uint64(pid), Readable: true,
			Mem: model.Mem{USS: uss, PSS: uss + 1<<20, RSS: uss + 10<<20, Used: uss}}
	}
	user := "/user.slice/user-1000.slice/user@1000.service/app.slice/"
	procs := []*model.Process{
		mk(1, 0, "systemd", "/init.scope", 1<<20),
		mk(1000, 1, "code", user+"app-gnome-code-4711.scope", uint64(gib+f.n*(200<<20))),
		mk(1001, 1000, "code", user+"app-gnome-code-4711.scope", 300<<20),
		mk(2000, 1, "kitty", user+"app-kitty-1.scope", 50<<20),
		mk(3000, 1, "qemu-system-x86", `/machine.slice/machine-qemu\x2d1\x2dwin11.scope/libvirt/emulator`, 4*gib),
		{PID: 4000, PPID: 1, Comm: "postgres", Cgroup: "/system.slice/postgresql.service", StartTime: 4000, Mem: model.Mem{RSS: 90 << 20, Unreadable: 1}},
	}
	s := &model.Snapshot{
		Time: f.time, SelfPID: -1, Unified: true, Procs: map[int]*model.Process{},
		Meminfo: procfs.Meminfo{"MemTotal": 16 * gib, "MemAvailable": 2 * gib, "MemFree": gib, "AnonPages": 10 * gib, "SwapTotal": 0},
		PSI:     &procfs.PSI{Some: procfs.PSILine{Avg10: 30}},
		CgMem:   map[string]cgroupfs.Mem{}, CgPSI: map[string]procfs.PSI{},
	}
	for _, p := range procs {
		s.Procs[p.PID] = p
	}
	return s, nil
}

func newModel(t *testing.T, sample func() (*model.Snapshot, error)) *Model {
	t.Helper()
	cfg := config.Default()
	m := New(Deps{
		Sample:   sample,
		Proc:     procfs.Default,
		Cgroup:   cgroupfs.FS{Root: t.TempDir()},
		Config:   cfg,
		Registry: &action.Registry{Path: filepath.Join(t.TempDir(), "frozen.json")},
		Exe:      "/usr/bin/reclaim",
		Clip:     clipboard.Env{},
		ExecuteAction: func(p *action.Plan, _ action.Env) action.Result {
			r := action.Result{Mode: p.Mode.String(), Method: "SIGSTOP"}
			for _, tg := range p.Targets {
				if p.Mode == action.Freeze {
					r.Frozen = append(r.Frozen, tg.PID)
				} else {
					r.Exited = append(r.Exited, tg.PID)
				}
			}
			return r
		},
		ThawEntry: func(e action.FrozenEntry, _ action.Env) action.Result {
			return action.Result{Mode: "thaw", Resumed: []int{e.Targets[0].PID}}
		},
		MemAvailable: func() uint64 { return 0 },
	}, group.ViewApps)
	m.SetSize(120, 40)
	return m
}

func TestListAndCulprit(t *testing.T) {
	f := &fakeSnap{time: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
	m := newModel(t, f.sample)
	for range 4 {
		drive(t, m, m.Tick())
	}
	s := screen(m)
	for _, want := range []string{"pressure culprit: code", "win11", "postgres", "PSI some 30.0%", "1 processes of other users unreadable"} {
		if !strings.Contains(s, want) {
			t.Errorf("screen lacks %q:\n%s", want, s)
		}
	}
	// The culprit row carries the C flag; postgres' USS is unknown.
	if !regexp.MustCompile(`▸ code .* C `).MatchString(s) {
		t.Errorf("no culprit flag:\n%s", s)
	}
	if !regexp.MustCompile(`postgresql +service .* \?`).MatchString(s) {
		t.Errorf("unreadable USS not shown as ?:\n%s", s)
	}

	keys(t, m, "v")
	if s := screen(m); !strings.Contains(s, "view containers") || !strings.Contains(s, "Host (not containerized)") {
		t.Fatalf("containers view:\n%s", s)
	}
}

func TestVMGetsCommandsNotActions(t *testing.T) {
	f := &fakeSnap{time: time.Now()}
	m := newModel(t, f.sample)
	drive(t, m, m.Init())
	keys(t, m, "v")
	for i, r := range m.rows {
		if r.g.Kind == model.KindVM {
			m.cursor, m.selected = i, r.g.ID
		}
	}
	keys(t, m, "t")
	if m.mode != modeSuggest {
		t.Fatalf("mode %v", m.mode)
	}
	s := screen(m)
	if !strings.Contains(s, "sudo virsh -c qemu:///system shutdown win11") || !strings.Contains(s, "doesn't terminate vm groups itself") {
		t.Fatalf("%s", s)
	}
	writes := keys(t, m, "down", "y")
	if len(writes) != 1 || writes[0] != clipboard.Sequence("sudo virsh -c qemu:///system managedsave win11", clipboard.Env{}) {
		t.Fatalf("writes %q", writes)
	}
}

// realSnap samples a real child process so plans can be made against it.
func realSnap(pids ...int) func() (*model.Snapshot, error) {
	return func() (*model.Snapshot, error) {
		s := &model.Snapshot{Time: time.Now(), SelfPID: os.Getpid(), Procs: map[int]*model.Process{},
			Meminfo: procfs.Meminfo{"MemTotal": 16 * gib}, CgMem: map[string]cgroupfs.Mem{}, CgPSI: map[string]procfs.PSI{}}
		for _, pid := range pids {
			st, err := procfs.Default.ReadStat(pid)
			if err != nil {
				continue
			}
			s.Procs[pid] = &model.Process{PID: pid, PPID: 1, Comm: st.Comm, StartTime: st.StartTime, Readable: true, Mem: model.Mem{USS: 1 << 20}}
		}
		return s, nil
	}
}

func spawn(t *testing.T) int {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go cmd.Wait()
	t.Cleanup(func() { cmd.Process.Kill() })
	return cmd.Process.Pid
}

func TestConfirmDefaultsToCancel(t *testing.T) {
	pid := spawn(t)
	m := newModel(t, realSnap(pid))
	drive(t, m, m.Init())
	keys(t, m, "t")
	if m.mode != modeConfirm {
		t.Fatalf("mode %v: %s", m.mode, m.status)
	}
	if s := screen(m); !strings.Contains(s, "Terminate sleep?") || !strings.Contains(s, "Expected to free") {
		t.Fatalf("%s", s)
	}
	keys(t, m, "enter") // focus starts on Cancel
	if m.mode != modeList || strings.Contains(m.status, "exited") {
		t.Fatalf("enter on the default button must cancel: %v %q", m.mode, m.status)
	}
	keys(t, m, "t", "+", "tab", "enter")
	if !strings.Contains(m.status, "terminate sleep: 1 exited on SIGTERM") {
		t.Fatalf("status %q", m.status)
	}
}

func TestFreezeRegistersAndQuitAsks(t *testing.T) {
	pid := spawn(t)
	m := newModel(t, realSnap(pid))
	// Really stop the process: the registry drops entries whose processes
	// are not stopped when it reconciles after the next sample.
	m.deps.ExecuteAction = action.Execute
	m.deps.ThawEntry = action.Thaw
	drive(t, m, m.Init())
	keys(t, m, "f", "tab", "enter")
	if len(m.deps.Registry.Entries) != 1 {
		t.Fatalf("registry %+v (%s)", m.deps.Registry.Entries, m.status)
	}
	if _, err := os.Stat(m.deps.Registry.Path); err != nil {
		t.Fatal("registry not saved")
	}
	if !strings.Contains(screen(m), "1 frozen (F)") {
		t.Fatal("frozen badge missing")
	}
	_, quit := drive(t, m, m.Key(term.Key{Rune: 'q'}))
	if quit || m.mode != modeQuit {
		t.Fatal("quitting with frozen groups must ask first")
	}
	keys(t, m, "esc", "F", "r")
	if len(m.deps.Registry.Entries) != 0 || !strings.Contains(m.status, "resume sleep: 1 resumed") {
		t.Fatalf("resume: %q %+v", m.status, m.deps.Registry.Entries)
	}
	keys(t, m, "esc")
	if _, quit := drive(t, m, m.Key(term.Key{Rune: 'q'})); !quit {
		t.Fatal("expected quit")
	}
}

func TestProtectedNeedsTypedOverride(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	// reclaim's parent sits alone in its own cgroup, so its group is
	// protected (an ancestor) but not hard-protected (reclaim isn't in it).
	parent := os.Getppid()
	cg := cgroupfs.FS{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(cg.Root, "shell.scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cg.Root, "shell.scope", "cgroup.procs"), []byte(strconv.Itoa(parent)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := newModel(t, func() (*model.Snapshot, error) {
		s, _ := realSnap(parent)()
		s.Unified = true
		s.Procs[parent].Cgroup = "/shell.scope"
		self, _ := procfs.Default.ReadStat(os.Getpid())
		s.Procs[self.PID] = &model.Process{PID: self.PID, PPID: parent, Comm: self.Comm, StartTime: self.StartTime, Cgroup: "/reclaim.scope"}
		return s, nil
	})
	m.deps.Cgroup = cg
	m.deps.ExecuteAction = func(p *action.Plan, _ action.Env) action.Result {
		t.Fatal("executed without override")
		return action.Result{}
	}
	drive(t, m, m.Init())
	for i, r := range m.rows {
		if r.g.Cgroup == "/shell.scope" {
			m.cursor, m.selected = i, r.g.ID
		}
	}
	keys(t, m, "t")
	if m.plan == nil || !m.plan.NeedsOverride() || m.plan.Blocked() {
		t.Fatalf("expected a protected plan, got %+v (%s)", m.plan, m.status)
	}
	if !strings.Contains(screen(m), "to override") {
		t.Fatalf("override prompt missing:\n%s", screen(m))
	}
	keys(t, m, "tab", "enter")
	if m.mode != modeConfirm || !strings.Contains(m.status, "type the group name") {
		t.Fatalf("mode %v status %q", m.mode, m.status)
	}
	keys(t, m, "esc")
	if m.mode != modeList || m.plan != nil {
		t.Fatal("esc must close the dialog")
	}
}

func TestRenderSmallTerminal(t *testing.T) {
	f := &fakeSnap{time: time.Now()}
	m := newModel(t, f.sample)
	drive(t, m, m.Init())
	m.SetSize(40, 10)
	for _, k := range []string{"?", "esc", "m", "esc", "i", "esc", "K", "esc"} {
		keys(t, m, k)
		lines := m.Render()
		if len(lines) > 10 {
			t.Fatalf("%d lines for a 10-line terminal after %q", len(lines), k)
		}
		for _, l := range lines {
			if n := len([]rune(ansi.ReplaceAllString(l, ""))); n > 40 {
				t.Fatalf("line of %d cells after %q: %q", n, k, l)
			}
		}
	}
}

func TestWrapAndSize(t *testing.T) {
	if got := wrap("aaa bbb ccc", 7); len(got) != 2 || got[0] != "aaa bbb" {
		t.Fatalf("%q", got)
	}
	cases := map[uint64]string{0: "0", 512: "512B", 1536: "1.5K", 3 * gib: "3.0G", 300 << 20: "300M"}
	for in, want := range cases {
		if size(in) != want {
			t.Errorf("size(%d) = %s, want %s", in, size(in), want)
		}
	}
	if signedSize(-(2 << 20)) != "-2.0M" {
		t.Fatal(signedSize(-(2 << 20)))
	}
	if sparkline([]uint64{1, 2, 3}, 10) != "▁▄█" {
		t.Fatal(sparkline([]uint64{1, 2, 3}, 10))
	}
}

func TestUsedPercentMapsToGroups(t *testing.T) {
	f := &fakeSnap{time: time.Now()}
	m := newModel(t, f.sample)
	drive(t, m, m.Init())
	s := screen(m)
	// 16G total, 2G available: 88% used, split into the top-level groups.
	for _, want := range []string{"RAM 88% used (14G of 16G)", "RAM%", "sort ram%", "█ machine-qemu-1-win11 25%", "█ code 9.3%", "· available 12%"} {
		if !strings.Contains(s, want) {
			t.Errorf("screen lacks %q:\n%s", want, s)
		}
	}
	// Default sort is the share of used RAM: the VM (4G) comes first.
	if m.rows[0].g.Name != "machine-qemu-1-win11" {
		t.Fatalf("first row %q", m.rows[0].g.Name)
	}
	keys(t, m, "m")
	s = screen(m)
	if !strings.Contains(s, "Why RAM is 88% used") || !strings.Contains(s, "rest") {
		t.Fatalf("memory screen:\n%s", s)
	}
}

func TestPct(t *testing.T) {
	cases := map[[2]uint64]string{{0, 10}: "0%", {1, 10000}: "<0.1%", {42, 1000}: "4.2%", {600, 1000}: "60%", {1, 0}: "?"}
	for in, want := range cases {
		if got := pct(in[0], in[1]); got != want {
			t.Errorf("pct(%d, %d) = %s, want %s", in[0], in[1], got, want)
		}
	}
}
