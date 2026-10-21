package action

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/protect"
)

func requireProc(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
}

// spawn starts a command and reaps it in the background.
func spawn(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go cmd.Wait()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd
}

func groupOf(t *testing.T, pids ...int) (*model.Group, *model.Snapshot) {
	t.Helper()
	snap := &model.Snapshot{SelfPID: os.Getpid(), Procs: map[int]*model.Process{}}
	self, _ := procfs.Default.ReadStat(os.Getpid())
	snap.Procs[self.PID] = &model.Process{PID: self.PID, PPID: self.PPID, Comm: self.Comm, StartTime: self.StartTime}
	g := &model.Group{ID: "test", Name: "test", Kind: model.KindTree}
	for _, pid := range pids {
		st, err := procfs.Default.ReadStat(pid)
		if err != nil {
			t.Fatal(err)
		}
		p := &model.Process{PID: pid, PPID: st.PPID, Comm: st.Comm, StartTime: st.StartTime, Readable: true, Mem: model.Mem{USS: 1 << 20, PSS: 2 << 20}}
		snap.Procs[pid] = p
		g.Procs = append(g.Procs, p)
		g.PIDs = append(g.PIDs, pid)
		g.Mem.Add(p.Mem)
	}
	return g, snap
}

func env(snap *model.Snapshot) Env {
	return Env{
		Proc:        procfs.Default,
		Cgroup:      cgroupfs.FS{Root: "/nonexistent"},
		Protector:   protect.New(config.Protect{}, snap),
		SelfPID:     os.Getpid(),
		SelfUID:     os.Getuid(),
		Grace:       300 * time.Millisecond,
		Meminfo:     procfs.Meminfo{"SwapTotal": 0},
		UnitRestart: func(string, bool) string { return "" },
	}
}

func waitState(t *testing.T, pid int, want byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err := procfs.Default.ReadStat(pid)
		if err == nil && st.State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, _ := procfs.Default.ReadStat(pid)
	t.Fatalf("pid %d state %c, want %c", pid, st.State, want)
}

func TestTerminateGraceful(t *testing.T) {
	requireProc(t)
	a := spawn(t, "sleep", "60")
	b := spawn(t, "sleep", "60")
	g, snap := groupOf(t, a.Process.Pid, b.Process.Pid)
	e := env(snap)
	p, err := NewPlan(g, Terminate, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.NeedsOverride() || len(p.Targets) != 2 || p.Estimate.Low != 2<<20 || p.Estimate.High != 4<<20 {
		t.Fatalf("plan %+v", p)
	}
	res := Execute(p, e)
	if len(res.Exited) != 2 || len(res.Killed) != 0 || len(res.Left) != 0 {
		t.Fatalf("result %+v", res)
	}
}

func TestTerminateEscalatesToKill(t *testing.T) {
	requireProc(t)
	stubborn := spawn(t, "sh", "-c", `trap "" TERM; while :; do sleep 0.05; done`)
	time.Sleep(100 * time.Millisecond) // let the trap install
	g, snap := groupOf(t, stubborn.Process.Pid)
	e := env(snap)
	p, err := NewPlan(g, Terminate, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := time.Now()
	res := Execute(p, e)
	if len(res.Killed) != 1 || len(res.Exited) != 0 {
		t.Fatalf("result %+v", res)
	}
	if time.Since(start) < e.Grace {
		t.Fatal("SIGKILL before the grace period")
	}
}

func TestPIDReuseIsRefused(t *testing.T) {
	requireProc(t)
	a := spawn(t, "sleep", "60")
	g, snap := groupOf(t, a.Process.Pid)
	g.Procs[0].StartTime++ // pretend the snapshot saw an older process
	if _, err := NewPlan(g, Terminate, env(snap)); err == nil || !strings.Contains(err.Error(), "no processes left") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if st, _ := procfs.Default.ReadStat(a.Process.Pid); st.State == 'Z' {
		t.Fatal("process was signalled")
	}
}

func TestProtectedPlans(t *testing.T) {
	requireProc(t)
	g, snap := groupOf(t, os.Getppid())
	p, err := NewPlan(g, Terminate, env(snap))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !p.NeedsOverride() {
		t.Fatal("parent of reclaim must need an override")
	}
	g1 := &model.Group{ID: "x", Name: "x", Kind: model.KindVM}
	if _, err := NewPlan(g1, Terminate, env(snap)); err == nil {
		t.Fatal("VM groups are not actionable")
	}
	blocked := &Plan{Mode: Terminate, Protected: []protect.Reason{{Hard: true, Text: "pid 1"}}}
	if res := Execute(blocked, env(snap)); res.Error == "" {
		t.Fatal("hard-protected plan executed")
	}
}

func TestFreezeAndThawWithSignals(t *testing.T) {
	requireProc(t)
	a := spawn(t, "sleep", "60")
	pid := a.Process.Pid
	g, snap := groupOf(t, pid)
	e := env(snap)
	p, err := NewPlan(g, Freeze, e)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.UseCgroup {
		t.Fatal("no cgroup in test")
	}
	joined := strings.Join(p.Warnings, " ")
	if !strings.Contains(joined, "frees no RAM") || !strings.Contains(joined, "Swap is off") || !strings.Contains(joined, "SIGSTOP") {
		t.Fatalf("warnings %q", p.Warnings)
	}
	res := Execute(p, e)
	if len(res.Frozen) != 1 || res.Method != "SIGSTOP" {
		t.Fatalf("%+v", res)
	}
	waitState(t, pid, 'T')

	reg := &Registry{Path: filepath.Join(t.TempDir(), "frozen.json")}
	reg.Add(FrozenEntry{GroupID: g.ID, Name: g.Name, Method: res.Method, Targets: p.Targets, At: time.Now()})
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistry(reg.Path)
	if err != nil || len(loaded.Entries) != 1 {
		t.Fatalf("load %v %+v", err, loaded)
	}
	if loaded.Reconcile(e) {
		t.Fatal("still frozen, nothing should change")
	}
	entry, _ := loaded.Find(g.ID)
	if r := Thaw(entry, e); len(r.Resumed) != 1 {
		t.Fatalf("thaw %+v", r)
	}
	waitState(t, pid, 'S')
	if !loaded.Reconcile(e) || len(loaded.Entries) != 0 {
		t.Fatal("thawed entry should be dropped")
	}
}

func TestHelperValidation(t *testing.T) {
	requireProc(t)
	e := env(&model.Snapshot{SelfPID: os.Getpid()})
	if _, err := validate([]string{"1:1"}, e, os.Getppid()); err == nil {
		t.Fatal("pid 1 accepted")
	}
	self, _ := procfs.Default.ReadStat(os.Getppid())
	if _, err := validate([]string{Target{PID: self.PID, StartTime: self.StartTime}.String()}, e, os.Getppid()); err == nil {
		t.Fatal("own ancestry accepted")
	}
	a := spawn(t, "sleep", "60")
	st, _ := procfs.Default.ReadStat(a.Process.Pid)
	stale := Target{PID: st.PID, StartTime: st.StartTime + 1}.String()
	ts, err := validate([]string{stale}, e, os.Getppid())
	if err != nil || len(ts) != 0 {
		t.Fatalf("stale target: %v %v", ts, err)
	}
	if _, err := ParseTarget("12"); err == nil {
		t.Fatal("bad target parsed")
	}

	// Full helper round trip on our own child.
	var out bytes.Buffer
	good := Target{PID: st.PID, StartTime: st.StartTime}.String()
	if code := RunHelper([]string{"terminate", "--grace", "1s", good}, &out); code != 0 {
		t.Fatalf("helper exit %d: %s", code, out.String())
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res.Exited) != 1 {
		t.Fatalf("helper result %s %v", out.String(), err)
	}
}

func TestSudoArgs(t *testing.T) {
	p := &Plan{Mode: Freeze, Grace: 5 * time.Second, Cgroup: "/a.scope", UseCgroup: true, Targets: []Target{{PID: 10, StartTime: 99}}}
	got := strings.Join(SudoArgs("/usr/bin/reclaim", p), " ")
	if got != "sudo -- /usr/bin/reclaim --helper freeze --grace 5s --cgroup /a.scope 10:99" {
		t.Fatal(got)
	}
}

func TestSignalNoFD(t *testing.T) {
	requireProc(t)
	a := spawn(t, "sleep", "60")
	st, _ := procfs.Default.ReadStat(a.Process.Pid)
	tg := Target{PID: st.PID, StartTime: st.StartTime} // fd 0, as from JSON
	if err := tg.signal(procfs.Default, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
}
