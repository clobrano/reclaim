// Package action stops process groups, after a plan has been confirmed.
//
// Membership is re-read when the plan is made, and every process is held by
// pidfd from then on, so a PID reused after the snapshot never receives a
// signal meant for another process.
package action

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/pressure"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/protect"
)

// Mode is what to do with a group.
type Mode int

const (
	Terminate Mode = iota
	Freeze
)

func (m Mode) String() string {
	if m == Freeze {
		return "freeze"
	}
	return "terminate"
}

// Env is what planning and execution need from the system.
type Env struct {
	Proc      procfs.FS
	Cgroup    cgroupfs.FS
	Protector *protect.Protector
	SelfPID   int
	SelfUID   int
	Grace     time.Duration
	Meminfo   procfs.Meminfo
	// UnitRestart returns the Restart= setting of a systemd unit, or "".
	// Nil means systemctl is queried.
	UnitRestart func(unit string, user bool) string
}

// Plan is a confirmed-or-not action on a group.
type Plan struct {
	Mode      Mode
	GroupID   string
	Name      string
	Kind      model.Kind
	Cgroup    string // set when the whole cgroup is the target
	Targets   []Target
	Estimate  model.Estimate
	Warnings  []string
	Protected []protect.Reason
	// UseCgroup: freeze through cgroup.freeze, or finish a terminate with
	// cgroup.kill.
	UseCgroup bool
	NeedsSudo bool
	Grace     time.Duration
}

// NeedsOverride reports whether the user must type the group name.
func (p *Plan) NeedsOverride() bool { return len(p.Protected) > 0 }

// Blocked reports whether the plan may not run at all.
func (p *Plan) Blocked() bool { return protect.Hard(p.Protected) }

// Close releases the pidfds. Call it when the plan is cancelled or done.
func (p *Plan) Close() {
	for i := range p.Targets {
		p.Targets[i].close()
	}
}

// wholeCgroup reports whether the group is exactly a cgroup subtree, so
// cgroup-level operations affect exactly its members.
func wholeCgroup(g *model.Group) bool {
	if g.Cgroup == "" || g.Cgroup == "/" {
		return false
	}
	switch g.Kind {
	case model.KindApp, model.KindService, model.KindSession, model.KindScope:
		return true
	}
	return false
}

// cgroupPIDs lists every PID in a cgroup subtree.
func cgroupPIDs(cg cgroupfs.FS, path string) ([]int, error) {
	var pids []int
	root := cg.Path(path)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel := "/" + strings.TrimPrefix(strings.TrimPrefix(p, cg.Root), "/")
		more, err := cg.Procs(rel)
		if err != nil {
			return nil // cgroup removed meanwhile
		}
		pids = append(pids, more...)
		return nil
	})
	return pids, err
}

// NewPlan re-reads the group's membership and prepares an action.
func NewPlan(g *model.Group, mode Mode, env Env) (*Plan, error) {
	if !g.Kind.Actionable() {
		return nil, fmt.Errorf("%s groups are not acted on directly; use the suggested commands", g.Kind)
	}
	p := &Plan{Mode: mode, GroupID: g.ID, Name: g.Name, Kind: g.Kind, Grace: env.Grace}
	p.Protected = env.Protector.Check(g)

	start := map[int]uint64{}
	for _, proc := range g.Procs {
		start[proc.PID] = proc.StartTime
	}
	var pids []int
	if wholeCgroup(g) {
		var err error
		if pids, err = cgroupPIDs(env.Cgroup, g.Cgroup); err != nil {
			return nil, fmt.Errorf("reading %s: %w", g.Cgroup, err)
		}
		p.Cgroup = g.Cgroup
	} else {
		pids = slices.Clone(g.PIDs)
	}
	sort.Ints(pids)
	changed := false
	for _, pid := range pids {
		if pid == env.SelfPID {
			continue
		}
		st, err := env.Proc.ReadStat(pid)
		if err != nil || st.KernelThread() {
			continue
		}
		if s, known := start[pid]; known && s != st.StartTime {
			changed = true // PID reused since the snapshot
			if p.Cgroup == "" {
				continue
			}
		}
		if _, known := start[pid]; !known {
			changed = true
		}
		status, _ := env.Proc.ReadStatus(pid)
		t := Target{PID: pid, StartTime: st.StartTime, Comm: st.Comm, UID: status.UID, fd: -1}
		if env.SelfUID != 0 && t.UID != env.SelfUID {
			p.NeedsSudo = true
		}
		p.Targets = append(p.Targets, t)
	}
	if len(p.Targets) != len(g.Procs) {
		changed = true
	}
	if len(p.Targets) == 0 {
		return nil, fmt.Errorf("%s has no processes left", g.Name)
	}
	if !p.NeedsSudo {
		for i := range p.Targets {
			if err := p.Targets[i].open(env.Proc); err != nil && !gone(err) {
				p.Close()
				return nil, fmt.Errorf("pid %d: %w", p.Targets[i].PID, err)
			}
		}
	}
	p.Estimate = model.EstimateOf(g.Mem)

	switch mode {
	case Freeze:
		p.UseCgroup = p.Cgroup != "" && env.Cgroup.CanFreeze(p.Cgroup)
	case Terminate:
		p.UseCgroup = p.Cgroup != "" && env.Cgroup.CanKill(p.Cgroup)
	}
	p.Warnings = warnings(g, p, env, changed)
	return p, nil
}

func warnings(g *model.Group, p *Plan, env Env, changed bool) []string {
	var w []string
	if p.Mode == Freeze {
		w = append(w, "Freezing frees no RAM by itself: it lets the kernel swap these pages out under pressure.")
		swapFree := env.Meminfo["SwapFree"]
		switch {
		case env.Meminfo["SwapTotal"] == 0:
			w = append(w, "Swap is off, so the frozen pages will stay in RAM.")
		case swapFree < p.Estimate.Low:
			w = append(w, fmt.Sprintf("Swap has only %s free, less than this group's private memory.", pressure.Bytes(swapFree)))
		}
		if !p.UseCgroup {
			w = append(w, "Using SIGSTOP (no writable cgroup.freeze): a parent shell may report the job as stopped.")
		}
	}
	if changed {
		w = append(w, fmt.Sprintf("Membership changed since the last refresh: now %d processes.", len(p.Targets)))
	}
	if p.NeedsSudo {
		others := 0
		for _, t := range p.Targets {
			if t.UID != env.SelfUID {
				others++
			}
		}
		w = append(w, fmt.Sprintf("%d processes belong to other users: reclaim will ask through sudo.", others))
	}
	if g.Mem.Unreadable > 0 {
		w = append(w, fmt.Sprintf("%d processes could not be read: the estimate is missing their memory.", g.Mem.Unreadable))
	}
	if g.Mem.Shared > g.Mem.USS && g.Mem.USS > 0 {
		w = append(w, fmt.Sprintf("Most of this group's memory is shared (%s shared, %s private): stopping it frees little of the shared part.",
			pressure.Bytes(g.Mem.Shared), pressure.Bytes(g.Mem.USS)))
	}
	if g.CgMem != nil && g.CgMem.File > 64<<20 && p.Mode == Terminate {
		w = append(w, fmt.Sprintf("%s of page cache is charged to this cgroup: stopping the group does not free it; the kernel reclaims it later.",
			pressure.Bytes(g.CgMem.File)))
	}
	if strings.HasSuffix(g.Unit, ".service") && p.Mode == Terminate {
		restart := ""
		if env.UnitRestart != nil {
			restart = env.UnitRestart(g.Unit, g.UserUnit)
		} else {
			restart = systemctlRestart(g.Unit, g.UserUnit)
		}
		if restart != "" && restart != "no" {
			flag := ""
			if g.UserUnit {
				flag = "--user "
			}
			w = append(w, fmt.Sprintf("systemd will restart it (Restart=%s); consider: systemctl %sstop %s", restart, flag, g.Unit))
		}
	}
	return w
}

func systemctlRestart(unit string, user bool) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	args := []string{"show", "-p", "Restart", "--value", unit}
	if user {
		args = append([]string{"--user"}, args...)
	}
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Result reports what an action did.
type Result struct {
	Mode    string         `json:"mode"`
	Exited  []int          `json:"exited,omitempty"`  // left after SIGTERM
	Killed  []int          `json:"killed,omitempty"`  // needed SIGKILL
	Frozen  []int          `json:"frozen,omitempty"`  // stopped or in a frozen cgroup
	Resumed []int          `json:"resumed,omitempty"` // thawed or continued
	Left    []int          `json:"left,omitempty"`    // still running
	Failed  map[int]string `json:"failed,omitempty"`
	Method  string         `json:"method,omitempty"` // cgroup or signal
	Error   string         `json:"error,omitempty"`
}

func (r *Result) fail(pid int, err error) {
	if r.Failed == nil {
		r.Failed = map[int]string{}
	}
	r.Failed[pid] = err.Error()
}

// Summary is a one-line account of the result.
func (r Result) Summary() string {
	var parts []string
	if r.Error != "" {
		parts = append(parts, "error: "+r.Error)
	}
	if len(r.Exited) > 0 {
		parts = append(parts, fmt.Sprintf("%d exited on SIGTERM", len(r.Exited)))
	}
	if len(r.Killed) > 0 {
		parts = append(parts, fmt.Sprintf("%d killed", len(r.Killed)))
	}
	if len(r.Frozen) > 0 {
		parts = append(parts, fmt.Sprintf("%d frozen (%s)", len(r.Frozen), r.Method))
	}
	if len(r.Resumed) > 0 {
		parts = append(parts, fmt.Sprintf("%d resumed", len(r.Resumed)))
	}
	if len(r.Left) > 0 {
		parts = append(parts, fmt.Sprintf("%d still running", len(r.Left)))
	}
	if len(r.Failed) > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", len(r.Failed)))
	}
	if len(parts) == 0 {
		return "nothing to do"
	}
	return strings.Join(parts, ", ")
}

// Execute runs a plan locally, without sudo. Plans that need sudo go through
// the helper (see SudoArgs).
func Execute(p *Plan, env Env) Result {
	if p.Blocked() {
		return Result{Mode: p.Mode.String(), Error: "group is hard-protected"}
	}
	switch p.Mode {
	case Freeze:
		return freeze(p.Targets, p.Cgroup, p.UseCgroup, env)
	default:
		// A frozen cgroup can't run its SIGTERM handlers: thaw it first.
		if p.Cgroup != "" {
			if frozen, err := env.Cgroup.FreezeRequested(p.Cgroup); err == nil && frozen {
				_ = env.Cgroup.SetFrozen(p.Cgroup, false, time.Second)
			}
		}
		return terminate(p.Targets, p.Cgroup, p.UseCgroup, p.Grace, env)
	}
}

const poll = 50 * time.Millisecond

func terminate(targets []Target, cgroup string, useKill bool, grace time.Duration, env Env) Result {
	res := Result{Mode: "terminate", Method: "signal"}
	var live []*Target
	for i := range targets {
		t := &targets[i]
		if !t.alive(env.Proc) {
			res.Exited = append(res.Exited, t.PID)
			continue
		}
		if err := t.signal(env.Proc, syscall.SIGTERM); err != nil {
			if gone(err) {
				res.Exited = append(res.Exited, t.PID)
			} else {
				res.fail(t.PID, err)
			}
			continue
		}
		// A stopped process can't handle SIGTERM until continued.
		_ = t.signal(env.Proc, syscall.SIGCONT)
		live = append(live, t)
	}
	live = waitExit(live, grace, env, &res.Exited)
	if len(live) > 0 && useKill && cgroup != "" {
		if err := env.Cgroup.Kill(cgroup); err == nil {
			res.Method = "cgroup.kill"
		}
	}
	for _, t := range live {
		if err := t.signal(env.Proc, syscall.SIGKILL); err != nil && !gone(err) {
			res.fail(t.PID, err)
		}
	}
	killed := []int{}
	live = waitExit(live, 3*time.Second, env, &killed)
	res.Killed = killed
	for _, t := range live {
		res.Left = append(res.Left, t.PID)
	}
	return res
}

// waitExit polls until every target exited or the timeout passes, appending
// exited PIDs to done, and returns the survivors.
func waitExit(live []*Target, timeout time.Duration, env Env, done *[]int) []*Target {
	deadline := time.Now().Add(timeout)
	for len(live) > 0 {
		next := live[:0]
		for _, t := range live {
			if t.alive(env.Proc) {
				next = append(next, t)
			} else {
				*done = append(*done, t.PID)
			}
		}
		live = next
		if len(live) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(poll)
	}
	return live
}

func freeze(targets []Target, cgroup string, useCgroup bool, env Env) Result {
	res := Result{Mode: "freeze"}
	if useCgroup {
		res.Method = "cgroup"
		if err := env.Cgroup.SetFrozen(cgroup, true, 2*time.Second); err == nil {
			for _, t := range targets {
				res.Frozen = append(res.Frozen, t.PID)
			}
			return res
		} else {
			res.Error = "cgroup.freeze: " + err.Error() + "; fell back to SIGSTOP"
		}
	}
	res.Method = "SIGSTOP"
	for i := range targets {
		t := &targets[i]
		if err := t.signal(env.Proc, syscall.SIGSTOP); err != nil {
			if !gone(err) {
				res.fail(t.PID, err)
			}
			continue
		}
		res.Frozen = append(res.Frozen, t.PID)
	}
	return res
}

// Thaw resumes a frozen entry.
func Thaw(e FrozenEntry, env Env) Result {
	res := Result{Mode: "thaw", Method: e.Method}
	if e.Method == "cgroup" {
		if err := env.Cgroup.SetFrozen(e.Cgroup, false, 2*time.Second); err != nil {
			res.Error = err.Error()
			return res
		}
		for _, t := range e.Targets {
			res.Resumed = append(res.Resumed, t.PID)
		}
		return res
	}
	for _, t := range e.Targets {
		t.fd = -1
		if err := t.signal(env.Proc, syscall.SIGCONT); err != nil {
			if !gone(err) {
				res.fail(t.PID, err)
			}
			continue
		}
		res.Resumed = append(res.Resumed, t.PID)
	}
	return res
}
