package action

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/protect"
)

// HelperFlag is the hidden flag that runs the privileged helper.
const HelperFlag = "--helper"

// SudoArgs is the command line that performs the plan through sudo.
func SudoArgs(exe string, p *Plan) []string {
	args := []string{"sudo", "--", exe, HelperFlag, p.Mode.String(), "--grace", p.Grace.String()}
	if p.UseCgroup && p.Cgroup != "" {
		args = append(args, "--cgroup", p.Cgroup)
	}
	for _, t := range p.Targets {
		args = append(args, t.String())
	}
	return args
}

// SudoThawArgs is the command line that resumes a frozen entry through sudo.
func SudoThawArgs(exe string, e FrozenEntry) []string {
	args := []string{"sudo", "--", exe, HelperFlag, "thaw"}
	if e.Method == "cgroup" {
		args = append(args, "--cgroup", e.Cgroup)
	}
	for _, t := range e.Targets {
		args = append(args, t.String())
	}
	return args
}

// RunHelper is the privileged side. It trusts nothing from the caller: every
// target is re-validated by start time and checked against the protections
// that can never be overridden. It prints a JSON Result.
func RunHelper(args []string, stdout io.Writer) int {
	res, err := runHelper(args)
	if err != nil {
		res.Error = err.Error()
	}
	_ = json.NewEncoder(stdout).Encode(res)
	if err != nil {
		return 1
	}
	return 0
}

func runHelper(args []string) (Result, error) {
	if len(args) == 0 {
		return Result{}, errors.New("helper: missing mode")
	}
	mode := args[0]
	fs := flag.NewFlagSet("helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	grace := fs.Duration("grace", 5*time.Second, "")
	cgroup := fs.String("cgroup", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return Result{Mode: mode}, err
	}
	env := Env{Proc: procfs.Default, Cgroup: cgroupfs.Default, SelfPID: os.Getpid()}
	targets, err := validate(fs.Args(), env, os.Getppid())
	if err != nil {
		return Result{Mode: mode}, err
	}
	if *cgroup != "" {
		if err := validateCgroup(*cgroup, targets, env); err != nil {
			return Result{Mode: mode}, err
		}
	}
	defer func() {
		for i := range targets {
			targets[i].close()
		}
	}()
	switch mode {
	case "terminate":
		return terminate(targets, *cgroup, *cgroup != "", *grace, env), nil
	case "freeze":
		return freeze(targets, *cgroup, *cgroup != "", env), nil
	case "thaw":
		method := "SIGSTOP"
		if *cgroup != "" {
			method = "cgroup"
		}
		return Thaw(FrozenEntry{Method: method, Cgroup: *cgroup, Targets: targets}, env), nil
	}
	return Result{Mode: mode}, fmt.Errorf("helper: unknown mode %q", mode)
}

// validate parses pid:start targets and refuses anything that is gone,
// reused, PID 1, a kernel thread, the helper's own ancestry, or a default
// system component.
func validate(specs []string, env Env, parent int) ([]Target, error) {
	if len(specs) == 0 {
		return nil, errors.New("helper: no targets")
	}
	ancestors := map[int]bool{env.SelfPID: true}
	for pid := parent; pid > 1 && !ancestors[pid]; {
		ancestors[pid] = true
		st, err := env.Proc.ReadStat(pid)
		if err != nil {
			break
		}
		pid = st.PPID
	}
	var out []Target
	for _, s := range specs {
		t, err := ParseTarget(s)
		if err != nil {
			return nil, err
		}
		if t.PID == 1 || ancestors[t.PID] {
			return nil, fmt.Errorf("helper: refusing pid %d (init or reclaim's own ancestry)", t.PID)
		}
		st, err := env.Proc.ReadStat(t.PID)
		if err != nil || st.StartTime != t.StartTime {
			continue // exited or reused: skip, never signal a stranger
		}
		if st.KernelThread() {
			return nil, fmt.Errorf("helper: refusing kernel thread %d", t.PID)
		}
		if protect.SystemDefault(st.Comm) {
			return nil, fmt.Errorf("helper: refusing %s (pid %d), a protected system component", st.Comm, t.PID)
		}
		t.Comm = st.Comm
		if err := t.open(env.Proc); err != nil {
			if gone(err) {
				continue
			}
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// validateCgroup checks that a cgroup operation can't reach beyond the
// validated targets: every process in the subtree must be one of them.
func validateCgroup(cg string, targets []Target, env Env) error {
	if cg == "/" || cg == "" {
		return errors.New("helper: refusing the root cgroup")
	}
	allowed := map[int]bool{}
	for _, t := range targets {
		allowed[t.PID] = true
	}
	pids, err := cgroupPIDs(env.Cgroup, cg)
	if err != nil {
		return err
	}
	for _, pid := range pids {
		if !allowed[pid] {
			return fmt.Errorf("helper: cgroup %s holds pid %d, which was not confirmed", cg, pid)
		}
	}
	return nil
}
