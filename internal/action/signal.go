package action

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/clobrano/reclaim/internal/procfs"
)

// Linux syscall numbers; identical on every architecture Go supports for
// these calls (they were added after the syscall table unification).
const (
	sysPidfdSendSignal = 424
	sysPidfdOpen       = 434
)

// Target is one process an action applies to. PID plus StartTime identify it
// across PID reuse.
type Target struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start"`
	Comm      string `json:"comm,omitempty"`
	UID       int    `json:"uid"`
	fd        int
}

// String formats the target for the helper command line, pid:start.
func (t Target) String() string { return fmt.Sprintf("%d:%d", t.PID, t.StartTime) }

// ParseTarget parses pid:start.
func ParseTarget(s string) (Target, error) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return Target{}, fmt.Errorf("target %q: want pid:start", s)
	}
	pid, err := strconv.Atoi(a)
	if err != nil || pid <= 0 {
		return Target{}, fmt.Errorf("target %q: bad pid", s)
	}
	start, err := strconv.ParseUint(b, 10, 64)
	if err != nil {
		return Target{}, fmt.Errorf("target %q: bad start time", s)
	}
	return Target{PID: pid, StartTime: start, fd: -1}, nil
}

// open obtains a pidfd, after checking the start time, so later signals
// reach exactly this process even if the PID is reused.
func (t *Target) open(proc procfs.FS) error {
	t.fd = -1
	fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(t.PID), 0, 0)
	if errno == 0 {
		t.fd = int(fd)
	} else if errno != syscall.ENOSYS {
		return errno
	}
	// Verify identity after opening, so the fd can't refer to a newer
	// process with the same PID.
	if !t.sameProcess(proc) {
		t.close()
		return syscall.ESRCH
	}
	return nil
}

func (t *Target) close() {
	if t.fd > 0 {
		syscall.Close(t.fd)
		t.fd = -1
	}
}

func (t *Target) sameProcess(proc procfs.FS) bool {
	st, err := proc.ReadStat(t.PID)
	return err == nil && st.StartTime == t.StartTime
}

// signal delivers sig via the pidfd, or via kill(2) after an identity check
// on kernels without pidfds.
func (t *Target) signal(proc procfs.FS, sig syscall.Signal) error {
	// fd 0 is what a Target decoded from JSON carries: treat it as unset.
	if t.fd > 0 {
		_, _, errno := syscall.Syscall6(sysPidfdSendSignal, uintptr(t.fd), uintptr(sig), 0, 0, 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}
	if !t.sameProcess(proc) {
		return syscall.ESRCH
	}
	return syscall.Kill(t.PID, sig)
}

// alive reports whether the process still runs. Zombies count as gone:
// their memory is already freed.
func (t *Target) alive(proc procfs.FS) bool {
	st, err := proc.ReadStat(t.PID)
	if err != nil || st.StartTime != t.StartTime {
		return false
	}
	return st.State != 'Z' && st.State != 'X'
}

// gone reports whether an error means the process no longer exists.
func gone(err error) bool {
	return errors.Is(err, syscall.ESRCH)
}
