// Package cgroupfs reads and writes the cgroup v2 files reclaim needs.
package cgroupfs

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/clobrano/reclaim/internal/procfs"
)

// FS is a cgroup v2 mount point.
type FS struct {
	Root string
}

// Default is the real unified hierarchy.
var Default = FS{Root: "/sys/fs/cgroup"}

// Unified reports whether Root is a cgroup v2 mount, or a directory that
// looks like one (fixtures).
func (fs FS) Unified() bool {
	_, err := os.Stat(filepath.Join(fs.Root, "cgroup.controllers"))
	return err == nil
}

// Path returns the filesystem path of a cgroup.
func (fs FS) Path(cg string) string {
	return filepath.Join(fs.Root, filepath.FromSlash(strings.TrimPrefix(cg, "/")))
}

func (fs FS) read(cg, file string) ([]byte, error) {
	return os.ReadFile(filepath.Join(fs.Path(cg), file))
}

func (fs FS) readUint(cg, file string) (uint64, error) {
	data, err := fs.read(cg, file)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return ^uint64(0), nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// Mem is the memory accounting of a cgroup, in bytes.
type Mem struct {
	Current uint64 // memory.current
	Swap    uint64 // memory.swap.current
	Anon    uint64 // memory.stat anon
	File    uint64 // memory.stat file (page cache)
	Shmem   uint64 // memory.stat shmem
	Kernel  uint64 // memory.stat kernel
}

// ReadMem reads memory.current, memory.swap.current and memory.stat.
func (fs FS) ReadMem(cg string) (Mem, error) {
	var m Mem
	cur, err := fs.readUint(cg, "memory.current")
	if err != nil {
		return m, err
	}
	m.Current = cur
	m.Swap, _ = fs.readUint(cg, "memory.swap.current")
	if data, err := fs.read(cg, "memory.stat"); err == nil {
		st := ParseStat(data)
		m.Anon, m.File, m.Shmem, m.Kernel = st["anon"], st["file"], st["shmem"], st["kernel"]
	}
	return m, nil
}

// ParseStat parses a flat-keyed file such as memory.stat.
func ParseStat(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err == nil {
			out[k] = n
		}
	}
	return out
}

// ReadPSI reads the cgroup's memory.pressure.
func (fs FS) ReadPSI(cg string) (procfs.PSI, error) {
	data, err := fs.read(cg, "memory.pressure")
	if err != nil {
		return procfs.PSI{}, err
	}
	return procfs.ParsePSI(data)
}

// Procs lists the PIDs directly in a cgroup (not its descendants).
func (fs FS) Procs(cg string) ([]int, error) {
	data, err := fs.read(cg, "cgroup.procs")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(f); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// HasChildren reports whether a cgroup has child cgroups.
func (fs FS) HasChildren(cg string) bool {
	entries, err := os.ReadDir(fs.Path(cg))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			return true
		}
	}
	return false
}

// Writable reports whether the current user may write a control file.
func (fs FS) Writable(cg, file string) bool {
	return syscall.Access(filepath.Join(fs.Path(cg), file), 2 /* W_OK */) == nil
}

// CanFreeze reports whether cgroup.freeze exists and is writable.
func (fs FS) CanFreeze(cg string) bool {
	return cg != "/" && cg != "" && fs.Writable(cg, "cgroup.freeze")
}

// CanKill reports whether cgroup.kill (Linux 5.14+) exists and is writable.
func (fs FS) CanKill(cg string) bool {
	return cg != "/" && cg != "" && fs.Writable(cg, "cgroup.kill")
}

func (fs FS) write(cg, file, val string) error {
	return os.WriteFile(filepath.Join(fs.Path(cg), file), []byte(val), 0)
}

// Kill writes cgroup.kill, which SIGKILLs every process in the subtree.
func (fs FS) Kill(cg string) error { return fs.write(cg, "cgroup.kill", "1") }

// Frozen reports the cgroup's effective frozen state from cgroup.events.
func (fs FS) Frozen(cg string) (bool, error) {
	data, err := fs.read(cg, "cgroup.events")
	if err != nil {
		return false, err
	}
	return ParseStat(data)["frozen"] == 1, nil
}

// FreezeRequested reports the value of cgroup.freeze.
func (fs FS) FreezeRequested(cg string) (bool, error) {
	data, err := fs.read(cg, "cgroup.freeze")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

// ErrFreezeTimeout means the kernel did not report the cgroup frozen in time.
var ErrFreezeTimeout = errors.New("cgroup did not report frozen in time")

// SetFrozen writes cgroup.freeze and waits for cgroup.events to agree.
func (fs FS) SetFrozen(cg string, frozen bool, timeout time.Duration) error {
	val := "0"
	if frozen {
		val = "1"
	}
	if err := fs.write(cg, "cgroup.freeze", val); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		got, err := fs.Frozen(cg)
		if err != nil {
			return err
		}
		if got == frozen {
			return nil
		}
		if time.Now().After(deadline) {
			return ErrFreezeTimeout
		}
		time.Sleep(20 * time.Millisecond)
	}
}
