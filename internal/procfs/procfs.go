// Package procfs parses the parts of /proc that reclaim needs.
//
// Every reader takes an FS rooted at an arbitrary directory so tests can run
// against fixture trees.
package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FS is a /proc mount point.
type FS struct {
	Root string
}

// Default is the real /proc.
var Default = FS{Root: "/proc"}

func (fs FS) path(parts ...string) string {
	return filepath.Join(append([]string{fs.Root}, parts...)...)
}

// PIDs lists numeric entries of the proc root.
func (fs FS) PIDs() ([]int, error) {
	entries, err := os.ReadDir(fs.Root)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// PF_KTHREAD from include/linux/sched.h.
const pfKthread = 0x00200000

// Stat holds the fields of /proc/<pid>/stat that reclaim uses.
type Stat struct {
	PID       int
	Comm      string
	State     byte
	PPID      int
	Flags     uint64
	UTime     uint64
	STime     uint64
	StartTime uint64 // clock ticks since boot; with PID, identifies a process
}

// KernelThread reports whether the process is a kernel thread.
func (s Stat) KernelThread() bool { return s.Flags&pfKthread != 0 }

// ParseStat parses the contents of /proc/<pid>/stat.
func ParseStat(data []byte) (Stat, error) {
	var s Stat
	open := bytes.IndexByte(data, '(')
	close := bytes.LastIndexByte(data, ')')
	if open < 0 || close < open {
		return s, errors.New("stat: malformed comm")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data[:open])))
	if err != nil {
		return s, fmt.Errorf("stat: pid: %w", err)
	}
	s.PID = pid
	s.Comm = string(data[open+1 : close])
	// Fields after comm, numbered from 3 (state) as in proc(5).
	f := strings.Fields(string(data[close+1:]))
	if len(f) < 20 {
		return s, errors.New("stat: too few fields")
	}
	field := func(n int) uint64 { // n is the proc(5) field number
		v, _ := strconv.ParseUint(f[n-3], 10, 64)
		return v
	}
	s.State = f[0][0]
	s.PPID = int(field(4))
	s.Flags = field(9)
	s.UTime = field(14)
	s.STime = field(15)
	s.StartTime = field(22)
	return s, nil
}

// ReadStat reads /proc/<pid>/stat.
func (fs FS) ReadStat(pid int) (Stat, error) {
	data, err := os.ReadFile(fs.path(strconv.Itoa(pid), "stat"))
	if err != nil {
		return Stat{}, err
	}
	return ParseStat(data)
}

// Status holds the fields of /proc/<pid>/status that reclaim uses.
type Status struct {
	UID    int
	VmRSS  uint64 // bytes
	VmSwap uint64 // bytes
	// RssAnon and RssShmem split VmRSS; readable even when smaps_rollup
	// is not.
	RssAnon  uint64
	RssShmem uint64
}

// ParseStatus parses the contents of /proc/<pid>/status.
func ParseStatus(data []byte) Status {
	var st Status
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "Uid":
			st.UID, _ = strconv.Atoi(fields[0]) // real UID
		case "VmRSS":
			st.VmRSS = kb(fields)
		case "VmSwap":
			st.VmSwap = kb(fields)
		case "RssAnon":
			st.RssAnon = kb(fields)
		case "RssShmem":
			st.RssShmem = kb(fields)
		}
	}
	return st
}

// ReadStatus reads /proc/<pid>/status.
func (fs FS) ReadStatus(pid int) (Status, error) {
	data, err := os.ReadFile(fs.path(strconv.Itoa(pid), "status"))
	if err != nil {
		return Status{}, err
	}
	return ParseStatus(data), nil
}

// kb converts a "<n> kB" field list to bytes.
func kb(fields []string) uint64 {
	v, _ := strconv.ParseUint(fields[0], 10, 64)
	if len(fields) > 1 && fields[1] == "kB" {
		v *= 1024
	}
	return v
}

// Rollup is /proc/<pid>/smaps_rollup, in bytes.
type Rollup struct {
	RSS          uint64
	PSS          uint64
	SharedClean  uint64
	SharedDirty  uint64
	PrivateClean uint64
	PrivateDirty uint64
	Swap         uint64
	SwapPSS      uint64
	// PSS split by backing (Linux 5.7+; all zero on older kernels).
	PSSAnon  uint64
	PSSFile  uint64
	PSSShmem uint64
}

// HasPSSSplit reports whether the kernel provided Pss_Anon/File/Shmem.
func (r Rollup) HasPSSSplit() bool { return r.PSSAnon+r.PSSFile+r.PSSShmem > 0 }

// USS is the memory only this process maps.
func (r Rollup) USS() uint64 { return r.PrivateClean + r.PrivateDirty }

// Shared is the memory this process maps together with others.
func (r Rollup) Shared() uint64 { return r.SharedClean + r.SharedDirty }

// ParseRollup parses the contents of /proc/<pid>/smaps_rollup.
func ParseRollup(data []byte) Rollup {
	var r Rollup
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(val)
		if len(fields) == 0 {
			continue
		}
		var dst *uint64
		switch key {
		case "Rss":
			dst = &r.RSS
		case "Pss":
			dst = &r.PSS
		case "Shared_Clean":
			dst = &r.SharedClean
		case "Shared_Dirty":
			dst = &r.SharedDirty
		case "Private_Clean":
			dst = &r.PrivateClean
		case "Private_Dirty":
			dst = &r.PrivateDirty
		case "Swap":
			dst = &r.Swap
		case "SwapPss":
			dst = &r.SwapPSS
		case "Pss_Anon":
			dst = &r.PSSAnon
		case "Pss_File":
			dst = &r.PSSFile
		case "Pss_Shmem":
			dst = &r.PSSShmem
		}
		if dst != nil {
			*dst = kb(fields)
		}
	}
	return r
}

// ReadRollup reads /proc/<pid>/smaps_rollup. Reading another user's process
// fails with a permission error.
func (fs FS) ReadRollup(pid int) (Rollup, error) {
	data, err := os.ReadFile(fs.path(strconv.Itoa(pid), "smaps_rollup"))
	if err != nil {
		return Rollup{}, err
	}
	return ParseRollup(data), nil
}

// ParseCgroup returns the cgroup v2 path from /proc/<pid>/cgroup, or "" when
// the process has no unified-hierarchy entry.
func ParseCgroup(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return rest
		}
	}
	return ""
}

// ReadCgroup reads the cgroup v2 path of a process.
func (fs FS) ReadCgroup(pid int) (string, error) {
	data, err := os.ReadFile(fs.path(strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	return ParseCgroup(data), nil
}

// ReadCmdline returns the argument vector of a process.
func (fs FS) ReadCmdline(pid int) ([]string, error) {
	data, err := os.ReadFile(fs.path(strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(string(data), "\x00"), nil
}

// ReadExe resolves /proc/<pid>/exe. It fails for other users' processes.
func (fs FS) ReadExe(pid int) (string, error) {
	return os.Readlink(fs.path(strconv.Itoa(pid), "exe"))
}

// Meminfo maps /proc/meminfo keys to values in bytes (page counts such as
// HugePages_Total are kept as plain numbers).
type Meminfo map[string]uint64

// ParseMeminfo parses the contents of /proc/meminfo.
func ParseMeminfo(data []byte) Meminfo {
	m := Meminfo{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		if fields := strings.Fields(val); len(fields) > 0 {
			m[key] = kb(fields)
		}
	}
	return m
}

// ReadMeminfo reads /proc/meminfo.
func (fs FS) ReadMeminfo() (Meminfo, error) {
	data, err := os.ReadFile(fs.path("meminfo"))
	if err != nil {
		return nil, err
	}
	return ParseMeminfo(data), nil
}

// PSILine is one line of a pressure file.
type PSILine struct {
	Avg10, Avg60, Avg300 float64
	Total                uint64 // microseconds stalled
}

// PSI is a parsed pressure file.
type PSI struct {
	Some, Full PSILine
}

// ParsePSI parses /proc/pressure/memory or a cgroup's memory.pressure.
func ParsePSI(data []byte) (PSI, error) {
	var p PSI
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var dst *PSILine
		switch fields[0] {
		case "some":
			dst = &p.Some
		case "full":
			dst = &p.Full
		default:
			continue
		}
		found = true
		for _, kv := range fields[1:] {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "avg10":
				dst.Avg10, _ = strconv.ParseFloat(v, 64)
			case "avg60":
				dst.Avg60, _ = strconv.ParseFloat(v, 64)
			case "avg300":
				dst.Avg300, _ = strconv.ParseFloat(v, 64)
			case "total":
				dst.Total, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	if !found {
		return p, errors.New("psi: no some/full lines")
	}
	return p, nil
}

// ReadPSI reads /proc/pressure/memory.
func (fs FS) ReadPSI() (PSI, error) {
	data, err := os.ReadFile(fs.path("pressure", "memory"))
	if err != nil {
		return PSI{}, err
	}
	return ParsePSI(data)
}

// Swap is one line of /proc/swaps.
type Swap struct {
	Filename string
	Type     string
	Size     uint64 // bytes
	Used     uint64 // bytes
}

// ParseSwaps parses /proc/swaps.
func ParseSwaps(data []byte) []Swap {
	var out []Swap
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		size, _ := strconv.ParseUint(f[2], 10, 64)
		used, _ := strconv.ParseUint(f[3], 10, 64)
		out = append(out, Swap{Filename: f[0], Type: f[1], Size: size * 1024, Used: used * 1024})
	}
	return out
}

// ReadSwaps reads /proc/swaps.
func (fs FS) ReadSwaps() ([]Swap, error) {
	data, err := os.ReadFile(fs.path("swaps"))
	if err != nil {
		return nil, err
	}
	return ParseSwaps(data), nil
}

// Mount is one line of /proc/<pid>/mountinfo.
type Mount struct {
	Dev        string // major:minor of the filesystem
	MountPoint string
	FSType     string
	Source     string
}

// ParseMountinfo parses /proc/<pid>/mountinfo.
func ParseMountinfo(data []byte) []Mount {
	var out []Mount
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		a, b := strings.Fields(pre), strings.Fields(post)
		if len(a) < 5 || len(b) < 2 {
			continue
		}
		out = append(out, Mount{Dev: a[2], MountPoint: unescapeOctal(a[4]), FSType: b[0], Source: unescapeOctal(b[1])})
	}
	return out
}

// unescapeOctal decodes the \040-style escapes mountinfo uses for spaces.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ReadMountinfo reads the mount table of reclaim's own mount namespace.
func (fs FS) ReadMountinfo() ([]Mount, error) {
	data, err := os.ReadFile(fs.path("self", "mountinfo"))
	if err != nil {
		return nil, err
	}
	return ParseMountinfo(data), nil
}

// ShmSegment is a System V shared memory segment from /proc/sysvipc/shm.
type ShmSegment struct {
	Key    string
	ID     int
	Perms  uint64 // includes SHM_DEST (01000) once removal was requested
	Size   uint64
	Nattch int
	UID    int
	CPID   int
	RSS    uint64 // resident bytes
	Swap   uint64
}

// shmDest marks a segment that will be destroyed on its last detach.
const shmDest = 0o1000

// Orphaned reports a segment no process has attached and nobody removed.
func (s ShmSegment) Orphaned() bool { return s.Nattch == 0 && s.Perms&shmDest == 0 }

// ParseSysvShm parses /proc/sysvipc/shm, locating columns by the header so
// older kernels without rss/swap columns still parse.
func ParseSysvShm(data []byte) []ShmSegment {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return nil
	}
	col := map[string]int{}
	for i, h := range strings.Fields(lines[0]) {
		col[h] = i
	}
	get := func(f []string, name string) string {
		if i, ok := col[name]; ok && i < len(f) {
			return f[i]
		}
		return ""
	}
	num := func(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }
	var out []ShmSegment
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 7 {
			continue
		}
		perms, _ := strconv.ParseUint(get(f, "perms"), 8, 64)
		out = append(out, ShmSegment{
			Key:    get(f, "key"),
			ID:     int(num(get(f, "shmid"))),
			Perms:  perms,
			Size:   num(get(f, "size")),
			Nattch: int(num(get(f, "nattch"))),
			UID:    int(num(get(f, "uid"))),
			CPID:   int(num(get(f, "cpid"))),
			RSS:    num(get(f, "rss")),
			Swap:   num(get(f, "swap")),
		})
	}
	return out
}

// ReadSysvShm reads /proc/sysvipc/shm.
func (fs FS) ReadSysvShm() ([]ShmSegment, error) {
	data, err := os.ReadFile(fs.path("sysvipc", "shm"))
	if err != nil {
		return nil, err
	}
	return ParseSysvShm(data), nil
}
