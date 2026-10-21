// Package sample takes snapshots of process and system memory.
package sample

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
)

// Sampler produces snapshots. It caches smaps_rollup results because reading
// them walks page tables, which is expensive for large processes.
type Sampler struct {
	Proc     procfs.FS
	Cgroup   cgroupfs.FS
	SysBlock string // usually /sys/block, for zram

	// MaxReuse bounds how long a cached rollup is reused for a process whose
	// CPU time and RSS did not change.
	MaxReuse time.Duration
	// RetryUnreadable is how often to retry processes that failed with a
	// permission error.
	RetryUnreadable time.Duration
	Workers         int

	mu    sync.Mutex
	cache map[key]entry
}

type key struct {
	pid   int
	start uint64
}

type entry struct {
	rollup procfs.Rollup
	ok     bool
	at     time.Time
	cpu    uint64
	rss    uint64
}

// New returns a sampler for the real system.
func New() *Sampler {
	return &Sampler{
		Proc:            procfs.Default,
		Cgroup:          cgroupfs.Default,
		SysBlock:        "/sys/block",
		MaxReuse:        10 * time.Second,
		RetryUnreadable: 30 * time.Second,
		Workers:         runtime.GOMAXPROCS(0),
		cache:           map[key]entry{},
	}
}

// Sample takes one snapshot.
func (s *Sampler) Sample() (*model.Snapshot, error) {
	now := time.Now()
	snap := &model.Snapshot{
		Time:    now,
		SelfPID: os.Getpid(),
		SelfUID: os.Getuid(),
		Procs:   map[int]*model.Process{},
		Unified: s.Cgroup.Unified(),
		CgMem:   map[string]cgroupfs.Mem{},
		CgPSI:   map[string]procfs.PSI{},
	}
	var err error
	if snap.Meminfo, err = s.Proc.ReadMeminfo(); err != nil {
		return nil, err
	}
	if psi, err := s.Proc.ReadPSI(); err == nil {
		snap.PSI = &psi
	} else {
		snap.Warnings = append(snap.Warnings, "PSI unavailable (kernel needs CONFIG_PSI, sometimes psi=1): pressure and culprit detection are off")
	}
	snap.Swaps, _ = s.Proc.ReadSwaps()
	snap.Zram = ReadZram(s.SysBlock)
	if !snap.Unified {
		snap.Warnings = append(snap.Warnings, "cgroup v2 not mounted: grouping falls back to the process tree")
	}

	pids, err := s.Proc.PIDs()
	if err != nil {
		return nil, err
	}
	jobs := make(chan int)
	results := make(chan *model.Process)
	var wg sync.WaitGroup
	for range max(1, s.Workers) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pid := range jobs {
				if p := s.process(pid, now); p != nil {
					results <- p
				}
			}
		}()
	}
	go func() {
		for _, pid := range pids {
			jobs <- pid
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	live := map[key]bool{}
	for p := range results {
		snap.Procs[p.PID] = p
		live[key{p.PID, p.StartTime}] = true
	}
	s.mu.Lock()
	for k := range s.cache {
		if !live[k] {
			delete(s.cache, k)
		}
	}
	s.mu.Unlock()
	return snap, nil
}

func (s *Sampler) process(pid int, now time.Time) *model.Process {
	st, err := s.Proc.ReadStat(pid)
	if err != nil || st.KernelThread() {
		return nil
	}
	status, err := s.Proc.ReadStatus(pid)
	if err != nil {
		return nil
	}
	p := &model.Process{
		PID:       pid,
		PPID:      st.PPID,
		UID:       status.UID,
		Comm:      st.Comm,
		StartTime: st.StartTime,
		State:     st.State,
		CPUTicks:  st.UTime + st.STime,
	}
	p.Cgroup, _ = s.Proc.ReadCgroup(pid)
	p.Cmdline, _ = s.Proc.ReadCmdline(pid)
	p.Exe, _ = s.Proc.ReadExe(pid)

	r, ok := s.rollup(pid, st, status, now)
	p.Readable = ok
	if ok {
		p.Mem = model.Mem{
			USS: r.USS(), PSS: r.PSS, Shared: r.Shared(),
			Swap: r.Swap, SwapPSS: r.SwapPSS, RSS: r.RSS,
		}
	} else {
		p.Mem = model.Mem{RSS: status.VmRSS, Swap: status.VmSwap, Unreadable: 1}
	}
	return p
}

func (s *Sampler) rollup(pid int, st procfs.Stat, status procfs.Status, now time.Time) (procfs.Rollup, bool) {
	k := key{pid, st.StartTime}
	cpu := st.UTime + st.STime
	s.mu.Lock()
	e, cached := s.cache[k]
	s.mu.Unlock()
	if cached {
		age := now.Sub(e.at)
		if !e.ok && age < s.RetryUnreadable {
			return e.rollup, false
		}
		if e.ok && age < s.MaxReuse && e.cpu == cpu && closeEnough(e.rss, status.VmRSS) {
			return e.rollup, true
		}
	}
	r, err := s.Proc.ReadRollup(pid)
	e = entry{rollup: r, ok: err == nil, at: now, cpu: cpu, rss: status.VmRSS}
	if err != nil && !errors.Is(err, fs.ErrPermission) {
		// The process exited or the file is missing: don't cache.
		return r, false
	}
	s.mu.Lock()
	s.cache[k] = e
	s.mu.Unlock()
	return r, e.ok
}

func closeEnough(a, b uint64) bool {
	d := a - b
	if b > a {
		d = b - a
	}
	return d*100 <= max(a, b) // within 1%
}

// ReadZram reads mm_stat of every zram device under sysBlock.
func ReadZram(sysBlock string) []model.Zram {
	matches, _ := filepath.Glob(filepath.Join(sysBlock, "zram*", "mm_stat"))
	var out []model.Zram
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		f := strings.Fields(string(data))
		if len(f) < 3 {
			continue
		}
		num := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
		out = append(out, model.Zram{
			Name:      filepath.Base(filepath.Dir(m)),
			OrigData:  num(0),
			ComprData: num(1),
			MemUsed:   num(2),
		})
	}
	return out
}
