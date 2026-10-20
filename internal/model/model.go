// Package model holds the types shared by the sampler, the groupers and the UI.
package model

import (
	"time"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/procfs"
)

// Mem is per-process or summed memory accounting, in bytes.
type Mem struct {
	USS     uint64 `json:"uss"`
	PSS     uint64 `json:"pss"`
	Shared  uint64 `json:"shared"`
	Swap    uint64 `json:"swap"`
	SwapPSS uint64 `json:"swap_pss"`
	RSS     uint64 `json:"rss"` // shown for familiarity, never used in estimates

	// Unreadable counts processes whose smaps_rollup could not be read.
	// Their USS/PSS/Shared/SwapPSS are missing from the sums above.
	Unreadable int `json:"unreadable,omitempty"`
}

// Add accumulates o into m.
func (m *Mem) Add(o Mem) {
	m.USS += o.USS
	m.PSS += o.PSS
	m.Shared += o.Shared
	m.Swap += o.Swap
	m.SwapPSS += o.SwapPSS
	m.RSS += o.RSS
	m.Unreadable += o.Unreadable
}

// Footprint is USS plus the proportional share of swap. It is the quantity
// tracked for growth.
func (m Mem) Footprint() uint64 { return m.USS + m.SwapPSS }

// Process is one sampled process.
type Process struct {
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	UID       int      `json:"uid"`
	Comm      string   `json:"comm"`
	Exe       string   `json:"exe,omitempty"`
	Cmdline   []string `json:"cmdline,omitempty"`
	Cgroup    string   `json:"cgroup"`
	StartTime uint64   `json:"start_time"`
	State     byte     `json:"-"`
	CPUTicks  uint64   `json:"-"`
	Mem       Mem      `json:"mem"`
	// Readable is false when smaps_rollup could not be read; Mem then only
	// carries RSS and Swap from /proc/<pid>/status.
	Readable bool `json:"readable"`
}

// Snapshot is one sampling pass over the system.
type Snapshot struct {
	Time     time.Time
	SelfPID  int
	SelfUID  int
	Procs    map[int]*Process
	Meminfo  procfs.Meminfo
	PSI      *procfs.PSI // nil when PSI is unavailable
	Swaps    []procfs.Swap
	Zram     []Zram
	Unified  bool // cgroup v2 available
	CgMem    map[string]cgroupfs.Mem
	CgPSI    map[string]procfs.PSI
	Warnings []string
}

// Zram is the footprint of one zram device, from mm_stat.
type Zram struct {
	Name      string `json:"name"`
	OrigData  uint64 `json:"orig_data"`
	ComprData uint64 `json:"compr_data"`
	MemUsed   uint64 `json:"mem_used"`
}

// Kind classifies a group.
type Kind string

const (
	KindApp       Kind = "app"
	KindService   Kind = "service"
	KindSession   Kind = "session"
	KindScope     Kind = "scope"
	KindTree      Kind = "tree"
	KindProcess   Kind = "process"
	KindContainer Kind = "container"
	KindPod       Kind = "pod"
	KindNode      Kind = "k8s-node"
	KindCluster   Kind = "kind-cluster"
	KindVM        Kind = "vm"
	KindHost      Kind = "host"
)

// Actionable reports whether reclaim may act on this kind of group directly.
// Containers, pods, clusters and VMs only get suggested commands.
func (k Kind) Actionable() bool {
	switch k {
	case KindApp, KindService, KindSession, KindScope, KindTree, KindProcess:
		return true
	}
	return false
}

// Group is a set of processes shown as one row. Groups nest.
type Group struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	Detail string `json:"detail,omitempty"`

	// Cgroup is set when the group is exactly one cgroup subtree.
	Cgroup string `json:"cgroup,omitempty"`
	// Unit is the systemd unit name, when known.
	Unit string `json:"unit,omitempty"`
	// UserUnit is true for units of a systemd --user manager.
	UserUnit bool `json:"user_unit,omitempty"`

	Container *Container `json:"container,omitempty"`
	Pod       *Pod       `json:"pod,omitempty"`
	VM        *VM        `json:"vm,omitempty"`
	Cluster   string     `json:"cluster,omitempty"`

	Procs    []*Process    `json:"-"`
	PIDs     []int         `json:"pids"`
	Children []*Group      `json:"children,omitempty"`
	Mem      Mem           `json:"mem"`
	CgMem    *cgroupfs.Mem `json:"cgroup_mem,omitempty"`
	PSI      *procfs.PSI   `json:"psi,omitempty"`
	// PSIShared is true when PSI comes from a cgroup the group shares with
	// other processes.
	PSIShared bool `json:"psi_shared,omitempty"`
}

// Container identifies a container found from cgroup paths.
type Container struct {
	Runtime string            `json:"runtime"` // podman, docker, containerd, crio
	ID      string            `json:"id"`
	Name    string            `json:"name,omitempty"`
	Rootful bool              `json:"rootful"`
	Labels  map[string]string `json:"-"`
}

// Short returns the container's name, or a short ID.
func (c *Container) Short() string {
	if c.Name != "" {
		return c.Name
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

// Pod identifies a Kubernetes pod found from cgroup paths.
type Pod struct {
	UID       string `json:"uid"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	OwnerKind string `json:"owner_kind,omitempty"` // Deployment, StatefulSet, DaemonSet, ...
	OwnerName string `json:"owner_name,omitempty"`
	Context   string `json:"context,omitempty"` // kubectl context
}

// VM identifies a libvirt guest.
type VM struct {
	Name string `json:"name"`
	URI  string `json:"uri"` // qemu:///system or qemu:///session
}

// Estimate is the range of memory a stop is expected to free.
type Estimate struct {
	Low  uint64 `json:"low"`  // Σ USS + Σ SwapPss
	High uint64 `json:"high"` // Σ PSS + Σ SwapPss
	// Partial is true when some processes were unreadable, so both bounds
	// are missing their contribution.
	Partial bool `json:"partial,omitempty"`
}

// EstimateOf computes the expected freed memory of a group.
func EstimateOf(m Mem) Estimate {
	return Estimate{
		Low:     m.USS + m.SwapPSS,
		High:    m.PSS + m.SwapPSS,
		Partial: m.Unreadable > 0,
	}
}

// Walk visits g and its descendants depth first.
func (g *Group) Walk(fn func(*Group)) {
	fn(g)
	for _, c := range g.Children {
		c.Walk(fn)
	}
}

// Contains reports whether pid is a member of the group.
func (g *Group) Contains(pid int) bool {
	for _, p := range g.Procs {
		if p.PID == pid {
			return true
		}
	}
	return false
}
