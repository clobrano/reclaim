// Package sysmem explains system memory in plain language, tagging each
// category with whether and how it can be reclaimed.
package sysmem

import (
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
)

// Tag says who can free a category.
type Tag int

const (
	// TagKernel: the kernel frees this itself when memory is needed.
	TagKernel Tag = iota
	// TagAction: freeable by an action (stopping a process, flushing swap, ...).
	TagAction
	// TagNone: not reclaimable.
	TagNone
	// TagUnused marks free memory, which is not a use at all.
	TagUnused
)

func (t Tag) String() string {
	switch t {
	case TagKernel:
		return "the kernel frees this itself"
	case TagAction:
		return "freeable by an action"
	case TagUnused:
		return "unused"
	}
	return "not reclaimable"
}

// Short is a compact label for narrow layouts.
func (t Tag) Short() string {
	switch t {
	case TagKernel:
		return "kernel"
	case TagAction:
		return "action"
	case TagUnused:
		return "free"
	}
	return "no"
}

// Row is one category of the breakdown.
type Row struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
	Tag   Tag    `json:"-"`
	TagS  string `json:"tag"`
	// InRAM is false for rows that describe data outside RAM (swap).
	InRAM   bool   `json:"in_ram"`
	Meaning string `json:"meaning"`
	Detail  string `json:"-"`
}

// Explanations, kept in one place so the wording is reviewed together.
var text = map[string][2]string{
	"Anonymous": {
		"Program data: heaps, stacks, JIT caches.",
		"Memory programs allocated for themselves. It only goes away when the program frees it or exits, or when the kernel swaps it out. Stopping the owning group frees it; see the groups list for who owns it.",
	},
	"Page cache": {
		"Copies of files kept in RAM for speed.",
		"Clean file pages that can be dropped instantly and re-read from disk. A large cache is healthy: it is memory doing useful work until something else needs it. Dropping it by hand only makes the next reads slower.",
	},
	"Dirty / writeback": {
		"File changes not yet written to disk.",
		"Modified file pages. The kernel writes them out and then can drop them like the rest of the page cache.",
	},
	"Slab, reclaimable": {
		"Kernel caches, mostly file names and inodes.",
		"Kernel object caches (dentries, inodes) that the kernel shrinks under pressure on its own.",
	},
	"Slab, unreclaimable": {
		"Kernel data structures in active use.",
		"Kernel allocations that cannot be dropped: network buffers, driver state, and similar. If this keeps growing, it can indicate a kernel or driver leak.",
	},
	"Shmem / tmpfs": {
		"Shared memory and files in RAM-backed filesystems.",
		"Files in tmpfs (/tmp, /dev/shm, /run), shared memory segments, and graphics buffers. The kernel can only swap them out. They are freed by deleting the files or stopping the processes that hold the segments.",
	},
	"zram": {
		"RAM used by compressed swap.",
		"Compressed swapped-out pages stored in RAM. This shrinks when swapped pages are read back or freed; it cannot be dropped directly.",
	},
	"Hugepages (reserved)": {
		"Memory set aside for huge pages.",
		"Pages reserved by vm.nr_hugepages. They are unavailable to anything else, used or not, until the reservation is lowered.",
	},
	"Kernel": {
		"Page tables, kernel stacks and per-CPU data.",
		"Memory the kernel needs to run processes and itself. It shrinks only when processes exit.",
	},
	"Free": {
		"Unused.",
		"Memory nothing is using right now.",
	},
	"Unaccounted": {
		"Not attributed by /proc/meminfo.",
		"The remainder after the categories above: driver allocations, the GPU, firmware reservations and rounding.",
	},
	"Swap used": {
		"Data swapped out of RAM (not counted in RAM).",
		"Pages the kernel moved to swap. Flushing swap (swapoff/swapon) brings them back into RAM, which only helps if enough RAM is free to hold them.",
	},
}

func row(name string, bytes uint64, tag Tag, inRAM bool) Row {
	t := text[name]
	return Row{Name: name, Bytes: bytes, Tag: tag, TagS: tag.String(), InRAM: inRAM, Meaning: t[0], Detail: t[1]}
}

func sub(a uint64, bs ...uint64) uint64 {
	for _, b := range bs {
		if b >= a {
			return 0
		}
		a -= b
	}
	return a
}

// Breakdown explains RAM use. RAM rows sum to MemTotal, with any remainder
// in "Unaccounted"; the "Swap used" row comes last and is not RAM.
func Breakdown(m procfs.Meminfo, zram []model.Zram) []Row {
	var zramUsed uint64
	for _, z := range zram {
		zramUsed += z.MemUsed
	}
	dirty := m["Dirty"] + m["Writeback"]
	cache := sub(m["Cached"]+m["Buffers"], m["Shmem"], dirty)
	kernel := m["PageTables"] + m["SecPageTables"] + m["KernelStack"] + m["Percpu"]
	huge := m["HugePages_Total"] * m["Hugepagesize"]
	rows := []Row{
		row("Anonymous", m["AnonPages"], TagAction, true),
		row("Page cache", cache, TagKernel, true),
		row("Dirty / writeback", dirty, TagKernel, true),
		row("Slab, reclaimable", m["SReclaimable"], TagKernel, true),
		row("Slab, unreclaimable", m["SUnreclaim"], TagNone, true),
		row("Shmem / tmpfs", m["Shmem"], TagAction, true),
	}
	if len(zram) > 0 {
		rows = append(rows, row("zram", zramUsed, TagNone, true))
	}
	if huge > 0 {
		rows = append(rows, row("Hugepages (reserved)", huge, TagNone, true))
	}
	rows = append(rows,
		row("Kernel", kernel, TagNone, true),
		row("Free", m["MemFree"], TagUnused, true),
	)
	var sum uint64
	for _, r := range rows {
		sum += r.Bytes
	}
	rows = append(rows, row("Unaccounted", sub(m["MemTotal"], sum), TagNone, true))
	if m["SwapTotal"] > 0 {
		rows = append(rows, row("Swap used", sub(m["SwapTotal"], m["SwapFree"]), TagAction, false))
	}
	return rows
}

// Summary is the headline numbers.
type Summary struct {
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
	Used      uint64 `json:"used"`
	SwapTotal uint64 `json:"swap_total"`
	SwapUsed  uint64 `json:"swap_used"`
}

// Summarize computes the headline numbers.
func Summarize(m procfs.Meminfo) Summary {
	return Summary{
		Total:     m["MemTotal"],
		Available: m["MemAvailable"],
		Used:      sub(m["MemTotal"], m["MemAvailable"]),
		SwapTotal: m["SwapTotal"],
		SwapUsed:  sub(m["SwapTotal"], m["SwapFree"]),
	}
}
