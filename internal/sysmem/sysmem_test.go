package sysmem

import (
	"testing"

	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
)

const gib = 1 << 30

func meminfo() procfs.Meminfo {
	return procfs.Meminfo{
		"MemTotal": 32 * gib, "MemFree": 2 * gib, "MemAvailable": 9 * gib,
		"Buffers": 1 * gib, "Cached": 8 * gib, "Shmem": 1 * gib,
		"Dirty": gib / 4, "Writeback": 0,
		"AnonPages": 14 * gib, "SReclaimable": gib, "SUnreclaim": gib / 2,
		"PageTables": gib / 4, "KernelStack": gib / 16, "Percpu": gib / 16,
		"HugePages_Total": 512, "Hugepagesize": 2 << 20,
		"SwapTotal": 8 * gib, "SwapFree": 2 * gib,
	}
}

func TestBreakdownSumsToTotal(t *testing.T) {
	rows := Breakdown(meminfo(), []model.Zram{{Name: "zram0", MemUsed: gib}})
	var ram uint64
	byName := map[string]Row{}
	for _, r := range rows {
		byName[r.Name] = r
		if r.InRAM {
			ram += r.Bytes
		}
		if r.Meaning == "" || r.Detail == "" {
			t.Errorf("%s has no explanation", r.Name)
		}
	}
	if ram != 32*gib {
		t.Fatalf("RAM rows sum to %d, want %d", ram, 32*gib)
	}
	if got := byName["Page cache"].Bytes; got != 8*gib+gib-gib-gib/4 {
		t.Fatalf("page cache %d", got)
	}
	if byName["Swap used"].Bytes != 6*gib || byName["Swap used"].InRAM {
		t.Fatal("swap row")
	}
	if byName["Hugepages (reserved)"].Bytes != gib {
		t.Fatal("hugepages")
	}
	if byName["Anonymous"].Tag != TagAction || byName["Page cache"].Tag != TagKernel || byName["Slab, unreclaimable"].Tag != TagNone {
		t.Fatal("tags")
	}
}

func TestBreakdownNoNegative(t *testing.T) {
	m := procfs.Meminfo{"MemTotal": 100, "Cached": 10, "Shmem": 50, "AnonPages": 200}
	for _, r := range Breakdown(m, nil) {
		if r.Bytes > 1000 {
			t.Fatalf("%s underflowed: %d", r.Name, r.Bytes)
		}
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(meminfo())
	if s.Used != 23*gib || s.SwapUsed != 6*gib {
		t.Fatalf("%+v", s)
	}
}
