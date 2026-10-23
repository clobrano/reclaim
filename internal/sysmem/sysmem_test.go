package sysmem

import (
	"strings"
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

func sumParts(ps []Part) uint64 {
	var s uint64
	for _, p := range ps {
		s += p.Bytes
	}
	return s
}

func TestExplainUsed(t *testing.T) {
	m := meminfo() // 32G total, 9G available: 23G used
	groups := []GroupUse{
		{ID: "a", Name: "code", Used: 6 * gib},
		{ID: "b", Name: "kind", Used: 5 * gib, Shmem: gib / 2},
		{ID: "c", Name: "firefox", Used: 3 * gib},
		{ID: "d", Name: "slack", Used: gib},
		{ID: "e", Name: "tiny", Used: gib / 2},
	}
	parts := ExplainUsed(m, []model.Zram{{MemUsed: gib}}, groups, 3)
	if got := sumParts(parts); got != 23*gib {
		t.Fatalf("parts sum to %d, want %d: %+v", got, 23*gib, parts)
	}
	want := []struct {
		name string
		kind PartKind
	}{
		{"code", PartGroup}, {"kind", PartGroup}, {"firefox", PartGroup},
		{"2 other groups", PartOthers}, {"kernel", PartKernel},
		{"tmpfs & shmem", PartTmpfs}, {"zram", PartZram}, {"hugepages", PartHuge}, {"rest", PartRest},
	}
	if len(parts) != len(want) {
		t.Fatalf("%+v", parts)
	}
	for i, w := range want {
		if parts[i].Name != w.name || parts[i].Kind != w.kind {
			t.Fatalf("part %d = %+v, want %v", i, parts[i], w)
		}
	}
	if parts[3].Bytes != gib+gib/2 || parts[5].Bytes != gib/2 {
		t.Fatalf("others/tmpfs %+v", parts)
	}
	if PartText(PartRest) == "" {
		t.Fatal("no explanation for rest")
	}
}

func TestExplainUsedOvercount(t *testing.T) {
	m := procfs.Meminfo{"MemTotal": 10 * gib, "MemAvailable": 6 * gib, "SUnreclaim": gib}
	// Groups claim more than the 3G left after the kernel's 1G.
	parts := ExplainUsed(m, nil, []GroupUse{{Name: "a", Used: 4 * gib}, {Name: "b", Used: 2 * gib}}, 5)
	if got := sumParts(parts); got != 4*gib {
		t.Fatalf("sum %d: %+v", got, parts)
	}
	if parts[0].Bytes != 2*gib || parts[1].Bytes != gib {
		t.Fatalf("not scaled proportionally: %+v", parts)
	}
	for _, p := range parts {
		if p.Kind == PartRest {
			t.Fatal("no rest expected")
		}
	}
}

func TestExplainShmem(t *testing.T) {
	tmpfs := []model.Tmpfs{{Path: "/dev/shm", Used: 6 * gib}, {Path: "/tmp", Used: 2 * gib}, {Path: "/run", Used: 0}}
	for i := 0; i < 7; i++ {
		tmpfs = append(tmpfs, model.Tmpfs{Path: "/run/user/" + string(rune('a'+i)), Used: 1 << 20})
	}
	shm := []procfs.ShmSegment{
		{ID: 1, RSS: gib / 2},            // orphaned
		{ID: 2, RSS: gib, Nattch: 1},     // attached: a process maps it
		{ID: 3, RSS: gib, Perms: 0o1600}, // marked for removal
		{ID: 4, RSS: gib},                // orphaned, larger
	}
	parts := ExplainShmem(10*gib, tmpfs, shm)
	names := []string{}
	for _, p := range parts {
		names = append(names, p.Name)
	}
	want := "/dev/shm,/tmp,/run/user/a,/run/user/b,/run/user/c,/run/user/d,3 other tmpfs mounts,2 orphaned System V segments,not on a visible tmpfs"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	sysv := parts[len(parts)-2]
	if sysv.Bytes != gib+gib/2 || len(sysv.SegmentIDs) != 2 || sysv.SegmentIDs[0] != 4 {
		t.Fatalf("%+v", sysv)
	}
	other := parts[len(parts)-1]
	if other.Bytes != 10*gib-8*gib-7<<20-gib-gib/2 {
		t.Fatalf("other %d", other.Bytes)
	}
	// Mounts larger than the slice (swapped-out files): no "other" part.
	if p := ExplainShmem(gib, tmpfs, nil); p[len(p)-1].Kind == "other" {
		t.Fatal("other should be empty")
	}
}
