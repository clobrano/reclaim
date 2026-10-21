package sample

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/clobrano/reclaim/internal/procfs"
)

func TestSampleLive(t *testing.T) {
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skip("no /proc")
	}
	s := New()
	snap, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	self, ok := snap.Procs[os.Getpid()]
	if !ok {
		t.Fatal("own process missing from snapshot")
	}
	if self.Comm == "" || self.StartTime == 0 {
		t.Fatalf("incomplete %+v", self)
	}
	if snap.Meminfo["MemTotal"] == 0 {
		t.Fatal("no MemTotal")
	}
	// A second pass reuses the cache and still finds us.
	snap2, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap2.Procs[os.Getpid()]; !ok {
		t.Fatal("own process missing on second pass")
	}
}

func TestReadZram(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "zram0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mm_stat"), []byte("  4096000  1024000  1200000 0 1200000 0 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	z := ReadZram(root)
	if len(z) != 1 || z[0].Name != "zram0" || z[0].OrigData != 4096000 || z[0].MemUsed != 1200000 {
		t.Fatalf("%+v", z)
	}
}

func TestCloseEnough(t *testing.T) {
	if !closeEnough(1000, 1005) || closeEnough(1000, 1100) || !closeEnough(0, 0) {
		t.Fatal("closeEnough")
	}
}

func TestUsedOf(t *testing.T) {
	split := procfs.Rollup{PSS: 1000, RSS: 2000, PSSAnon: 600, PSSFile: 300, PSSShmem: 100}
	if u, s := usedOf(split, procfs.Status{}); u != 700 || s != 100 {
		t.Fatalf("split: %d %d", u, s)
	}
	// Pre-5.7 kernels: PSS scaled by the anon+shmem share of RSS.
	old := procfs.Rollup{PSS: 1000, RSS: 2000}
	if u, s := usedOf(old, procfs.Status{RssAnon: 1200, RssShmem: 200}); u != 700 || s != 100 {
		t.Fatalf("scaled: %d %d", u, s)
	}
	if u, _ := usedOf(procfs.Rollup{}, procfs.Status{}); u != 0 {
		t.Fatal("empty")
	}
}
