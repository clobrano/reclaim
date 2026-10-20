package cgroupfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T, files map[string]string) FS {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return FS{Root: root}
}

func TestReadMem(t *testing.T) {
	fs := fixture(t, map[string]string{
		"cgroup.controllers":                  "memory pids\n",
		"a.slice/b.scope/memory.current":      "1048576\n",
		"a.slice/b.scope/memory.swap.current": "4096\n",
		"a.slice/b.scope/memory.stat":         "anon 700000\nfile 300000\nkernel 1000\nshmem 5\n",
		"a.slice/b.scope/memory.pressure":     "some avg10=1.00 avg60=0.00 avg300=0.00 total=42\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1\n",
		"a.slice/b.scope/cgroup.procs":        "10\n11\n",
	})
	if !fs.Unified() {
		t.Fatal("expected unified")
	}
	m, err := fs.ReadMem("/a.slice/b.scope")
	if err != nil {
		t.Fatal(err)
	}
	want := Mem{Current: 1048576, Swap: 4096, Anon: 700000, File: 300000, Shmem: 5, Kernel: 1000}
	if m != want {
		t.Fatalf("got %+v", m)
	}
	p, err := fs.ReadPSI("/a.slice/b.scope")
	if err != nil || p.Some.Total != 42 {
		t.Fatalf("psi %+v %v", p, err)
	}
	pids, _ := fs.Procs("/a.slice/b.scope")
	if len(pids) != 2 || pids[1] != 11 {
		t.Fatalf("pids %v", pids)
	}
	if !fs.HasChildren("/a.slice") || fs.HasChildren("/a.slice/b.scope") {
		t.Fatal("children")
	}
}

func TestSetFrozenFixture(t *testing.T) {
	// A fixture can't change cgroup.events by itself, so pre-set it to the
	// target state and check the write and the wait.
	fs := fixture(t, map[string]string{
		"x.scope/cgroup.freeze": "0\n",
		"x.scope/cgroup.events": "populated 1\nfrozen 1\n",
	})
	if !fs.CanFreeze("/x.scope") {
		t.Fatal("expected freezable")
	}
	if fs.CanFreeze("/") {
		t.Fatal("root is never freezable")
	}
	if err := fs.SetFrozen("/x.scope", true, time.Second); err != nil {
		t.Fatal(err)
	}
	if req, _ := fs.FreezeRequested("/x.scope"); !req {
		t.Fatal("freeze not written")
	}
	if err := fs.SetFrozen("/x.scope", false, 50*time.Millisecond); err != ErrFreezeTimeout {
		t.Fatalf("expected timeout, got %v", err)
	}
}
