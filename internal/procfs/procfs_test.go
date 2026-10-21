package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseStat(t *testing.T) {
	// comm contains spaces and parentheses, which is why parsing anchors on
	// the last ')'.
	data := []byte("1234 (Web (Content) x) S 1000 1234 1000 0 -1 4194560 86 0 0 0 7 3 0 0 20 0 1 0 9005 2928640 363 18446744073709551615")
	s, err := ParseStat(data)
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != 1234 || s.Comm != "Web (Content) x" || s.State != 'S' || s.PPID != 1000 {
		t.Fatalf("unexpected %+v", s)
	}
	if s.UTime != 7 || s.STime != 3 || s.StartTime != 9005 {
		t.Fatalf("unexpected times %+v", s)
	}
	if s.KernelThread() {
		t.Fatal("not a kernel thread")
	}
	k, _ := ParseStat([]byte("2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 18446744073709551615"))
	if !k.KernelThread() {
		t.Fatal("kthreadd is a kernel thread")
	}
	if _, err := ParseStat([]byte("garbage")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseStatus(t *testing.T) {
	st := ParseStatus([]byte("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t    1924 kB\nRssAnon:\t 1000 kB\nRssShmem:\t 24 kB\nVmSwap:\t  10 kB\n"))
	if st.UID != 1000 || st.VmRSS != 1924*1024 || st.VmSwap != 10*1024 || st.RssAnon != 1000*1024 || st.RssShmem != 24*1024 {
		t.Fatalf("unexpected %+v", st)
	}
}

func TestParseRollup(t *testing.T) {
	r := ParseRollup([]byte(`5606273d3000-7ffeb6cbb000 ---p 00000000 00:00 0                          [rollup]
Rss:                1564 kB
Pss:                 446 kB
Pss_Dirty:           112 kB
Pss_Anon:            100 kB
Pss_File:            330 kB
Pss_Shmem:            16 kB
Shared_Clean:       1416 kB
Shared_Dirty:          0 kB
Private_Clean:        36 kB
Private_Dirty:       112 kB
Swap:                 20 kB
SwapPss:              10 kB
`))
	if r.RSS != 1564*1024 || r.PSS != 446*1024 || r.USS() != 148*1024 || r.Shared() != 1416*1024 {
		t.Fatalf("unexpected %+v", r)
	}
	if !r.HasPSSSplit() || r.PSSAnon != 100*1024 || r.PSSFile != 330*1024 || r.PSSShmem != 16*1024 {
		t.Fatalf("unexpected split %+v", r)
	}
	if r.Swap != 20*1024 || r.SwapPSS != 10*1024 {
		t.Fatalf("unexpected swap %+v", r)
	}
}

func TestParseCgroup(t *testing.T) {
	v2 := "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-code-4711.scope\n"
	if got := ParseCgroup([]byte(v2)); got != "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-code-4711.scope" {
		t.Fatal(got)
	}
	hybrid := "9:name=systemd:/\n4:memory:/x\n0::/\n"
	if got := ParseCgroup([]byte(hybrid)); got != "/" {
		t.Fatal(got)
	}
	if got := ParseCgroup([]byte("4:memory:/x\n")); got != "" {
		t.Fatal(got)
	}
}

func TestParseMeminfo(t *testing.T) {
	m := ParseMeminfo([]byte("MemTotal:       32000000 kB\nHugePages_Total:       4\nHugepagesize:       2048 kB\n"))
	if m["MemTotal"] != 32000000*1024 || m["HugePages_Total"] != 4 || m["Hugepagesize"] != 2048*1024 {
		t.Fatalf("unexpected %v", m)
	}
}

func TestParsePSI(t *testing.T) {
	p, err := ParsePSI([]byte("some avg10=18.50 avg60=4.00 avg300=1.00 total=123456\nfull avg10=2.00 avg60=0.50 avg300=0.10 total=789\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Some.Avg10 != 18.5 || p.Some.Total != 123456 || p.Full.Avg60 != 0.5 || p.Full.Total != 789 {
		t.Fatalf("unexpected %+v", p)
	}
	if _, err := ParsePSI([]byte("")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSwaps(t *testing.T) {
	s := ParseSwaps([]byte("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/zram0  partition\t8388604\t\t1024\t\t100\n"))
	if len(s) != 1 || s[0].Filename != "/dev/zram0" || s[0].Size != 8388604*1024 || s[0].Used != 1024*1024 {
		t.Fatalf("unexpected %+v", s)
	}
}

func TestFSFixture(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "42")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cmdline", "/usr/bin/sleep\x00100\x00")
	write("cgroup", "0::/a.scope\n")
	if err := os.Mkdir(filepath.Join(root, "self-not-a-pid"), 0o755); err != nil {
		t.Fatal(err)
	}
	fs := FS{Root: root}
	pids, err := fs.PIDs()
	if err != nil || len(pids) != 1 || pids[0] != 42 {
		t.Fatalf("pids %v %v", pids, err)
	}
	args, _ := fs.ReadCmdline(42)
	if len(args) != 2 || args[1] != "100" {
		t.Fatalf("args %q", args)
	}
	cg, _ := fs.ReadCgroup(42)
	if cg != "/a.scope" {
		t.Fatal(cg)
	}
}

func TestLiveSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	s, err := Default.ReadStat(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if s.PID != os.Getpid() || s.StartTime == 0 {
		t.Fatalf("unexpected %+v", s)
	}
	r, err := Default.ReadRollup(os.Getpid())
	if err != nil {
		t.Skipf("smaps_rollup unavailable: %v", err)
	}
	if r.PSS == 0 || r.RSS < r.USS() {
		t.Fatalf("implausible %+v", r)
	}
}
