package suggest

import (
	"strings"
	"testing"

	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/sysmem"
)

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"web":          "web",
		"a b":          "'a b'",
		"it's":         `'it'\''s'`,
		"":             "''",
		"$(rm -rf /)":  "'$(rm -rf /)'",
		"--replicas=0": "--replicas=0",
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func cmds(s []Suggestion) string {
	var out []string
	for _, x := range s {
		out = append(out, x.Cmd)
	}
	return strings.Join(out, "\n")
}

func TestContainer(t *testing.T) {
	g := &model.Group{Kind: model.KindContainer, Container: &model.Container{Runtime: "podman", ID: "abcdef0123456789", Name: "pg"}}
	got := cmds(For(g))
	if got != "podman stop pg\npodman pause pg" {
		t.Fatal(got)
	}
	g.Container.Rootful = true
	g.Container.Name = ""
	if got := cmds(For(g)); !strings.HasPrefix(got, "sudo podman stop abcdef012345") {
		t.Fatal(got)
	}
	g.Container = &model.Container{Runtime: "docker", ID: "x", Name: "redis", Rootful: true}
	if got := cmds(For(g)); !strings.HasPrefix(got, "docker stop redis") {
		t.Fatal(got)
	}
}

func TestCluster(t *testing.T) {
	node := &model.Group{Kind: model.KindNode, Container: &model.Container{Runtime: "podman", Name: "dev-control-plane"}}
	g := &model.Group{Kind: model.KindCluster, Cluster: "dev", Children: []*model.Group{node}}
	if got := cmds(For(g)); got != "env KIND_EXPERIMENTAL_PROVIDER=podman kind delete cluster --name dev" {
		t.Fatal(got)
	}
}

func TestPod(t *testing.T) {
	g := &model.Group{Kind: model.KindPod, Pod: &model.Pod{Name: "web-1", Namespace: "default", OwnerKind: "Deployment", OwnerName: "web", Context: "kind-dev"}}
	got := cmds(For(g))
	want := "kubectl --context kind-dev -n default scale deployment/web --replicas=0\nkubectl --context kind-dev -n default delete pod web-1"
	if got != want {
		t.Fatal(got)
	}
	g.Pod.Name = ""
	if s := For(g); len(s) != 1 || !s[0].Disabled {
		t.Fatal("unknown pod should be disabled")
	}
}

func TestVM(t *testing.T) {
	g := &model.Group{Kind: model.KindVM, VM: &model.VM{Name: "fedora 40", URI: "qemu:///system"}, Mem: model.Mem{USS: 8 << 30}}
	got := cmds(For(g))
	for _, want := range []string{
		"sudo virsh -c qemu:///system shutdown 'fedora 40'",
		"sudo virsh -c qemu:///system managedsave 'fedora 40'",
		"sudo virsh -c qemu:///system setmem 'fedora 40' 4194304KiB --live",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestService(t *testing.T) {
	g := &model.Group{Kind: model.KindService, Unit: "syncthing.service", UserUnit: true}
	if got := cmds(For(g)); got != "systemctl --user stop syncthing.service" {
		t.Fatal(got)
	}
	if s := For(&model.Group{Kind: model.KindApp, Unit: "app-x.scope"}); s != nil {
		t.Fatal("no suggestion expected for app scopes")
	}
}

func TestKernelSwapFlush(t *testing.T) {
	const gib = 1 << 30
	flush := func(m procfs.Meminfo, z []model.Zram) Suggestion {
		s := Kernel(m, z)
		return s[len(s)-1]
	}
	if s := flush(procfs.Meminfo{"SwapTotal": 8 * gib, "SwapFree": 4 * gib, "MemAvailable": 4 * gib}, nil); !s.Disabled || !strings.Contains(s.Caveat, "Not safe") {
		t.Fatalf("%+v", s)
	}
	if s := flush(procfs.Meminfo{"SwapTotal": 8 * gib, "SwapFree": 6 * gib, "MemAvailable": 10 * gib}, []model.Zram{{}}); s.Disabled || !strings.Contains(s.Caveat, "zram") {
		t.Fatalf("%+v", s)
	}
	if s := flush(procfs.Meminfo{}, nil); !s.Disabled {
		t.Fatal("no swap")
	}
	if s := Kernel(procfs.Meminfo{}, nil)[0]; !strings.Contains(s.Caveat, "pointless") {
		t.Fatal("drop_caches caveat")
	}
}

func TestShmem(t *testing.T) {
	parts := []sysmem.ShmemPart{
		{Name: "/dev/shm", Kind: "tmpfs", Path: "/dev/shm", Bytes: 6 << 30},
		{Name: "/run/user/1001", Kind: "tmpfs", Path: "/run/user/1001", Bytes: 100 << 20},
		{Name: "/run/user/1000", Kind: "tmpfs", Path: "/run/user/1000", Bytes: 1 << 20}, // too small
		{Name: "2 orphaned System V segments", Kind: "sysv", Bytes: 3 << 30, SegmentIDs: []int{7, 9}},
		{Name: "not on a visible tmpfs", Kind: "other", Bytes: 1 << 30},
	}
	shm := []procfs.ShmSegment{{ID: 7, UID: 1000, RSS: 2 << 30, CPID: 42}, {ID: 9, UID: 0, RSS: 1 << 30}}
	got := cmds(Shmem(parts, shm, 1000))
	want := strings.Join([]string{
		"du -xah /dev/shm 2>/dev/null | sort -h | tail -20",
		"sudo du -xah /run/user/1001 2>/dev/null | sort -h | tail -20",
		"ipcrm -m 7",
		"sudo ipcrm -m 9",
		"sudo lsof -n 2>/dev/null | grep 'memfd:' | sort -k7 -n | tail -20",
	}, "\n")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
