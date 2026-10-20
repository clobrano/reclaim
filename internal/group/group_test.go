package group

import (
	"testing"

	"github.com/clobrano/reclaim/internal/model"
)

const (
	nodeID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ctrID  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	podUID = "6f2a1c3e_1111_2222_3333_444455556666"
	appCg  = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-code-4711.scope"
	termCg = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal-99.scope"
)

func proc(pid, ppid int, comm, cg string, uss uint64) *model.Process {
	return &model.Process{
		PID: pid, PPID: ppid, Comm: comm, Cgroup: cg, StartTime: uint64(pid) * 10,
		Readable: true, Mem: model.Mem{USS: uss, PSS: uss + 10, RSS: uss + 100},
	}
}

func snapshot(procs ...*model.Process) *model.Snapshot {
	s := &model.Snapshot{Unified: true, Procs: map[int]*model.Process{}}
	for _, p := range procs {
		s.Procs[p.PID] = p
	}
	return s
}

type fakeNames struct{}

func (fakeNames) Container(rt, id string) (string, map[string]string, bool) {
	if id == nodeID {
		return "dev-control-plane", map[string]string{"io.x-k8s.kind.cluster": "dev"}, true
	}
	return "", nil, false
}

func (fakeNames) Pod(uid string) (*model.Pod, bool) {
	return &model.Pod{UID: uid, Name: "web-7d9f-abcde", Namespace: "default", OwnerKind: "Deployment", OwnerName: "web"}, true
}

func testSnap() *model.Snapshot {
	nodeCg := "/system.slice/docker-" + nodeID + ".scope"
	podCg := nodeCg + "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod" + podUID + ".slice/cri-containerd-" + ctrID + ".scope"
	return snapshot(
		proc(1, 0, "systemd", "/init.scope", 5),
		proc(900, 1, "systemd", "/user.slice/user-1000.slice/user@1000.service/init.scope", 5),
		proc(1000, 900, "code", appCg, 1000),
		proc(1001, 1000, "code", appCg, 500),
		proc(1100, 900, "gnome-terminal-", termCg, 50),
		proc(1101, 1100, "bash", termCg, 5),
		proc(2000, 1, "systemd", nodeCg+"/init.scope", 7),
		proc(2001, 2000, "kubelet", nodeCg+"/kubelet.slice/kubelet.service", 70),
		proc(2100, 2000, "nginx", podCg, 30),
		proc(3000, 1, "qemu-system-x86", `/machine.slice/machine-qemu\x2d1\x2dfedora.scope/libvirt/emulator`, 2000),
	)
}

func TestAppsView(t *testing.T) {
	groups := Build(ViewApps, testSnap(), nil)
	var code *model.Group
	for _, g := range groups {
		if g.Name == "code" {
			code = g
		}
	}
	if code == nil {
		t.Fatal("no code group")
	}
	if code.Kind != model.KindApp || code.Cgroup != appCg || len(code.PIDs) != 2 || code.Mem.USS != 1500 {
		t.Fatalf("%+v", code)
	}
	if len(code.Children) != 2 || code.Children[0].Kind != model.KindProcess {
		t.Fatalf("children %+v", code.Children)
	}
}

func TestContainersView(t *testing.T) {
	groups := Build(ViewContainers, testSnap(), fakeNames{})
	byKind := map[model.Kind]*model.Group{}
	for _, g := range groups {
		byKind[g.Kind] = g
	}
	cluster := byKind[model.KindCluster]
	if cluster == nil || cluster.Cluster != "dev" || len(cluster.Children) != 1 {
		t.Fatalf("cluster %+v", cluster)
	}
	if cluster.Name != "kind: dev (1 nodes, 1 pods)" {
		t.Fatal(cluster.Name)
	}
	node := cluster.Children[0]
	if node.Kind != model.KindNode || node.Mem.USS != 107 {
		t.Fatalf("node %+v", node)
	}
	var pod *model.Group
	for _, c := range node.Children {
		if c.Kind == model.KindPod {
			pod = c
		}
	}
	if pod == nil || pod.Name != "default/web-7d9f-abcde" || pod.Pod.Context != "kind-dev" || len(pod.Children) != 1 {
		t.Fatalf("pod %+v", pod)
	}
	vm := byKind[model.KindVM]
	if vm == nil || vm.Name != "fedora" || vm.VM.URI != "qemu:///system" {
		t.Fatalf("vm %+v", vm)
	}
	host := byKind[model.KindHost]
	if host == nil || len(host.Children) == 0 {
		t.Fatal("no host group")
	}
	if host.Mem.USS != 5+5+1000+500+50+5 {
		t.Fatalf("host USS %d", host.Mem.USS)
	}
}

func TestTreeView(t *testing.T) {
	groups := Build(ViewTree, testSnap(), nil)
	var code, kindInit *model.Group
	for _, g := range groups {
		switch g.Name {
		case "code":
			code = g
		}
		if g.Detail == "pid 2000 + 2" {
			kindInit = g
		}
	}
	if code == nil || len(code.PIDs) != 2 || code.Kind != model.KindTree {
		t.Fatalf("code %+v", code)
	}
	if kindInit == nil {
		t.Fatalf("kind node init subtree missing: %+v", groups)
	}
}

func TestFallbackToTreeWithoutCgroupV2(t *testing.T) {
	s := testSnap()
	s.Unified = false
	for _, g := range Build(ViewApps, s, nil) {
		if g.Cgroup != "" {
			t.Fatalf("expected tree groups, got %+v", g)
		}
	}
}

func TestKindCluster(t *testing.T) {
	cases := map[string]string{
		"kind-control-plane": "kind",
		"dev-worker":         "dev",
		"dev-worker2":        "dev",
		"postgres":           "",
		"my-workerbee":       "",
	}
	for name, want := range cases {
		if got := KindCluster(&model.Container{Name: name}); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestFind(t *testing.T) {
	groups := Build(ViewApps, testSnap(), nil)
	if g := Find(groups, "cg:"+appCg); g == nil || g.Name != "code" {
		t.Fatal("find")
	}
	if Find(groups, "nope") != nil {
		t.Fatal("found nonexistent")
	}
}
