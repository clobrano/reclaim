package detect

import "testing"

const (
	id1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	id2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	uid = "6f2a1c3e-1111-2222-3333-444455556666"
)

func TestClassifyApp(t *testing.T) {
	i := Classify("/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-code-4711.scope")
	if i.Unit != "app-gnome-code-4711.scope" || !i.UserUnit || i.Container != nil {
		t.Fatalf("%+v", i)
	}
	if i.UnitPath != "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-code-4711.scope" {
		t.Fatal(i.UnitPath)
	}
}

func TestClassifySystemService(t *testing.T) {
	i := Classify("/system.slice/sshd.service")
	if i.Unit != "sshd.service" || i.UserUnit {
		t.Fatalf("%+v", i)
	}
}

func TestClassifyRootlessPodman(t *testing.T) {
	i := Classify("/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id1 + ".scope/container")
	if i.Container == nil || i.Container.Runtime != "podman" || i.Container.ID != id1 || i.Container.Rootful {
		t.Fatalf("%+v", i.Container)
	}
}

func TestClassifyKindNode(t *testing.T) {
	path := "/system.slice/docker-" + id1 + ".scope/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" +
		"6f2a1c3e_1111_2222_3333_444455556666.slice/cri-containerd-" + id2 + ".scope"
	i := Classify(path)
	if i.Container == nil || i.Container.Runtime != "docker" || !i.Container.Rootful {
		t.Fatalf("node %+v", i.Container)
	}
	if i.Pod == nil || i.Pod.UID != uid {
		t.Fatalf("pod %+v", i.Pod)
	}
	if i.InnerContainer == nil || i.InnerContainer.ID != id2 || i.InnerContainer.Runtime != "containerd" {
		t.Fatalf("inner %+v", i.InnerContainer)
	}
	if i.Unit != "docker-"+id1+".scope" {
		t.Fatal(i.Unit)
	}
}

func TestClassifyHostKubelet(t *testing.T) {
	i := Classify("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
		"6f2a1c3e_1111_2222_3333_444455556666.slice/crio-" + id2 + ".scope")
	if i.Container != nil || i.Pod == nil || i.InnerContainer == nil || i.InnerContainer.Runtime != "crio" {
		t.Fatalf("%+v", i)
	}
}

func TestClassifyVM(t *testing.T) {
	i := Classify(`/machine.slice/machine-qemu\x2d3\x2dfedora\x2d40.scope/libvirt/emulator`)
	if i.VM == nil || i.VM.Name != "fedora-40" || i.VM.URI != "qemu:///system" {
		t.Fatalf("%+v", i.VM)
	}
	j := Classify(`/user.slice/user-1000.slice/user@1000.service/machine.slice/machine-qemu\x2d1\x2dwin.scope`)
	if j.VM == nil || j.VM.URI != "qemu:///session" {
		t.Fatalf("%+v", j.VM)
	}
}

func TestClassifyRoot(t *testing.T) {
	if i := Classify("/"); i.Unit != "" || i.Container != nil {
		t.Fatalf("%+v", i)
	}
}

func TestAppName(t *testing.T) {
	cases := map[string]string{
		"app-gnome-code-4711.scope":                                  "code",
		"app-gnome-org.gnome.Terminal-1234.scope":                    "Terminal",
		"app-flatpak-org.mozilla.firefox-98765.scope":                "firefox",
		`app-gnome-xdg\x2duser\x2ddirs@autostart.service`:            "xdg-user-dirs",
		"app-org.kde.konsole-0a1b2c3d4e5f60718293a4b5c6d7e8f9.scope": "konsole",
		"session-3.scope":       "session-3",
		"sshd.service":          "sshd",
		"user@1000.service":     "systemd --user",
		"tmux-spawn-1234.scope": "tmux-spawn",
		"getty@tty1.service":    "getty",
	}
	for in, want := range cases {
		if got := AppName(in); got != want {
			t.Errorf("AppName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnescape(t *testing.T) {
	if got := Unescape(`a\x2db\x2`); got != `a-b\x2` {
		t.Fatal(got)
	}
}
