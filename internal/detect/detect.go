// Package detect classifies cgroup paths: systemd units, containers, pods
// and libvirt guests.
package detect

import (
	"strconv"
	"strings"
)

// Info is what a cgroup path says about the processes in it.
type Info struct {
	// Unit is the outermost meaningful systemd unit (a .scope or .service),
	// and UnitPath the cgroup path up to and including it.
	Unit     string
	UnitPath string
	// UserUnit is true when the unit belongs to a systemd --user manager.
	UserUnit bool

	// Container is the outermost container. For a kind node, the pods it
	// runs are in Pod and InnerContainer.
	Container      *Ref
	Pod            *PodRef
	InnerContainer *Ref

	VM *VMRef
}

// Ref locates a container.
type Ref struct {
	Runtime string // podman, docker, containerd, crio
	ID      string
	Path    string // cgroup path of the container's scope
	Rootful bool
}

// PodRef locates a pod.
type PodRef struct {
	UID  string
	Path string
}

// VMRef locates a libvirt guest.
type VMRef struct {
	Name string
	URI  string
	Path string
}

// Unescape decodes systemd's \xNN escapes in unit names.
func Unescape(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isUnit(seg string) bool {
	return strings.HasSuffix(seg, ".scope") || strings.HasSuffix(seg, ".service")
}

func isUserManager(seg string) bool {
	return strings.HasPrefix(seg, "user@") && strings.HasSuffix(seg, ".service")
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// containerScope recognises container runtime scopes.
func containerScope(seg string) (runtime, id string, ok bool) {
	name, isScope := strings.CutSuffix(seg, ".scope")
	if !isScope {
		// cgroupfs-driver layouts use a bare 64-hex directory.
		if len(seg) == 64 && isHex(seg) {
			return "containerd", seg, true
		}
		return "", "", false
	}
	for _, p := range []struct{ prefix, runtime string }{
		{"libpod-conmon-", "podman"},
		{"libpod-", "podman"},
		{"docker-", "docker"},
		{"cri-containerd-", "containerd"},
		{"crio-conmon-", "crio"},
		{"crio-", "crio"},
	} {
		if rest, ok := strings.CutPrefix(name, p.prefix); ok && isHex(rest) {
			return p.runtime, rest, true
		}
	}
	return "", "", false
}

// podSlice recognises kubepods pod cgroups such as
// kubepods-burstable-pod<uid>.slice or pod<uid>.
func podSlice(seg string) (string, bool) {
	name := strings.TrimSuffix(seg, ".slice")
	i := strings.LastIndex(name, "pod")
	if i < 0 {
		return "", false
	}
	if i > 0 && name[i-1] != '-' {
		return "", false
	}
	uid := strings.ReplaceAll(name[i+3:], "_", "-")
	if len(uid) != 36 || strings.Count(uid, "-") != 4 {
		return "", false
	}
	return uid, true
}

// vmScope recognises libvirt machine scopes, machine-qemu\x2d<n>\x2d<name>.scope.
func vmScope(seg string) (string, bool) {
	name, ok := strings.CutSuffix(Unescape(seg), ".scope")
	if !ok {
		return "", false
	}
	rest, ok := strings.CutPrefix(name, "machine-qemu-")
	if !ok {
		return "", false
	}
	_, vm, ok := strings.Cut(rest, "-") // drop the domain id
	return vm, ok && vm != ""
}

// Classify interprets a cgroup v2 path.
func Classify(path string) Info {
	var info Info
	if path == "" || path == "/" {
		return info
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	inUser := false
	for i, seg := range segs {
		cur := "/" + strings.Join(segs[:i+1], "/")
		if isUserManager(seg) {
			inUser = true
			continue
		}
		if info.Unit == "" && isUnit(seg) {
			info.Unit = seg
			info.UnitPath = cur
			info.UserUnit = inUser
		}
		if rt, id, ok := containerScope(seg); ok {
			ref := &Ref{Runtime: rt, ID: id, Path: cur, Rootful: !inUser}
			switch {
			case info.Container == nil:
				info.Container = ref
			case info.InnerContainer == nil:
				info.InnerContainer = ref
			}
			continue
		}
		if uid, ok := podSlice(seg); ok && info.Pod == nil {
			info.Pod = &PodRef{UID: uid, Path: cur}
			continue
		}
		if name, ok := vmScope(seg); ok && info.VM == nil {
			uri := "qemu:///system"
			if inUser {
				uri = "qemu:///session"
			}
			info.VM = &VMRef{Name: name, URI: uri, Path: cur}
		}
	}
	// A pod outside any container scope is a host-level kubelet's pod; its
	// containers are scopes or bare IDs below the pod slice.
	if info.Pod != nil && info.Container != nil && info.InnerContainer == nil &&
		len(info.Container.Path) > len(info.Pod.Path) {
		info.InnerContainer, info.Container = info.Container, nil
	}
	return info
}

// launchers are prefixes desktop launchers put in app scope names.
var launchers = map[string]bool{
	"gnome": true, "kde": true, "flatpak": true, "snap": true, "dbus": true,
	"xdg": true, "sway": true, "hyprland": true, "niri": true, "cosmic": true,
}

// AppName derives a human name from a systemd unit name, for example
// "app-gnome-org.gnome.Terminal-4711.scope" → "Terminal".
func AppName(unit string) string {
	name := Unescape(unit)
	for _, suf := range []string{".scope", ".service", ".slice"} {
		name = strings.TrimSuffix(name, suf)
	}
	if before, _, ok := strings.Cut(name, "@"); ok && before != "" && !strings.HasPrefix(name, "user@") {
		name = before
	}
	switch {
	case name == "init":
		return "init"
	case strings.HasPrefix(name, "user@"):
		return "systemd --user"
	case strings.HasPrefix(name, "session-"):
		return name
	}
	app, isApp := strings.CutPrefix(name, "app-")
	if !isApp {
		return dropRandom(name)
	}
	parts := strings.Split(app, "-")
	if len(parts) > 1 && launchers[parts[0]] {
		parts = parts[1:]
	}
	app = dropRandom(strings.Join(parts, "-"))
	// Reverse-DNS application IDs: keep the last component.
	if strings.Count(app, ".") >= 2 {
		app = app[strings.LastIndex(app, ".")+1:]
	}
	return app
}

// dropRandom removes a trailing "-<digits>" or "-<long hex>" instance suffix.
func dropRandom(name string) string {
	i := strings.LastIndex(name, "-")
	if i <= 0 {
		return name
	}
	last := name[i+1:]
	if _, err := strconv.Atoi(last); err == nil || (len(last) >= 8 && isHex(last)) {
		return name[:i]
	}
	return name
}
