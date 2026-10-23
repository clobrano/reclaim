// Package suggest builds the commands reclaim proposes for things it does not
// act on itself: containers, pods, clusters, VMs and the kernel.
package suggest

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/pressure"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/sysmem"
)

// Suggestion is one command the user can copy and run.
type Suggestion struct {
	Title  string `json:"title"`
	Cmd    string `json:"cmd"`
	Effect string `json:"effect,omitempty"`
	Caveat string `json:"caveat,omitempty"`
	// Disabled suggestions are shown with the reason in Caveat but not
	// offered for copying.
	Disabled bool `json:"disabled,omitempty"`
}

var safe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// Quote quotes a word for POSIX shells.
func Quote(s string) string {
	if s != "" && safe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func cmd(words ...string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = Quote(w)
	}
	return strings.Join(q, " ")
}

func freesAbout(g *model.Group) string {
	e := model.EstimateOf(g.Mem)
	s := fmt.Sprintf("frees about %s–%s", pressure.Bytes(e.Low), pressure.Bytes(e.High))
	if e.Partial {
		s += " (some processes unreadable)"
	}
	return s
}

// For returns the suggestions for a group.
func For(g *model.Group) []Suggestion {
	switch g.Kind {
	case model.KindCluster:
		return cluster(g)
	case model.KindNode:
		out := container(g, true)
		if g.Cluster != "" {
			out = append(cluster(g), out...)
		}
		return out
	case model.KindContainer:
		if g.Container == nil {
			return nil
		}
		if g.Container.Runtime == "containerd" || g.Container.Runtime == "crio" {
			return []Suggestion{{
				Title:  "Stop this container through its pod",
				Cmd:    "# this container belongs to a Kubernetes pod; use the pod's commands",
				Caveat: "Containers managed by a kubelet are restarted by it; delete or scale down the pod instead.",
			}}
		}
		return container(g, false)
	case model.KindPod:
		return pod(g)
	case model.KindVM:
		return vm(g)
	}
	if strings.HasSuffix(g.Unit, ".service") {
		words := []string{"systemctl"}
		if g.UserUnit {
			words = append(words, "--user")
		} else {
			words = append([]string{"sudo"}, words...)
		}
		return []Suggestion{{
			Title:  "Stop the service through systemd",
			Cmd:    cmd(append(words, "stop", g.Unit)...),
			Effect: freesAbout(g),
			Caveat: "Unlike killing it, systemd will not restart a stopped unit.",
		}}
	}
	return nil
}

func runtimeCLI(c *model.Container) []string {
	switch c.Runtime {
	case "docker":
		return []string{"docker"}
	case "podman":
		if c.Rootful {
			return []string{"sudo", "podman"}
		}
		return []string{"podman"}
	}
	return []string{"sudo", "crictl"}
}

func container(g *model.Group, node bool) []Suggestion {
	c := g.Container
	if c == nil {
		return nil
	}
	cli := runtimeCLI(c)
	name := c.Short()
	stop := Suggestion{
		Title:  "Stop the container",
		Cmd:    cmd(append(cli, "stop", name)...),
		Effect: freesAbout(g),
	}
	pause := Suggestion{
		Title:  "Pause the container",
		Cmd:    cmd(append(cli, "pause", name)...),
		Caveat: "Pausing frees no RAM by itself; it only lets the kernel swap the pages out under pressure. Resume with " + cmd(append(cli, "unpause", name)...) + ".",
	}
	if node {
		stop.Caveat = "This is a Kubernetes node; stopping it takes down its pods and the cluster may not come back cleanly."
	}
	return []Suggestion{stop, pause}
}

func kindCmd(g *model.Group) []string {
	rt := ""
	if g.Container != nil {
		rt = g.Container.Runtime
	} else if len(g.Children) > 0 && g.Children[0].Container != nil {
		rt = g.Children[0].Container.Runtime
	}
	if rt == "podman" {
		return []string{"env", "KIND_EXPERIMENTAL_PROVIDER=podman", "kind"}
	}
	return []string{"kind"}
}

func cluster(g *model.Group) []Suggestion {
	return []Suggestion{{
		Title:  "Delete the kind cluster",
		Cmd:    cmd(append(kindCmd(g), "delete", "cluster", "--name", g.Cluster)...),
		Effect: freesAbout(g),
		Caveat: "Deletes the cluster and everything in it; recreate it with kind create cluster.",
	}}
}

func pod(g *model.Group) []Suggestion {
	p := g.Pod
	if p == nil || p.Name == "" {
		return []Suggestion{{
			Title:    "Delete the pod",
			Cmd:      "# pod name unknown",
			Caveat:   "kubectl could not resolve this pod's UID; check that kubectl works for this cluster.",
			Disabled: true,
		}}
	}
	base := []string{"kubectl"}
	if p.Context != "" {
		base = append(base, "--context", p.Context)
	}
	base = append(base, "-n", p.Namespace)
	del := Suggestion{
		Title:  "Delete the pod",
		Cmd:    cmd(append(base, "delete", "pod", p.Name)...),
		Effect: freesAbout(g),
	}
	switch p.OwnerKind {
	case "Deployment", "StatefulSet", "ReplicaSet":
		del.Caveat = fmt.Sprintf("Its %s will schedule a replacement; scale it down to keep the memory free.", p.OwnerKind)
		kind := strings.ToLower(p.OwnerKind)
		return []Suggestion{
			{
				Title:  fmt.Sprintf("Scale %s/%s down to zero", kind, p.OwnerName),
				Cmd:    cmd(append(base, "scale", kind+"/"+p.OwnerName, "--replicas=0")...),
				Effect: freesAbout(g) + " (this pod; other replicas too)",
				Caveat: "Scale back up with --replicas=<n> later.",
			},
			del,
		}
	case "DaemonSet":
		del.Caveat = "Its DaemonSet will recreate it; DaemonSets can't be scaled down."
	case "Job":
		del.Caveat = "Its Job may retry it."
	}
	return []Suggestion{del}
}

func vm(g *model.Group) []Suggestion {
	v := g.VM
	if v == nil {
		return nil
	}
	virsh := []string{"virsh", "-c", v.URI}
	if v.URI == "qemu:///system" {
		virsh = append([]string{"sudo"}, virsh...)
	}
	target := g.Mem.USS / 2 / 1024 // KiB
	if target < 1<<20 {
		target = 1 << 20 // keep at least 1 GiB
	}
	target -= target % 1024
	return []Suggestion{
		{
			Title:  "Shut the VM down",
			Cmd:    cmd(append(virsh, "shutdown", v.Name)...),
			Effect: freesAbout(g),
			Caveat: "Asks the guest to power off cleanly; it may take a while or be ignored.",
		},
		{
			Title:  "Save the VM's state to disk",
			Cmd:    cmd(append(virsh, "managedsave", v.Name)...),
			Effect: freesAbout(g),
			Caveat: "Restored where it left off on the next virsh start.",
		},
		{
			Title:  "Shrink the VM with the balloon",
			Cmd:    cmd(append(virsh, "setmem", v.Name, fmt.Sprintf("%dKiB", target), "--live")...),
			Effect: fmt.Sprintf("returns the memory above %s to the host", pressure.Bytes(target*1024)),
			Caveat: "Needs the virtio balloon driver in the guest. Check the guest's use first: " + cmd(append(virsh, "dommemstat", v.Name)...),
		},
	}
}

// Kernel returns the kernel-level suggestions, with their honest caveats.
func Kernel(m procfs.Meminfo, zram []model.Zram) []Suggestion {
	cache := m["Cached"] + m["Buffers"]
	if cache > m["Shmem"] {
		cache -= m["Shmem"]
	}
	out := []Suggestion{
		{
			Title:  "Drop the page cache",
			Cmd:    "sync && echo 1 | sudo tee /proc/sys/vm/drop_caches",
			Effect: fmt.Sprintf("frees up to %s of cache", pressure.Bytes(cache)),
			Caveat: "Usually pointless: the kernel already frees page cache on demand, and you'll pay to re-read those files from disk.",
		},
		{
			Title:  "Compact memory",
			Cmd:    "echo 1 | sudo tee /proc/sys/vm/compact_memory",
			Effect: "frees nothing; defragments free memory",
			Caveat: "Helps only with fragmentation, e.g. when huge page allocations fail.",
		},
	}
	swapUsed := m["SwapTotal"] - min(m["SwapTotal"], m["SwapFree"])
	flush := Suggestion{
		Title:  "Flush swap back into RAM",
		Cmd:    "sudo swapoff -a && sudo swapon -a",
		Effect: fmt.Sprintf("moves %s from swap back into RAM", pressure.Bytes(swapUsed)),
		Caveat: "Makes swapped-out programs responsive again; it doesn't free memory.",
	}
	need := swapUsed + swapUsed/4
	switch {
	case m["SwapTotal"] == 0:
		flush.Disabled = true
		flush.Caveat = "No swap is configured."
	case swapUsed == 0:
		flush.Disabled = true
		flush.Caveat = "Swap is empty; nothing to flush."
	case m["MemAvailable"] <= need:
		flush.Disabled = true
		flush.Caveat = fmt.Sprintf("Not safe now: %s in swap needs about %s available (with margin), only %s is. The flush could trigger the OOM killer.",
			pressure.Bytes(swapUsed), pressure.Bytes(need), pressure.Bytes(m["MemAvailable"]))
	}
	if len(zram) > 0 && !flush.Disabled {
		flush.Caveat += " Swap is on zram: flushing turns compressed pages back into uncompressed RAM, so it uses more RAM than zram does now."
	}
	return append(out, flush)
}

// Shmem returns commands to find and free the shared memory no process maps:
// what fills each large tmpfs, orphaned System V segments, and memfd buffers.
func Shmem(parts []sysmem.ShmemPart, shm []procfs.ShmSegment, selfUID int) []Suggestion {
	segs := map[int]procfs.ShmSegment{}
	for _, s := range shm {
		segs[s.ID] = s
	}
	var out []Suggestion
	for _, p := range parts {
		switch p.Kind {
		case "tmpfs":
			if p.Path == "" || p.Bytes < 16<<20 {
				continue
			}
			words := []string{"du", "-xah", p.Path}
			prefix := ""
			if otherUsersDir(p.Path, selfUID) {
				prefix = "sudo "
			}
			out = append(out, Suggestion{
				Title:  "See what fills " + p.Path,
				Cmd:    prefix + cmd(words...) + " 2>/dev/null | sort -h | tail -20",
				Effect: fmt.Sprintf("lists the largest of %s of files; deleting them frees that memory", pressure.Bytes(p.Bytes)),
				Caveat: "Files on tmpfs live in RAM (or swap) until deleted. A file still open is freed only when its program closes it; files under /dev/shm and /run/user usually belong to running apps, so check before deleting.",
			})
		case "sysv":
			for i, id := range p.SegmentIDs {
				if i == 3 {
					break
				}
				s := segs[id]
				c := cmd("ipcrm", "-m", fmt.Sprint(id))
				if s.UID != selfUID && selfUID != 0 {
					c = "sudo " + c
				}
				out = append(out, Suggestion{
					Title:  fmt.Sprintf("Remove orphaned shared-memory segment %d", id),
					Cmd:    c,
					Effect: "frees " + pressure.Bytes(s.RSS),
					Caveat: fmt.Sprintf("No process has it attached; it was created by pid %d. A program that crashed may expect to reattach it on restart (databases do), so make sure its owner is gone for good.", s.CPID),
				})
			}
		case "other":
			if p.Bytes < 256<<20 {
				continue
			}
			out = append(out, Suggestion{
				Title:  "Find processes holding memfd buffers",
				Cmd:    "sudo lsof -n 2>/dev/null | grep 'memfd:' | sort -k7 -n | tail -20",
				Effect: fmt.Sprintf("helps place %s of shared memory that isn't on a visible tmpfs", pressure.Bytes(p.Bytes)),
				Caveat: "The SIZE column is the buffer size; the memory goes away when every holder closes it, usually by exiting. GPU buffers don't show here: as root, look at /sys/kernel/debug/dri/*/gem_names or your driver's equivalent.",
			})
		}
	}
	return out
}

// otherUsersDir reports a /run/user/<uid> path of another user.
func otherUsersDir(path string, selfUID int) bool {
	rest, ok := strings.CutPrefix(path, "/run/user/")
	if !ok || selfUID == 0 {
		return false
	}
	uid, _, _ := strings.Cut(rest, "/")
	return uid != fmt.Sprint(selfUID)
}
