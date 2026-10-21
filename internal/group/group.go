// Package group turns a snapshot into the three views reclaim shows: apps and
// systemd scopes, containers/pods/VMs, and the process tree.
package group

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/detect"
	"github.com/clobrano/reclaim/internal/model"
)

// View selects a grouping.
type View int

const (
	ViewApps View = iota
	ViewContainers
	ViewTree
	viewCount
)

func (v View) String() string {
	switch v {
	case ViewApps:
		return "apps"
	case ViewContainers:
		return "containers"
	case ViewTree:
		return "tree"
	}
	return "?"
}

// Next cycles to the following view.
func (v View) Next() View { return (v + 1) % viewCount }

// ParseView parses a view name.
func ParseView(s string) (View, error) {
	for v := View(0); v < viewCount; v++ {
		if v.String() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("unknown view %q (apps, containers, tree)", s)
}

// Names resolves container IDs and pod UIDs to names. Implementations may
// return false when they don't know; the views then show short IDs.
type Names interface {
	Container(runtime, id string) (name string, labels map[string]string, ok bool)
	Pod(uid string) (*model.Pod, bool)
}

// Build groups the snapshot according to the view. names may be nil.
func Build(v View, snap *model.Snapshot, names Names) []*model.Group {
	if !snap.Unified && v != ViewTree {
		v = ViewTree
	}
	var groups []*model.Group
	switch v {
	case ViewApps:
		groups = apps(procList(snap))
	case ViewContainers:
		groups = containers(snap, names)
	default:
		groups = tree(snap)
	}
	for _, g := range groups {
		finalize(g)
	}
	return groups
}

func procList(snap *model.Snapshot) []*model.Process {
	out := make([]*model.Process, 0, len(snap.Procs))
	for _, p := range snap.Procs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// finalize sums memory and PIDs bottom-up. Groups that already list Procs
// keep them; parents without their own list take the union of children.
func finalize(g *model.Group) {
	for _, c := range g.Children {
		finalize(c)
	}
	if g.Procs == nil {
		seen := map[int]bool{}
		for _, c := range g.Children {
			for _, p := range c.Procs {
				if !seen[p.PID] {
					seen[p.PID] = true
					g.Procs = append(g.Procs, p)
				}
			}
		}
	}
	sort.Slice(g.Procs, func(i, j int) bool { return g.Procs[i].PID < g.Procs[j].PID })
	g.Mem = model.Mem{}
	g.PIDs = g.PIDs[:0]
	for _, p := range g.Procs {
		g.Mem.Add(p.Mem)
		g.PIDs = append(g.PIDs, p.PID)
	}
}

// processChildren lists each process of a multi-process group as a child.
func processChildren(parentID string, procs []*model.Process) []*model.Group {
	if len(procs) < 2 {
		return nil
	}
	out := make([]*model.Group, 0, len(procs))
	for _, p := range procs {
		out = append(out, processGroup(parentID, p))
	}
	return out
}

func processGroup(parentID string, p *model.Process) *model.Group {
	return &model.Group{
		ID:     fmt.Sprintf("%s/pid:%d:%d", parentID, p.PID, p.StartTime),
		Name:   processName(p),
		Kind:   model.KindProcess,
		Detail: fmt.Sprintf("pid %d", p.PID),
		Procs:  []*model.Process{p},
	}
}

// processName is the comm, or the script name for interpreters.
func processName(p *model.Process) string {
	name := p.Comm
	if len(p.Cmdline) > 1 {
		switch strings.TrimRight(path.Base(p.Cmdline[0]), "0123456789.") {
		case "python", "node", "ruby", "perl", "java", "bash", "sh":
			for _, a := range p.Cmdline[1:] {
				if a == "-c" || strings.ContainsAny(a, " \t") {
					break // inline code, not a script name
				}
				if !strings.HasPrefix(a, "-") {
					return name + " " + path.Base(a)
				}
			}
		}
	}
	return name
}

// apps groups processes by their outermost systemd unit, or by their
// cgroup when they are not in a unit.
func apps(procs []*model.Process) []*model.Group {
	byKey := map[string]*model.Group{}
	var order []string
	cache := map[string]detect.Info{}
	for _, p := range procs {
		info, ok := cache[p.Cgroup]
		if !ok {
			info = detect.Classify(p.Cgroup)
			cache[p.Cgroup] = info
		}
		key := info.UnitPath
		if key == "" {
			key = p.Cgroup
		}
		if key == "" {
			key = "/"
		}
		g, ok := byKey[key]
		if !ok {
			g = appGroup(key, info)
			byKey[key] = g
			order = append(order, key)
		}
		g.Procs = append(g.Procs, p)
	}
	out := make([]*model.Group, 0, len(order))
	for _, k := range order {
		g := byKey[k]
		g.Children = processChildren(g.ID, g.Procs)
		if g.Name == "" && len(g.Procs) > 0 {
			g.Name = g.Procs[0].Comm
		}
		out = append(out, g)
	}
	return out
}

func appGroup(key string, info detect.Info) *model.Group {
	g := &model.Group{ID: "cg:" + key, Cgroup: key, Detail: key}
	switch {
	case info.Unit != "":
		g.Unit = info.Unit
		g.UserUnit = info.UserUnit
		g.Name = detect.AppName(info.Unit)
		switch {
		case strings.HasPrefix(info.Unit, "app-"):
			g.Kind = model.KindApp
		case strings.HasPrefix(info.Unit, "session-"):
			g.Kind = model.KindSession
		case strings.HasSuffix(info.Unit, ".service"):
			g.Kind = model.KindService
		default:
			g.Kind = model.KindScope
		}
	case key == "/":
		g.Kind = model.KindScope
		g.Name = "(root cgroup)"
	default:
		g.Kind = model.KindScope
		g.Name = detect.Unescape(path.Base(key))
	}
	return g
}

// containers builds clusters → nodes → pods → containers, standalone
// containers, VMs, and a Host group holding everything else as apps.
func containers(snap *model.Snapshot, names Names) []*model.Group {
	type node struct {
		g       *model.Group
		pods    map[string]*model.Group
		inner   map[string]*model.Group
		system  *model.Group
		hasPods bool
	}
	ctrs := map[string]*node{}
	var ctrOrder []string
	vms := map[string]*model.Group{}
	var vmOrder []string
	hostPods := map[string]*model.Group{}
	var hostPodOrder []string
	innerOf := map[string]*model.Group{}
	var host []*model.Process

	podGroup := func(parentID string, ref *detect.PodRef, ctx string) *model.Group {
		g := &model.Group{
			ID:     parentID + "/pod:" + ref.UID,
			Name:   "pod " + ref.UID[:8],
			Kind:   model.KindPod,
			Cgroup: ref.Path,
			Pod:    &model.Pod{UID: ref.UID},
		}
		if names != nil {
			if p, ok := names.Pod(ref.UID); ok {
				pp := *p
				if pp.Context == "" {
					pp.Context = ctx
				}
				g.Pod = &pp
				g.Name = p.Namespace + "/" + p.Name
			}
		}
		return g
	}
	innerGroup := func(parentID string, ref *detect.Ref) *model.Group {
		c := &model.Container{Runtime: ref.Runtime, ID: ref.ID, Rootful: ref.Rootful}
		return &model.Group{
			ID:        parentID + "/ctr:" + ref.ID,
			Name:      "container " + c.Short(),
			Kind:      model.KindContainer,
			Cgroup:    ref.Path,
			Container: c,
		}
	}

	for _, p := range procList(snap) {
		info := detect.Classify(p.Cgroup)
		switch {
		case info.Container != nil:
			ref := info.Container
			n, ok := ctrs[ref.ID]
			if !ok {
				c := &model.Container{Runtime: ref.Runtime, ID: ref.ID, Rootful: ref.Rootful}
				if names != nil {
					c.Name, c.Labels, _ = names.Container(ref.Runtime, ref.ID)
				}
				n = &node{
					g: &model.Group{
						ID:        "ctr:" + ref.ID,
						Name:      c.Short(),
						Kind:      model.KindContainer,
						Detail:    ref.Runtime,
						Container: c,
					},
					pods:  map[string]*model.Group{},
					inner: map[string]*model.Group{},
				}
				ctrs[ref.ID] = n
				ctrOrder = append(ctrOrder, ref.ID)
			}
			// conmon scopes share the ID but live outside the container
			// scope; the cgroup is the container scope proper.
			if !strings.Contains(ref.Path, "conmon") {
				n.g.Cgroup = ref.Path
			}
			n.g.Procs = append(n.g.Procs, p)
			if info.Pod == nil {
				if n.system == nil {
					n.system = &model.Group{ID: n.g.ID + "/system", Name: "node services", Kind: model.KindContainer}
				}
				n.system.Procs = append(n.system.Procs, p)
				continue
			}
			n.hasPods = true
			pod, ok := n.pods[info.Pod.UID]
			if !ok {
				pod = podGroup(n.g.ID, info.Pod, "")
				n.pods[info.Pod.UID] = pod
				n.g.Children = append(n.g.Children, pod)
			}
			pod.Procs = append(pod.Procs, p)
			if info.InnerContainer != nil {
				ic, ok := n.inner[info.InnerContainer.ID]
				if !ok {
					ic = innerGroup(pod.ID, info.InnerContainer)
					n.inner[info.InnerContainer.ID] = ic
					pod.Children = append(pod.Children, ic)
				}
				ic.Procs = append(ic.Procs, p)
			}
		case info.Pod != nil:
			pod, ok := hostPods[info.Pod.UID]
			if !ok {
				pod = podGroup("host", info.Pod, "")
				hostPods[info.Pod.UID] = pod
				hostPodOrder = append(hostPodOrder, info.Pod.UID)
			}
			pod.Procs = append(pod.Procs, p)
			if info.InnerContainer != nil {
				ic, ok := innerOf[info.InnerContainer.ID]
				if !ok {
					ic = innerGroup(pod.ID, info.InnerContainer)
					innerOf[info.InnerContainer.ID] = ic
					pod.Children = append(pod.Children, ic)
				}
				ic.Procs = append(ic.Procs, p)
			}
		case info.VM != nil:
			g, ok := vms[info.VM.Path]
			if !ok {
				g = &model.Group{
					ID:     "vm:" + info.VM.Path,
					Name:   info.VM.Name,
					Kind:   model.KindVM,
					Detail: info.VM.URI,
					Cgroup: info.VM.Path,
					VM:     &model.VM{Name: info.VM.Name, URI: info.VM.URI},
				}
				vms[info.VM.Path] = g
				vmOrder = append(vmOrder, info.VM.Path)
			}
			g.Procs = append(g.Procs, p)
		default:
			host = append(host, p)
		}
	}

	var out []*model.Group
	clusters := map[string]*model.Group{}
	for _, id := range ctrOrder {
		n := ctrs[id]
		if !n.hasPods {
			n.g.Children = processChildren(n.g.ID, n.g.Procs)
			out = append(out, n.g)
			continue
		}
		n.g.Kind = model.KindNode
		if n.system != nil {
			n.g.Children = append([]*model.Group{n.system}, n.g.Children...)
		}
		cluster := KindCluster(n.g.Container)
		if cluster == "" {
			out = append(out, n.g)
			continue
		}
		n.g.Cluster = cluster
		for _, pod := range n.pods {
			if pod.Pod.Context == "" {
				pod.Pod.Context = "kind-" + cluster
			}
		}
		cg, ok := clusters[cluster]
		if !ok {
			cg = &model.Group{
				ID:      "kind:" + cluster,
				Name:    "kind: " + cluster,
				Kind:    model.KindCluster,
				Cluster: cluster,
				Detail:  n.g.Container.Runtime,
			}
			clusters[cluster] = cg
			out = append(out, cg)
		}
		cg.Children = append(cg.Children, n.g)
	}
	for _, cg := range clusters {
		pods := 0
		for _, n := range cg.Children {
			pods += len(n.Children)
			if len(n.Children) > 0 && n.Children[0].Name == "node services" {
				pods--
			}
		}
		cg.Name = fmt.Sprintf("kind: %s (%d nodes, %d pods)", cg.Cluster, len(cg.Children), pods)
	}
	for _, uid := range hostPodOrder {
		out = append(out, hostPods[uid])
	}
	for _, p := range vmOrder {
		out = append(out, vms[p])
	}
	if len(host) > 0 {
		h := &model.Group{ID: "host", Name: "Host (not containerized)", Kind: model.KindHost}
		h.Children = apps(host)
		for _, c := range h.Children {
			prefixIDs(c, "host/")
		}
		out = append(out, h)
	}
	return out
}

func prefixIDs(g *model.Group, prefix string) {
	g.Walk(func(x *model.Group) { x.ID = prefix + x.ID })
}

// KindCluster returns the kind cluster a node container belongs to, from its
// label or, failing that, from kind's node naming.
func KindCluster(c *model.Container) string {
	if c == nil {
		return ""
	}
	if v := c.Labels["io.x-k8s.kind.cluster"]; v != "" {
		return v
	}
	for _, suffix := range []string{"-control-plane", "-worker", "-external-load-balancer"} {
		if i := strings.LastIndex(c.Name, suffix); i > 0 {
			rest := c.Name[i+len(suffix):]
			if strings.Trim(rest, "0123456789") == "" {
				return c.Name[:i]
			}
		}
	}
	return ""
}

// tree groups by process subtree. Roots are children of PID 1, of a systemd
// user manager, or of processes not visible in the snapshot.
func tree(snap *model.Snapshot) []*model.Group {
	children := map[int][]*model.Process{}
	procs := procList(snap)
	for _, p := range procs {
		children[p.PPID] = append(children[p.PPID], p)
	}
	isAnchor := func(pid int) bool {
		if pid <= 1 {
			return true
		}
		parent, ok := snap.Procs[pid]
		return !ok || userManager(parent)
	}
	var build func(p *model.Process, parentID string) *model.Group
	build = func(p *model.Process, parentID string) *model.Group {
		id := fmt.Sprintf("%s/pid:%d:%d", parentID, p.PID, p.StartTime)
		g := &model.Group{ID: id, Name: processName(p), Kind: model.KindTree, Detail: fmt.Sprintf("pid %d", p.PID)}
		g.Procs = []*model.Process{p}
		for _, c := range children[p.PID] {
			child := build(c, id)
			g.Children = append(g.Children, child)
			g.Procs = append(g.Procs, child.Procs...)
		}
		if len(g.Children) == 0 {
			g.Kind = model.KindProcess
		} else {
			g.Detail = fmt.Sprintf("pid %d + %d", p.PID, len(g.Procs)-1)
		}
		return g
	}
	var out []*model.Group
	for _, p := range procs {
		if p.PID == 1 {
			// init itself is a group of one; its children are roots.
			out = append(out, &model.Group{ID: "tree:1", Name: processName(p), Kind: model.KindProcess, Detail: "pid 1", Procs: []*model.Process{p}})
			continue
		}
		if isAnchor(p.PPID) && !userManager(p) {
			out = append(out, build(p, "tree"))
		}
	}
	// systemd --user managers are anchors; list them as single processes.
	for _, p := range procs {
		if userManager(p) {
			out = append(out, &model.Group{ID: fmt.Sprintf("tree/pid:%d:%d", p.PID, p.StartTime), Name: "systemd --user", Kind: model.KindProcess, Detail: fmt.Sprintf("pid %d", p.PID), Procs: []*model.Process{p}})
		}
	}
	return out
}

// userManager reports whether p is a systemd --user instance.
func userManager(p *model.Process) bool {
	return p.PID != 1 && p.Comm == "systemd" && strings.Contains(p.Cgroup, "/user@")
}

// Enrich attaches cgroup memory and PSI to groups. A group without its own
// cgroup whose processes all share one cgroup inherits that cgroup's PSI,
// marked by PSIShared.
func Enrich(groups []*model.Group, snap *model.Snapshot, cg cgroupfs.FS) {
	if !snap.Unified {
		return
	}
	mem := func(p string) (cgroupfs.Mem, bool) {
		if m, ok := snap.CgMem[p]; ok {
			return m, true
		}
		m, err := cg.ReadMem(p)
		if err != nil {
			return m, false
		}
		snap.CgMem[p] = m
		return m, true
	}
	psi := func(p string) bool {
		if _, ok := snap.CgPSI[p]; ok {
			return true
		}
		v, err := cg.ReadPSI(p)
		if err != nil {
			return false
		}
		snap.CgPSI[p] = v
		return true
	}
	for _, top := range groups {
		top.Walk(func(g *model.Group) {
			p := g.Cgroup
			if p == "" {
				p = sharedCgroup(g.Procs)
				if p == "" {
					return
				}
				if psi(p) {
					v := snap.CgPSI[p]
					g.PSI = &v
					g.PSIShared = true
				}
				return
			}
			if p != "/" {
				if m, ok := mem(p); ok {
					g.CgMem = &m
				}
			}
			if psi(p) {
				v := snap.CgPSI[p]
				g.PSI = &v
			}
		})
	}
}

func sharedCgroup(procs []*model.Process) string {
	if len(procs) == 0 {
		return ""
	}
	cg := procs[0].Cgroup
	for _, p := range procs[1:] {
		if p.Cgroup != cg {
			return ""
		}
	}
	return cg
}

// Find returns the group with the given ID.
func Find(groups []*model.Group, id string) *model.Group {
	var found *model.Group
	for _, g := range groups {
		g.Walk(func(x *model.Group) {
			if found == nil && x.ID == id {
				found = x
			}
		})
	}
	return found
}
