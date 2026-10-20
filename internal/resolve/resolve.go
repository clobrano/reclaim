// Package resolve maps container IDs and pod UIDs to names with read-only
// queries to the tools the user already has (podman, docker, kubectl).
// Every query is optional: when one fails, views show short IDs.
package resolve

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/clobrano/reclaim/internal/model"
)

// Runner runs a command and returns its stdout. Tests replace it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, name, args...).Output()
}

// Resolver caches names; Refresh updates them.
type Resolver struct {
	Run     Runner
	Timeout time.Duration

	mu         sync.RWMutex
	containers map[string]containerInfo // by full ID
	pods       map[string]model.Pod     // by UID
}

type containerInfo struct {
	name   string
	labels map[string]string
}

// New returns a resolver that queries the real tools.
func New() *Resolver {
	return &Resolver{Run: execRunner, Timeout: 3 * time.Second}
}

// Container implements group.Names.
func (r *Resolver) Container(runtime, id string) (string, map[string]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.containers[id]
	return c.name, c.labels, ok
}

// Pod implements group.Names.
func (r *Resolver) Pod(uid string) (*model.Pod, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.pods[uid]
	if !ok {
		return nil, false
	}
	return &p, true
}

// Refresh queries every available tool. It is safe to call concurrently
// with lookups.
func (r *Resolver) Refresh() {
	containers := map[string]containerInfo{}
	r.podman(containers)
	r.docker(containers)
	pods := map[string]model.Pod{}
	r.kube(pods)
	r.mu.Lock()
	r.containers, r.pods = containers, pods
	r.mu.Unlock()
}

func (r *Resolver) run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	return r.Run(ctx, name, args...)
}

func (r *Resolver) podman(out map[string]containerInfo) {
	data, err := r.run("podman", "ps", "--no-trunc", "--format", "json")
	if err != nil {
		return
	}
	var list []struct {
		ID     string            `json:"Id"`
		Names  []string          `json:"Names"`
		Labels map[string]string `json:"Labels"`
	}
	if json.Unmarshal(data, &list) != nil {
		return
	}
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}
		out[c.ID] = containerInfo{name: name, labels: c.Labels}
	}
}

func (r *Resolver) docker(out map[string]containerInfo) {
	data, err := r.run("docker", "ps", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		var c struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Labels string `json:"Labels"`
		}
		if json.Unmarshal([]byte(line), &c) != nil || c.ID == "" {
			continue
		}
		labels := map[string]string{}
		for _, kv := range strings.Split(c.Labels, ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				labels[k] = v
			}
		}
		out[c.ID] = containerInfo{name: strings.Split(c.Names, ",")[0], labels: labels}
	}
}

func (r *Resolver) kube(out map[string]model.Pod) {
	data, err := r.run("kubectl", "config", "get-contexts", "-o", "name")
	if err != nil {
		return
	}
	for _, ctx := range strings.Fields(string(data)) {
		// Only kind contexts: querying arbitrary remote clusters would be
		// slow and is outside reclaim's scope.
		if !strings.HasPrefix(ctx, "kind-") {
			continue
		}
		pods, err := r.run("kubectl", "--context", ctx, "get", "pods", "-A", "-o", "json")
		if err != nil {
			continue
		}
		ParsePods(pods, ctx, out)
	}
}

// ParsePods reads `kubectl get pods -o json` output into out, keyed by UID.
func ParsePods(data []byte, context string, out map[string]model.Pod) {
	var list struct {
		Items []struct {
			Metadata struct {
				UID             string            `json:"uid"`
				Name            string            `json:"name"`
				Namespace       string            `json:"namespace"`
				Labels          map[string]string `json:"labels"`
				OwnerReferences []struct {
					Kind string `json:"kind"`
					Name string `json:"name"`
				} `json:"ownerReferences"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &list) != nil {
		return
	}
	for _, it := range list.Items {
		m := it.Metadata
		p := model.Pod{UID: m.UID, Name: m.Name, Namespace: m.Namespace, Context: context}
		if len(m.OwnerReferences) > 0 {
			p.OwnerKind, p.OwnerName = m.OwnerReferences[0].Kind, m.OwnerReferences[0].Name
			// A ReplicaSet created by a Deployment is named
			// <deployment>-<pod-template-hash>.
			if hash := m.Labels["pod-template-hash"]; p.OwnerKind == "ReplicaSet" && hash != "" {
				if dep, ok := strings.CutSuffix(p.OwnerName, "-"+hash); ok {
					p.OwnerKind, p.OwnerName = "Deployment", dep
				}
			}
		}
		out[m.UID] = p
	}
}
