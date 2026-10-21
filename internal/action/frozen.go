package action

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// FrozenEntry is a group reclaim froze. Entries are persisted so a frozen
// group is never forgotten if reclaim exits or crashes.
type FrozenEntry struct {
	GroupID string    `json:"group_id"`
	Name    string    `json:"name"`
	Method  string    `json:"method"` // "cgroup" or "SIGSTOP"
	Cgroup  string    `json:"cgroup,omitempty"`
	Targets []Target  `json:"targets"`
	Sudo    bool      `json:"sudo,omitempty"`
	At      time.Time `json:"at"`
	// Estimate is the private memory at freeze time, for display.
	Estimate uint64 `json:"estimate"`
}

// Registry is the persisted list of frozen groups.
type Registry struct {
	Path    string
	Entries []FrozenEntry
}

// LoadRegistry reads the registry; a missing file is an empty registry.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{Path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r.Entries); err != nil {
		return r, err
	}
	return r, nil
}

// Save writes the registry atomically.
func (r *Registry) Save() error {
	if r.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.Entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.Path)
}

// Add records a frozen group, replacing an entry for the same group.
func (r *Registry) Add(e FrozenEntry) {
	r.Remove(e.GroupID)
	r.Entries = append(r.Entries, e)
}

// Remove drops the entry for a group.
func (r *Registry) Remove(groupID string) {
	out := r.Entries[:0]
	for _, e := range r.Entries {
		if e.GroupID != groupID {
			out = append(out, e)
		}
	}
	r.Entries = out
}

// Reconcile drops entries that are no longer frozen: the cgroup was thawed
// or removed, or every stopped process exited or was continued elsewhere.
// It reports whether anything changed.
func (r *Registry) Reconcile(env Env) bool {
	out := r.Entries[:0]
	changed := false
	for _, e := range r.Entries {
		if e.Method == "cgroup" {
			if frozen, err := env.Cgroup.FreezeRequested(e.Cgroup); err == nil && frozen {
				out = append(out, e)
				continue
			}
			changed = true
			continue
		}
		var still []Target
		for _, t := range e.Targets {
			st, err := env.Proc.ReadStat(t.PID)
			if err == nil && st.StartTime == t.StartTime && (st.State == 'T' || st.State == 't') {
				still = append(still, t)
			}
		}
		if len(still) == 0 {
			changed = true
			continue
		}
		if len(still) != len(e.Targets) {
			changed = true
		}
		e.Targets = still
		out = append(out, e)
	}
	r.Entries = out
	return changed
}

// Find returns the entry for a group.
func (r *Registry) Find(groupID string) (FrozenEntry, bool) {
	for _, e := range r.Entries {
		if e.GroupID == groupID {
			return e, true
		}
	}
	return FrozenEntry{}, false
}
