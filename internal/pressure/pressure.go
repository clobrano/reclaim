// Package pressure finds the group driving memory pressure.
//
// PSI tells who is stalled, which is not necessarily who causes the stall.
// The score therefore combines a group's share of stall time with its share
// of recent growth, and the evidence is always shown next to the flag.
package pressure

import (
	"fmt"
	"time"

	"github.com/clobrano/reclaim/internal/history"
	"github.com/clobrano/reclaim/internal/model"
)

// Config tunes culprit detection.
type Config struct {
	Window       time.Duration // default 60s
	PSIWeight    float64       // default 0.4
	GrowthWeight float64       // default 0.6
	Threshold    float64       // system "some avg10" in percent, default 10
	MinScore     float64       // default 0.3
}

// DefaultConfig returns the defaults from the plan.
func DefaultConfig() Config {
	return Config{Window: 60 * time.Second, PSIWeight: 0.4, GrowthWeight: 0.6, Threshold: 10, MinScore: 0.3}
}

// Score is one group's contribution.
type Score struct {
	PSIShare    float64
	GrowthShare float64
	Score       float64
	Growth      int64
	Span        time.Duration
}

// Evidence describes a score in plain words.
func (s Score) Evidence() string {
	out := fmt.Sprintf("grew %s in %s", SignedBytes(s.Growth), s.Span.Round(time.Second))
	if s.PSIShare > 0 {
		out += fmt.Sprintf(", %.0f%% of stall time", s.PSIShare*100)
	}
	return out
}

// Tracker flags a culprit only when the same group leads two evaluations in
// a row while the system is under pressure, to avoid flapping.
type Tracker struct {
	Cfg       Config
	candidate string
	streak    int
}

// Result is one evaluation.
type Result struct {
	Scores   map[string]Score
	Culprit  string // group ID, empty when none
	Pressure bool   // system pressure above threshold
}

// Evaluate scores the given groups (disjoint, typically the top level of
// the current view) using their recorded history. sysAvg10 is the system
// "some avg10"; hasPSI is false when PSI is unavailable.
func (t *Tracker) Evaluate(groups []*model.Group, h *history.History, sysAvg10 float64, hasPSI bool) Result {
	res := Result{Scores: map[string]Score{}}
	var growthSum float64
	var psiSum float64
	type raw struct {
		growth int64
		span   time.Duration
		psi    uint64
	}
	raws := map[string]raw{}
	for _, g := range groups {
		var r raw
		if d, span, ok := h.Growth(g.ID, t.Cfg.Window); ok {
			r.growth, r.span = d, span
			if d > 0 {
				growthSum += float64(d)
			}
		}
		// Shared PSI would be counted once per group sharing it; only own
		// cgroups take part.
		if !g.PSIShared {
			if p, ok := h.PSIDelta(g.ID, t.Cfg.Window); ok {
				r.psi = p
				psiSum += float64(p)
			}
		}
		raws[g.ID] = r
	}
	best, bestScore := "", 0.0
	for id, r := range raws {
		var s Score
		s.Growth, s.Span = r.growth, r.span
		if growthSum > 0 && r.growth > 0 {
			s.GrowthShare = float64(r.growth) / growthSum
		}
		if psiSum > 0 {
			s.PSIShare = float64(r.psi) / psiSum
		}
		s.Score = t.Cfg.PSIWeight*s.PSIShare + t.Cfg.GrowthWeight*s.GrowthShare
		res.Scores[id] = s
		if s.Score > bestScore || (s.Score == bestScore && id < best) {
			best, bestScore = id, s.Score
		}
	}
	res.Pressure = hasPSI && sysAvg10 >= t.Cfg.Threshold
	if !res.Pressure || bestScore < t.Cfg.MinScore || res.Scores[best].Growth <= 0 {
		t.candidate, t.streak = "", 0
		return res
	}
	if best == t.candidate {
		t.streak++
	} else {
		t.candidate, t.streak = best, 1
	}
	if t.streak >= 2 {
		res.Culprit = best
	}
	return res
}

// SignedBytes formats a byte delta like "+1.2 GB".
func SignedBytes(d int64) string {
	sign := "+"
	if d < 0 {
		sign = "-"
		d = -d
	}
	return sign + Bytes(uint64(d))
}

// Bytes formats a size with binary units, short form.
func Bytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	v := float64(b) / float64(div)
	suffix := []string{"K", "M", "G", "T", "P"}[exp]
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, suffix)
	}
	return fmt.Sprintf("%.1f %s", v, suffix)
}
