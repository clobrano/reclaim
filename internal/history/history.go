// Package history keeps per-group samples over the session, for growth and
// pressure deltas. Nothing is persisted across runs.
package history

import (
	"math"
	"time"
)

// Point is one sample of a group.
type Point struct {
	T         time.Time
	Footprint uint64 // USS + SwapPss
	PSI       uint64 // cumulative "some" stall time in µs
	HasPSI    bool
}

// History holds bounded series keyed by group ID.
type History struct {
	Keep   time.Duration
	series map[string][]Point
}

// New keeps samples for the given duration.
func New(keep time.Duration) *History {
	return &History{Keep: keep, series: map[string][]Point{}}
}

// Record appends a sample and drops samples older than Keep.
func (h *History) Record(id string, p Point) {
	s := append(h.series[id], p)
	cut := 0
	for cut < len(s)-1 && p.T.Sub(s[cut].T) > h.Keep {
		cut++
	}
	h.series[id] = s[cut:]
}

// Prune forgets groups that were not seen since before.
func (h *History) Prune(before time.Time) {
	for id, s := range h.series {
		if len(s) == 0 || s[len(s)-1].T.Before(before) {
			delete(h.series, id)
		}
	}
}

// Series returns the samples of a group, oldest first.
func (h *History) Series(id string) []Point { return h.series[id] }

// baseline returns the oldest point no older than window, and the newest.
func (h *History) baseline(id string, window time.Duration) (Point, Point, bool) {
	s := h.series[id]
	if len(s) < 2 {
		return Point{}, Point{}, false
	}
	last := s[len(s)-1]
	for _, p := range s {
		if last.T.Sub(p.T) <= window {
			return p, last, p.T.Before(last.T)
		}
	}
	return Point{}, Point{}, false
}

// Growth returns the footprint change over (at most) window, and the
// span actually covered.
func (h *History) Growth(id string, window time.Duration) (int64, time.Duration, bool) {
	first, last, ok := h.baseline(id, window)
	if !ok {
		return 0, 0, false
	}
	return int64(last.Footprint) - int64(first.Footprint), last.T.Sub(first.T), true
}

// PSIDelta returns the stall time accumulated over (at most) window.
func (h *History) PSIDelta(id string, window time.Duration) (uint64, bool) {
	first, last, ok := h.baseline(id, window)
	if !ok || !first.HasPSI || !last.HasPSI || last.PSI < first.PSI {
		return 0, false
	}
	return last.PSI - first.PSI, true
}

// Trend fits a line to the footprint over the last window. It reports the
// slope in bytes per second and the fit's R².
type Trend struct {
	Slope float64
	R2    float64
	Span  time.Duration
	Delta int64
}

// Trend computes the linear trend over (at most) window. ok is false with
// fewer than three samples.
func (h *History) Trend(id string, window time.Duration) (Trend, bool) {
	s := h.series[id]
	if len(s) < 3 {
		return Trend{}, false
	}
	last := s[len(s)-1]
	start := 0
	for start < len(s) && last.T.Sub(s[start].T) > window {
		start++
	}
	s = s[start:]
	if len(s) < 3 {
		return Trend{}, false
	}
	t0 := s[0].T
	var n, sx, sy, sxx, sxy, syy float64
	for _, p := range s {
		x := p.T.Sub(t0).Seconds()
		y := float64(p.Footprint)
		n++
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
		syy += y * y
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return Trend{}, false
	}
	slope := (n*sxy - sx*sy) / den
	vy := n*syy - sy*sy
	r2 := 1.0
	if vy > 0 {
		r := (n*sxy - sx*sy) / math.Sqrt(den*vy)
		r2 = r * r
	}
	return Trend{
		Slope: slope,
		R2:    r2,
		Span:  last.T.Sub(t0),
		Delta: int64(last.Footprint) - int64(s[0].Footprint),
	}, true
}

// SteadyGrowth reports a trend worth annotating: a good linear fit with
// positive slope over at least minSpan and growth above minDelta.
func (t Trend) SteadyGrowth(minSpan time.Duration, minDelta int64) bool {
	return t.Span >= minSpan && t.Slope > 0 && t.R2 > 0.8 && t.Delta > minDelta
}
