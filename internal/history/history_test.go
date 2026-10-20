package history

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func TestGrowthAndPSI(t *testing.T) {
	h := New(30 * time.Minute)
	for i := 0; i <= 10; i++ {
		h.Record("g", Point{T: t0.Add(time.Duration(i) * 10 * time.Second), Footprint: uint64(1000 + 100*i), PSI: uint64(50 * i), HasPSI: true})
	}
	d, span, ok := h.Growth("g", time.Minute)
	if !ok || d != 600 || span != time.Minute {
		t.Fatalf("growth %d %v %v", d, span, ok)
	}
	p, ok := h.PSIDelta("g", time.Minute)
	if !ok || p != 300 {
		t.Fatalf("psi %d %v", p, ok)
	}
	if _, _, ok := h.Growth("missing", time.Minute); ok {
		t.Fatal("missing series")
	}
}

func TestRecordKeepsBounded(t *testing.T) {
	h := New(time.Minute)
	for i := 0; i < 100; i++ {
		h.Record("g", Point{T: t0.Add(time.Duration(i) * 10 * time.Second)})
	}
	if n := len(h.Series("g")); n > 8 {
		t.Fatalf("kept %d points", n)
	}
	h.Prune(t0.Add(time.Hour))
	if len(h.Series("g")) != 0 {
		t.Fatal("prune")
	}
}

func TestTrend(t *testing.T) {
	h := New(time.Hour)
	for i := 0; i <= 20; i++ {
		h.Record("leak", Point{T: t0.Add(time.Duration(i) * time.Minute), Footprint: uint64(1<<30 + i*(60<<20))})
		noise := uint64(0)
		if i%2 == 0 {
			noise = 300 << 20
		}
		h.Record("flat", Point{T: t0.Add(time.Duration(i) * time.Minute), Footprint: 1<<30 + noise})
	}
	tr, ok := h.Trend("leak", time.Hour)
	if !ok || tr.R2 < 0.99 || tr.Slope <= 0 || tr.Delta != 1200<<20 {
		t.Fatalf("leak %+v", tr)
	}
	if !tr.SteadyGrowth(10*time.Minute, 256<<20) {
		t.Fatal("expected steady growth")
	}
	fl, _ := h.Trend("flat", time.Hour)
	if fl.SteadyGrowth(10*time.Minute, 256<<20) {
		t.Fatalf("flat flagged: %+v", fl)
	}
}
