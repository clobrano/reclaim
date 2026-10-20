package pressure

import (
	"testing"
	"time"

	"github.com/clobrano/reclaim/internal/history"
	"github.com/clobrano/reclaim/internal/model"
)

var t0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func record(h *history.History, id string, step int, footprint, psi uint64) {
	h.Record(id, history.Point{T: t0.Add(time.Duration(step) * 10 * time.Second), Footprint: footprint, PSI: psi, HasPSI: true})
}

func TestCulpritNeedsTwoEvaluations(t *testing.T) {
	h := history.New(time.Hour)
	groups := []*model.Group{{ID: "lsp"}, {ID: "browser"}, {ID: "victim"}}
	tr := &Tracker{Cfg: DefaultConfig()}
	var res Result
	for i := 0; i <= 6; i++ {
		record(h, "lsp", i, uint64(1<<30+i*(150<<20)), uint64(i*1000))
		record(h, "browser", i, 2<<30, uint64(i*200))
		record(h, "victim", i, 1<<30, uint64(i*5000)) // stalls a lot, doesn't grow
		res = tr.Evaluate(groups, h, 25, true)
		if i == 1 && res.Culprit != "" {
			t.Fatal("flagged after one evaluation")
		}
	}
	if res.Culprit != "lsp" {
		t.Fatalf("culprit %q scores %+v", res.Culprit, res.Scores)
	}
	s := res.Scores["lsp"]
	if s.GrowthShare != 1 || s.Growth != 6*(150<<20) {
		t.Fatalf("%+v", s)
	}
	if s.Evidence() != "grew +900 M in 1m0s, 16% of stall time" {
		t.Fatal(s.Evidence())
	}
}

func TestNoCulpritWithoutPressure(t *testing.T) {
	h := history.New(time.Hour)
	groups := []*model.Group{{ID: "a"}}
	tr := &Tracker{Cfg: DefaultConfig()}
	for i := 0; i < 5; i++ {
		record(h, "a", i, uint64(i<<30), 0)
		if res := tr.Evaluate(groups, h, 2, true); res.Culprit != "" || res.Pressure {
			t.Fatal("flagged without pressure")
		}
	}
	if res := tr.Evaluate(groups, h, 50, false); res.Pressure {
		t.Fatal("pressure without PSI")
	}
}

func TestSharedPSIExcluded(t *testing.T) {
	h := history.New(time.Hour)
	groups := []*model.Group{{ID: "a", PSIShared: true}, {ID: "b"}}
	for i := 0; i < 3; i++ {
		record(h, "a", i, 0, uint64(i*100))
		record(h, "b", i, 0, uint64(i*100))
	}
	res := (&Tracker{Cfg: DefaultConfig()}).Evaluate(groups, h, 0, true)
	if res.Scores["a"].PSIShare != 0 || res.Scores["b"].PSIShare != 1 {
		t.Fatalf("%+v", res.Scores)
	}
}

func TestBytes(t *testing.T) {
	cases := map[uint64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 K", 3 << 30: "3.0 G", 200 << 20: "200 M"}
	for in, want := range cases {
		if got := Bytes(in); got != want {
			t.Errorf("Bytes(%d) = %q want %q", in, got, want)
		}
	}
	if SignedBytes(-(1 << 20)) != "-1.0 M" {
		t.Fatal(SignedBytes(-(1 << 20)))
	}
}
