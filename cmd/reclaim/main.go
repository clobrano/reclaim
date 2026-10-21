// Command reclaim shows where memory goes, in groups developers recognize,
// and estimates honestly how much each action would free.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clobrano/reclaim/internal/action"
	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/clipboard"
	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/group"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/resolve"
	"github.com/clobrano/reclaim/internal/sample"
	"github.com/clobrano/reclaim/internal/suggest"
	"github.com/clobrano/reclaim/internal/sysmem"
	"github.com/clobrano/reclaim/internal/term"
	"github.com/clobrano/reclaim/internal/ui"
)

var version = "dev"

func main() {
	// The privileged helper is invoked by reclaim itself through sudo.
	if len(os.Args) > 1 && os.Args[1] == action.HelperFlag {
		os.Exit(action.RunHelper(os.Args[2:], os.Stdout))
	}
	os.Exit(run())
}

func run() int {
	var (
		configPath = flag.String("config", config.DefaultPath(), "config file")
		viewName   = flag.String("view", "apps", "initial view: apps, containers or tree")
		dump       = flag.Bool("dump", false, "print one snapshot as JSON and exit")
		interval   = flag.Duration("interval", 0, "refresh interval (default from config, 2s)")
		noNames    = flag.Bool("no-resolve", false, "don't query podman, docker or kubectl for names")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: reclaim [flags]\n\nShows where memory goes and what stopping each group would free.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Println("reclaim", version)
		return 0
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		return 2
	}
	if *interval > 0 {
		cfg.Interval = *interval
	}
	view, err := group.ParseView(*viewName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		return 2
	}
	var names group.Names
	var refresh func()
	if !*noNames {
		r := resolve.New()
		names, refresh = r, r.Refresh
	}
	s := sample.New()

	if *dump {
		if refresh != nil {
			refresh()
		}
		return dumpJSON(s, view, names)
	}

	if !term.IsTerminal(os.Stdin) || !term.IsTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "reclaim: not a terminal (use --dump for JSON output)")
		return 2
	}
	if os.Getuid() == 0 && !confirmRoot() {
		return 1
	}
	reg, err := action.LoadRegistry(filepath.Join(config.StateDir(), "frozen.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim: frozen list:", err)
	}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	m := ui.New(ui.Deps{
		Sample:     s.Sample,
		Names:      names,
		Proc:       procfs.Default,
		Cgroup:     cgroupfs.Default,
		Config:     cfg,
		Registry:   reg,
		Exe:        exe,
		Clip:       clipboard.Env{Tmux: os.Getenv("TMUX") != "", Screen: os.Getenv("STY") != ""},
		AfterDelay: time.Second,
	}, view)
	t, err := term.Open(os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		return 1
	}
	defer t.Close()
	ui.Run(t, m, cfg.Interval, refresh)
	return 0
}

func confirmRoot() bool {
	fmt.Fprint(os.Stderr, "reclaim is meant to run as your user: it asks through sudo only when an action needs it.\n"+
		"Running it as root lets every action reach every process. Continue? [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

type dumpGroup struct {
	*model.Group
	Estimate model.Estimate `json:"estimate"`
	Children []dumpGroup    `json:"children,omitempty"`
}

func wrapGroups(gs []*model.Group) []dumpGroup {
	out := make([]dumpGroup, 0, len(gs))
	for _, g := range gs {
		out = append(out, dumpGroup{Group: g, Estimate: model.EstimateOf(g.Mem), Children: wrapGroups(g.Children)})
	}
	return out
}

func dumpJSON(s *sample.Sampler, view group.View, names group.Names) int {
	snap, err := s.Sample()
	if err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		return 1
	}
	groups := group.Build(view, snap, names)
	group.Enrich(groups, snap, s.Cgroup)
	out := map[string]any{
		"time":      snap.Time,
		"view":      view.String(),
		"summary":   sysmem.Summarize(snap.Meminfo),
		"breakdown": sysmem.Breakdown(snap.Meminfo, snap.Zram),
		"psi":       snap.PSI,
		"zram":      snap.Zram,
		"warnings":  snap.Warnings,
		"groups":    wrapGroups(groups),
		"kernel":    suggest.Kernel(snap.Meminfo, snap.Zram),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "reclaim:", err)
		return 1
	}
	return 0
}
