// Package ui is reclaim's terminal interface. Model holds all state and is
// driven by keys and messages; App connects it to a real terminal.
package ui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/clobrano/reclaim/internal/action"
	"github.com/clobrano/reclaim/internal/cgroupfs"
	"github.com/clobrano/reclaim/internal/clipboard"
	"github.com/clobrano/reclaim/internal/config"
	"github.com/clobrano/reclaim/internal/group"
	"github.com/clobrano/reclaim/internal/history"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/pressure"
	"github.com/clobrano/reclaim/internal/procfs"
	"github.com/clobrano/reclaim/internal/protect"
	"github.com/clobrano/reclaim/internal/suggest"
	"github.com/clobrano/reclaim/internal/sysmem"
	"github.com/clobrano/reclaim/internal/term"
)

// Deps are the model's connections to the system.
type Deps struct {
	Sample   func() (*model.Snapshot, error)
	Names    group.Names
	Proc     procfs.FS
	Cgroup   cgroupfs.FS
	Config   config.Config
	Registry *action.Registry
	Exe      string // path of reclaim, for the sudo helper
	Clip     clipboard.Env
	// ExecuteAction and ThawEntry default to the action package; tests
	// replace them.
	ExecuteAction func(*action.Plan, action.Env) action.Result
	ThawEntry     func(action.FrozenEntry, action.Env) action.Result
	MemAvailable  func() uint64
	AfterDelay    time.Duration // wait before measuring what an action freed
}

// Cmd is a side effect the App runs for the model.
type Cmd struct {
	// Run executes in a goroutine; its result is passed back to Handle.
	Run func() any
	// Foreground runs with the terminal suspended (for sudo); its result
	// is passed back to Handle.
	Foreground func() any
	// Write sends raw bytes to the terminal (OSC 52).
	Write string
	Quit  bool
}

type mode int

const (
	modeList mode = iota
	modeConfirm
	modeSuggest
	modeFrozen
	modeSystem
	modeDetail
	modeHelp
	modeQuit
)

type sortKey int

const (
	sortUSS sortKey = iota
	sortPSS
	sortSwap
	sortGrowth
	sortPSI
	sortName
	sortCount
)

func (s sortKey) String() string {
	return [...]string{"uss", "pss", "swap", "growth", "psi", "name"}[s]
}

type row struct {
	g     *model.Group
	depth int
}

// Model is the UI state.
type Model struct {
	deps Deps

	snap     *model.Snapshot
	views    [3][]*model.Group
	view     group.View
	sort     sortKey
	expanded map[string]bool
	rows     []row
	selected string
	cursor   int
	offset   int

	hist      *history.History
	tracker   *pressure.Tracker
	culprit   pressure.Result
	culpritG  *model.Group
	protector *protect.Protector

	mode    mode
	status  string
	statusT time.Time
	busy    string

	// Dialog state.
	plan       *action.Plan
	planGroup  *model.Group
	override   string
	focusOK    bool
	suggs      []suggest.Suggestion
	suggTitle  string
	suggCursor int
	sysCursor  int
	frozenCur  int
	detail     *model.Group

	width, height int
	sampling      bool
}

// New creates a model.
func New(deps Deps, view group.View) *Model {
	if deps.ExecuteAction == nil {
		deps.ExecuteAction = action.Execute
	}
	if deps.ThawEntry == nil {
		deps.ThawEntry = action.Thaw
	}
	if deps.MemAvailable == nil {
		deps.MemAvailable = func() uint64 {
			m, err := deps.Proc.ReadMeminfo()
			if err != nil {
				return 0
			}
			return m["MemAvailable"]
		}
	}
	if deps.Registry == nil {
		deps.Registry = &action.Registry{}
	}
	cfg := deps.Config
	keep := max(cfg.GrowthWindow, cfg.GrowthMinSpan, cfg.CulpritWindow) + time.Minute
	m := &Model{
		deps:     deps,
		view:     view,
		expanded: map[string]bool{},
		hist:     history.New(keep),
		tracker: &pressure.Tracker{Cfg: pressure.Config{
			Window: cfg.CulpritWindow, PSIWeight: cfg.PSIWeight, GrowthWeight: cfg.GrowthWeight,
			Threshold: cfg.CulpritThreshold, MinScore: 0.3,
		}},
		width: 100, height: 30,
	}
	if n := len(deps.Registry.Entries); n > 0 {
		m.setStatus(fmt.Sprintf("%d groups are still frozen from an earlier session: press F to see them", n))
	}
	return m
}

func (m *Model) setStatus(s string) {
	m.status = s
	m.statusT = time.Now()
}

func (m *Model) env() action.Env {
	var mi procfs.Meminfo
	if m.snap != nil {
		mi = m.snap.Meminfo
	}
	return action.Env{
		Proc:      m.deps.Proc,
		Cgroup:    m.deps.Cgroup,
		Protector: m.protector,
		SelfPID:   os.Getpid(),
		SelfUID:   os.Getuid(),
		Grace:     m.deps.Config.Grace,
		Meminfo:   mi,
	}
}

// Init returns the first sampling command.
func (m *Model) Init() []Cmd { return []Cmd{m.sampleCmd()} }

// Tick is called on every refresh interval.
func (m *Model) Tick() []Cmd {
	if m.sampling {
		return nil
	}
	return []Cmd{m.sampleCmd()}
}

type msgSnapshot struct {
	snap  *model.Snapshot
	views [3][]*model.Group
	err   error
}

func (m *Model) sampleCmd() Cmd {
	m.sampling = true
	sample, names, cg := m.deps.Sample, m.deps.Names, m.deps.Cgroup
	return Cmd{Run: func() any {
		snap, err := sample()
		if err != nil {
			return msgSnapshot{err: err}
		}
		var views [3][]*model.Group
		for v := group.ViewApps; v <= group.ViewTree; v++ {
			views[v] = group.Build(v, snap, names)
			group.Enrich(views[v], snap, cg)
		}
		return msgSnapshot{snap: snap, views: views}
	}}
}

type msgAction struct {
	plan   *action.Plan
	group  *model.Group
	result action.Result
	freed  int64
}

type msgThaw struct {
	entry  action.FrozenEntry
	result action.Result
	quit   bool
}

// Handle processes a message produced by a Cmd.
func (m *Model) Handle(msg any) []Cmd {
	switch msg := msg.(type) {
	case msgSnapshot:
		m.sampling = false
		if msg.err != nil {
			m.setStatus("sampling failed: " + msg.err.Error())
			return nil
		}
		m.applySnapshot(msg.snap, msg.views)
	case msgAction:
		m.busy = ""
		msg.plan.Close()
		m.finishAction(msg)
		return []Cmd{m.sampleCmd()}
	case msgThaw:
		m.busy = ""
		if msg.result.Error == "" {
			m.deps.Registry.Remove(msg.entry.GroupID)
			m.saveRegistry()
		}
		m.setStatus(fmt.Sprintf("resume %s: %s", msg.entry.Name, msg.result.Summary()))
		if msg.quit && len(m.deps.Registry.Entries) == 0 {
			return []Cmd{{Quit: true}}
		}
	}
	return nil
}

func (m *Model) saveRegistry() {
	if err := m.deps.Registry.Save(); err != nil {
		m.setStatus("could not save the frozen list: " + err.Error())
	}
}

func (m *Model) applySnapshot(snap *model.Snapshot, views [3][]*model.Group) {
	m.snap = snap
	m.views = views
	m.protector = protect.New(m.deps.Config.Protect, snap)
	for _, gs := range views {
		for _, top := range gs {
			top.Walk(func(g *model.Group) {
				p := history.Point{T: snap.Time, Footprint: g.Mem.Footprint()}
				if g.PSI != nil {
					p.PSI, p.HasPSI = g.PSI.Some.Total, true
				}
				m.hist.Record(g.ID, p)
			})
		}
	}
	m.hist.Prune(snap.Time.Add(-time.Minute))
	var avg10 float64
	if snap.PSI != nil {
		avg10 = snap.PSI.Some.Avg10
	}
	// Culprit scoring uses the apps view: its top-level groups are disjoint
	// systemd units, each with its own cgroup PSI.
	base := views[group.ViewApps]
	if !snap.Unified {
		base = views[group.ViewTree]
	}
	m.culprit = m.tracker.Evaluate(base, m.hist, avg10, snap.PSI != nil)
	m.culpritG = nil
	if m.culprit.Culprit != "" {
		m.culpritG = group.Find(base, m.culprit.Culprit)
	}
	if m.deps.Registry.Reconcile(m.env()) {
		m.saveRegistry()
	}
	m.rebuild()
}

// isCulprit reports whether g is, or directly corresponds to, the culprit.
func (m *Model) isCulprit(g *model.Group) bool {
	c := m.culpritG
	if c == nil {
		return false
	}
	return g.ID == c.ID || g.ID == "host/"+c.ID || (c.Cgroup != "" && g.Cgroup == c.Cgroup)
}

func (m *Model) growth(g *model.Group) (int64, bool) {
	d, _, ok := m.hist.Growth(g.ID, m.deps.Config.GrowthWindow)
	return d, ok
}

func (m *Model) trend(g *model.Group) (history.Trend, bool) {
	t, ok := m.hist.Trend(g.ID, max(m.deps.Config.GrowthWindow, m.deps.Config.GrowthMinSpan))
	if !ok {
		return t, false
	}
	return t, t.SteadyGrowth(m.deps.Config.GrowthMinSpan, int64(m.deps.Config.GrowthMinDelta))
}

func (m *Model) sortGroups(gs []*model.Group) {
	key := func(g *model.Group) float64 {
		switch m.sort {
		case sortPSS:
			return float64(g.Mem.PSS)
		case sortSwap:
			return float64(g.Mem.Swap)
		case sortGrowth:
			d, _ := m.growth(g)
			return float64(d)
		case sortPSI:
			if g.PSI != nil {
				return g.PSI.Some.Avg10
			}
			return -1
		}
		return float64(g.Mem.USS)
	}
	sort.SliceStable(gs, func(i, j int) bool {
		if m.sort == sortName {
			return strings.ToLower(gs[i].Name) < strings.ToLower(gs[j].Name)
		}
		a, b := key(gs[i]), key(gs[j])
		if a != b {
			return a > b
		}
		return gs[i].Name < gs[j].Name
	})
	for _, g := range gs {
		m.sortGroups(g.Children)
	}
}

// rebuild flattens the current view into rows, keeping the selection.
func (m *Model) rebuild() {
	gs := m.views[m.view]
	m.sortGroups(gs)
	m.rows = m.rows[:0]
	var walk func(g *model.Group, depth int)
	walk = func(g *model.Group, depth int) {
		m.rows = append(m.rows, row{g, depth})
		if m.expanded[g.ID] {
			for _, c := range g.Children {
				walk(c, depth+1)
			}
		}
	}
	for _, g := range gs {
		walk(g, 0)
	}
	m.cursor = min(m.cursor, max(0, len(m.rows)-1))
	for i, r := range m.rows {
		if r.g.ID == m.selected {
			m.cursor = i
			break
		}
	}
	if m.cursor < len(m.rows) {
		m.selected = m.rows[m.cursor].g.ID
	}
}

func (m *Model) current() *model.Group {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return nil
	}
	return m.rows[m.cursor].g
}

func (m *Model) move(delta int) {
	if len(m.rows) == 0 {
		return
	}
	m.cursor = max(0, min(len(m.rows)-1, m.cursor+delta))
	m.selected = m.rows[m.cursor].g.ID
}

// Key handles a key press.
func (m *Model) Key(k term.Key) []Cmd {
	if k.Name == "ctrl+c" {
		return m.quit()
	}
	switch m.mode {
	case modeConfirm:
		return m.keyConfirm(k)
	case modeSuggest:
		return m.keySuggest(k)
	case modeFrozen:
		return m.keyFrozen(k)
	case modeSystem:
		return m.keySystem(k)
	case modeQuit:
		return m.keyQuit(k)
	case modeDetail, modeHelp:
		if k.Name == "esc" || k.String() == "q" || k.String() == "i" || k.String() == "?" || k.Name == "enter" {
			m.mode = modeList
		}
		return nil
	}
	return m.keyList(k)
}

func (m *Model) listHeight() int {
	return max(1, m.height-m.chromeHeight())
}

func (m *Model) keyList(k term.Key) []Cmd {
	switch k.String() {
	case "q":
		return m.quit()
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-m.listHeight())
	case "pgdn":
		m.move(m.listHeight())
	case "home", "g":
		m.move(-len(m.rows))
	case "end", "G":
		m.move(len(m.rows))
	case "enter", " ":
		if g := m.current(); g != nil && len(g.Children) > 0 {
			m.expanded[g.ID] = !m.expanded[g.ID]
			m.rebuild()
		}
	case "right", "l":
		if g := m.current(); g != nil && len(g.Children) > 0 {
			m.expanded[g.ID] = true
			m.rebuild()
		}
	case "left", "h":
		if g := m.current(); g != nil {
			if m.expanded[g.ID] {
				m.expanded[g.ID] = false
				m.rebuild()
			} else if d := m.rows[m.cursor].depth; d > 0 {
				for i := m.cursor - 1; i >= 0; i-- {
					if m.rows[i].depth < d {
						m.cursor = i
						m.selected = m.rows[i].g.ID
						break
					}
				}
			}
		}
	case "v":
		m.view = m.view.Next()
		m.cursor, m.offset = 0, 0
		m.selected = ""
		m.rebuild()
		if m.snap != nil && !m.snap.Unified && m.view != group.ViewTree {
			m.setStatus("cgroup v2 is not available: every view shows the process tree")
		}
	case "s":
		m.sort = (m.sort + 1) % sortCount
		m.rebuild()
	case "r":
		return m.Tick()
	case "t":
		return m.startPlan(action.Terminate)
	case "f":
		return m.startPlan(action.Freeze)
	case "c":
		m.openSuggestions(m.current())
	case "K":
		m.openKernel()
	case "F":
		m.mode = modeFrozen
		m.frozenCur = 0
	case "m":
		m.mode = modeSystem
	case "i":
		if g := m.current(); g != nil {
			m.detail = g
			m.mode = modeDetail
		}
	case "?":
		m.mode = modeHelp
	}
	return nil
}

func (m *Model) quit() []Cmd {
	if len(m.deps.Registry.Entries) > 0 && m.mode != modeQuit {
		m.mode = modeQuit
		return nil
	}
	return []Cmd{{Quit: true}}
}

func (m *Model) keyQuit(k term.Key) []Cmd {
	switch k.String() {
	case "r":
		m.mode = modeList
		var cmds []Cmd
		for _, e := range m.deps.Registry.Entries {
			cmds = append(cmds, m.thawCmd(e, true))
		}
		return cmds
	case "k", "ctrl+c":
		return []Cmd{{Quit: true}}
	case "esc", "q":
		m.mode = modeList
	}
	return nil
}

func (m *Model) startPlan(mode action.Mode) []Cmd {
	g := m.current()
	if g == nil || m.protector == nil {
		return nil
	}
	if m.busy != "" {
		m.setStatus("wait: " + m.busy)
		return nil
	}
	if !g.Kind.Actionable() {
		m.openSuggestions(g)
		m.setStatus(fmt.Sprintf("reclaim doesn't %s %s groups itself: copy a command and run it", mode, g.Kind))
		return nil
	}
	p, err := action.NewPlan(g, mode, m.env())
	if err != nil {
		m.setStatus(err.Error())
		return nil
	}
	m.plan, m.planGroup = p, g
	m.override = ""
	m.focusOK = false
	m.mode = modeConfirm
	return nil
}

func (m *Model) closePlan() {
	if m.plan != nil {
		m.plan.Close()
	}
	m.plan, m.planGroup = nil, nil
	m.mode = modeList
}

func (m *Model) overrideOK() bool {
	return !m.plan.NeedsOverride() || m.override == m.plan.Name
}

func (m *Model) keyConfirm(k term.Key) []Cmd {
	p := m.plan
	typing := p.NeedsOverride() && !p.Blocked()
	switch k.Name {
	case "esc":
		m.closePlan()
		return nil
	case "tab", "left", "right", "shift+tab":
		if !p.Blocked() {
			m.focusOK = !m.focusOK
		}
		return nil
	case "backspace":
		if typing && m.override != "" {
			r := []rune(m.override)
			m.override = string(r[:len(r)-1])
		}
		return nil
	case "enter":
		if !m.focusOK || p.Blocked() {
			m.closePlan()
			return nil
		}
		if !m.overrideOK() {
			m.setStatus("type the group name exactly to override its protection")
			return nil
		}
		return m.confirm()
	}
	if k.Rune == 0 {
		return nil
	}
	if typing {
		m.override += string(k.Rune)
		return nil
	}
	switch k.Rune {
	case '+':
		if p.Mode == action.Terminate {
			p.Grace += time.Second
		}
	case '-':
		if p.Mode == action.Terminate && p.Grace >= time.Second {
			p.Grace -= time.Second
		}
	case 'q':
		m.closePlan()
	}
	return nil
}

// confirm executes the plan, through sudo when needed.
func (m *Model) confirm() []Cmd {
	p, g := m.plan, m.planGroup
	m.plan, m.planGroup = nil, nil
	m.mode = modeList
	env := m.env()
	env.Grace = p.Grace
	exec, memAvail, delay := m.deps.ExecuteAction, m.deps.MemAvailable, m.deps.AfterDelay
	m.busy = fmt.Sprintf("%s %s", p.Mode, p.Name)
	if p.Mode == action.Terminate {
		m.busy += fmt.Sprintf(" (grace %s)", p.Grace)
	}
	run := func() any {
		before := memAvail()
		res := exec(p, env)
		time.Sleep(delay)
		after := memAvail()
		return msgAction{plan: p, group: g, result: res, freed: int64(after) - int64(before)}
	}
	if p.NeedsSudo {
		exe := m.deps.Exe
		return []Cmd{{Foreground: func() any {
			before := memAvail()
			fmt.Printf("reclaim: %s %s needs sudo (processes of other users)\n", p.Mode, p.Name)
			res := runSudo(action.SudoArgs(exe, p))
			time.Sleep(delay)
			return msgAction{plan: p, group: g, result: res, freed: int64(memAvail()) - int64(before)}
		}}}
	}
	return []Cmd{{Run: run}}
}

func (m *Model) finishAction(msg msgAction) {
	p, res := msg.plan, msg.result
	text := fmt.Sprintf("%s %s: %s", p.Mode, p.Name, res.Summary())
	if p.Mode == action.Terminate && res.Error == "" {
		text += fmt.Sprintf(". MemAvailable %s (estimated %s–%s)",
			signedSize(msg.freed), size(p.Estimate.Low), size(p.Estimate.High))
	}
	if p.Mode == action.Freeze && len(res.Frozen) > 0 {
		e := action.FrozenEntry{
			GroupID: p.GroupID, Name: p.Name, Method: res.Method, Sudo: p.NeedsSudo,
			At: time.Now(), Estimate: p.Estimate.Low,
		}
		if res.Method == "cgroup" {
			e.Cgroup = p.Cgroup
		}
		for _, t := range p.Targets {
			for _, pid := range res.Frozen {
				if t.PID == pid {
					e.Targets = append(e.Targets, t)
				}
			}
		}
		m.deps.Registry.Add(e)
		m.saveRegistry()
		text += ". Press F to see frozen groups and resume them."
	}
	m.setStatus(text)
}

func (m *Model) thawCmd(e action.FrozenEntry, quit bool) Cmd {
	env := m.env()
	thaw := m.deps.ThawEntry
	m.busy = "resuming " + e.Name
	if e.Sudo {
		exe := m.deps.Exe
		return Cmd{Foreground: func() any {
			fmt.Printf("reclaim: resuming %s needs sudo\n", e.Name)
			return msgThaw{entry: e, result: runSudo(action.SudoThawArgs(exe, e)), quit: quit}
		}}
	}
	return Cmd{Run: func() any { return msgThaw{entry: e, result: thaw(e, env), quit: quit} }}
}

func (m *Model) keyFrozen(k term.Key) []Cmd {
	entries := m.deps.Registry.Entries
	switch k.String() {
	case "esc", "q", "F":
		m.mode = modeList
	case "up", "k":
		m.frozenCur = max(0, m.frozenCur-1)
	case "down", "j":
		m.frozenCur = min(len(entries)-1, m.frozenCur+1)
	case "r", "enter":
		if m.frozenCur < len(entries) {
			return []Cmd{m.thawCmd(entries[m.frozenCur], false)}
		}
	}
	return nil
}

func (m *Model) openSuggestions(g *model.Group) {
	if g == nil {
		return
	}
	m.suggs = suggest.For(g)
	m.suggTitle = "Commands for " + g.Name
	if len(m.suggs) == 0 {
		m.suggTitle = "No commands for " + g.Name + "; kernel-level commands"
		m.openKernel()
		return
	}
	m.suggCursor = 0
	m.mode = modeSuggest
}

func (m *Model) openKernel() {
	if m.snap == nil {
		return
	}
	if !strings.HasPrefix(m.suggTitle, "No commands") {
		m.suggTitle = "Kernel-level commands"
	}
	m.suggs = suggest.Kernel(m.snap.Meminfo, m.snap.Zram)
	m.suggCursor = 0
	m.mode = modeSuggest
}

func (m *Model) keySuggest(k term.Key) []Cmd {
	switch k.String() {
	case "esc", "q", "c":
		m.mode = modeList
		m.suggTitle = ""
	case "up", "k":
		m.suggCursor = max(0, m.suggCursor-1)
	case "down", "j":
		m.suggCursor = min(len(m.suggs)-1, m.suggCursor+1)
	case "y", "enter":
		if m.suggCursor >= len(m.suggs) {
			return nil
		}
		s := m.suggs[m.suggCursor]
		if s.Disabled || strings.HasPrefix(s.Cmd, "#") {
			m.setStatus("not offered: " + s.Caveat)
			return nil
		}
		msg := "copied: " + s.Cmd
		if h := clipboard.Hint(m.deps.Clip); h != "" {
			msg += " (" + h + ")"
		}
		m.setStatus(msg)
		return []Cmd{{Write: clipboard.Sequence(s.Cmd, m.deps.Clip)}}
	}
	return nil
}

func (m *Model) keySystem(k term.Key) []Cmd {
	n := 0
	if m.snap != nil {
		n = len(sysmem.Breakdown(m.snap.Meminfo, m.snap.Zram))
	}
	switch k.String() {
	case "esc", "q", "m":
		m.mode = modeList
	case "up", "k":
		m.sysCursor = max(0, m.sysCursor-1)
	case "down", "j":
		m.sysCursor = min(n-1, m.sysCursor+1)
	case "c", "K":
		m.suggTitle = ""
		m.openKernel()
	}
	return nil
}

// SetSize records the terminal size.
func (m *Model) SetSize(w, h int) { m.width, m.height = w, h }
