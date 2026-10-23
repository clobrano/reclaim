package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/clobrano/reclaim/internal/action"
	"github.com/clobrano/reclaim/internal/model"
	"github.com/clobrano/reclaim/internal/sysmem"
)

func (m *Model) headerLines() []line {
	var out []line
	l := line{}
	l.add(sBold+";"+sCyan, " reclaim ")
	if m.snap == nil {
		l.add(sDim, " sampling…")
		return []line{l}
	}
	s := sysmem.Summarize(m.snap.Meminfo)
	l.add("", " RAM ").add(sBold, pct(s.Used, s.Total)+" used").
		add("", fmt.Sprintf(" (%s of %s) · ", size(s.Used), size(s.Total))).add(sBold, size(s.Available)).add("", " available")
	if s.SwapTotal > 0 {
		l.add("", "  swap ").add(sBold, size(s.SwapUsed)+"/"+size(s.SwapTotal))
	}
	if p := m.snap.PSI; p != nil {
		style := sGreen
		switch {
		case p.Some.Avg10 >= m.deps.Config.CulpritThreshold:
			style = sRed + ";" + sBold
		case p.Some.Avg10 >= 1:
			style = sYellow
		}
		l.add("", "  PSI some ").add(style, fmt.Sprintf("%.1f%%", p.Some.Avg10)).add("", fmt.Sprintf(" full %.1f%%", p.Full.Avg10))
	} else {
		l.add(sDim, "  PSI n/a")
	}
	out = append(out, l)
	if m.showUsageBar() {
		out = append(out, m.usageLines()...)
	}

	l = line{}
	l.add("", " view ").add(sBold, m.view.String()).add("", "  sort ").add(sBold, m.sort.String())
	if n := len(m.deps.Registry.Entries); n > 0 {
		l.add(sBlue, fmt.Sprintf("  %d frozen (F)", n))
	}
	unreadable := 0
	for _, p := range m.snap.Procs {
		if !p.Readable {
			unreadable++
		}
	}
	if unreadable > 0 {
		l.add(sYellow, fmt.Sprintf("  %d processes of other users unreadable: their USS/PSS show as ?", unreadable))
	}
	for _, w := range m.snap.Warnings {
		l.add(sYellow, "  "+w)
	}
	out = append(out, l)

	if c := m.culpritG; c != nil {
		l = line{}
		l.add(sRed+";"+sBold, " ▲ pressure culprit: "+c.Name).add(sRed, " — "+m.culprit.Scores[c.ID].Evidence())
		out = append(out, l)
	}
	return out
}

type column struct {
	title string
	width int
	cell  func(g *model.Group) (string, string)
}

func (m *Model) columns() []column {
	mem := func(get func(model.Mem) uint64, needsRollup bool) func(*model.Group) (string, string) {
		return func(g *model.Group) (string, string) {
			if needsRollup && len(g.Procs) > 0 && g.Mem.Unreadable == len(g.Procs) {
				return "?", sDim
			}
			s := size(get(g.Mem))
			if needsRollup && g.Mem.Unreadable > 0 {
				s += "*"
			}
			return s, ""
		}
	}
	cols := []column{
		{"RAM%", 6, func(g *model.Group) (string, string) {
			s := pct(g.Mem.Used, m.snap.Meminfo["MemTotal"])
			if g.Mem.Unreadable > 0 {
				s += "*"
			}
			return s, sBold
		}},
		{"USS", 8, mem(func(x model.Mem) uint64 { return x.USS }, true)},
		{"PSS", 8, mem(func(x model.Mem) uint64 { return x.PSS }, true)},
	}
	if m.width >= 100 {
		cols = append(cols, column{"Shared", 8, mem(func(x model.Mem) uint64 { return x.Shared }, true)})
	}
	cols = append(cols, column{"Swap", 8, mem(func(x model.Mem) uint64 { return x.Swap }, false)})
	if m.width >= 110 {
		cols = append(cols, column{"RSS", 8, func(g *model.Group) (string, string) { return size(g.Mem.RSS), sDim }})
	}
	if m.width >= 70 {
		win := m.deps.Config.GrowthWindow
		cols = append(cols, column{"Δ" + shortDur(win), 8, func(g *model.Group) (string, string) {
			d, ok := m.growth(g)
			if !ok {
				return "", ""
			}
			style := ""
			if d > 64<<20 {
				style = sYellow
			}
			if d > 512<<20 {
				style = sRed
			}
			return signedSize(d), style
		}})
		cols = append(cols, column{"PSI", 6, func(g *model.Group) (string, string) {
			if g.PSI == nil {
				return "", ""
			}
			style := ""
			if g.PSIShared {
				style = sDim
			}
			if g.PSI.Some.Avg10 >= 5 {
				style = sYellow
			}
			return fmt.Sprintf("%.0f%%", g.PSI.Some.Avg10), style
		}})
	}
	return cols
}

func shortDur(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func (m *Model) flags(g *model.Group) (string, string) {
	f := []byte("    ")
	style := ""
	if m.isCulprit(g) {
		f[0] = 'C'
		style = sRed + ";" + sBold
	}
	if _, steady := m.trend(g); steady {
		f[1] = 'G'
		if style == "" {
			style = sYellow
		}
	}
	if m.protector != nil && g.Kind.Actionable() && len(m.protector.Check(g)) > 0 {
		f[2] = 'P'
		if style == "" {
			style = sMagenta
		}
	}
	if _, ok := m.deps.Registry.Find(g.ID); ok {
		f[3] = 'F'
		if style == "" {
			style = sBlue
		}
	}
	return string(f), style
}

func (m *Model) rowLine(r row, cols []column, nameW int) line {
	g := r.g
	l := line{}
	marker := "  "
	if len(g.Children) > 0 {
		marker = "▸ "
		if m.expanded[g.ID] {
			marker = "▾ "
		}
	}
	name := strings.Repeat("  ", r.depth) + marker + g.Name
	kind := string(g.Kind)
	if g.Kind == model.KindProcess || g.Kind == model.KindTree {
		kind = g.Detail
	}
	nameText := truncate(name, nameW)
	l.add(sBold, nameText)
	if rest := nameW - len([]rune(nameText)); rest > 2 && kind != "" {
		l.add(sDim, padRight(" "+kind, rest))
	} else if rest > 0 {
		l.add("", strings.Repeat(" ", rest))
	}
	f, fs := m.flags(g)
	l.add(fs, " "+f)
	for _, c := range cols {
		v, st := c.cell(g)
		l.add(st, " "+padLeft(v, c.width))
	}
	return l
}

func (m *Model) colHeader(cols []column, nameW int) line {
	l := line{}
	l.add(sBold+";"+sDim, padRight(" Group", nameW)+" "+"Flag")
	for _, c := range cols {
		l.add(sBold+";"+sDim, " "+padLeft(c.title, c.width))
	}
	return l
}

func (m *Model) sysBar() line {
	l := line{{" ", ""}}
	if m.snap == nil {
		return l
	}
	short := map[string]string{
		"Anonymous": "anon", "Page cache": "cache", "Dirty / writeback": "dirty",
		"Slab, reclaimable": "slab", "Slab, unreclaimable": "slab-u", "Shmem / tmpfs": "shmem",
		"zram": "zram", "Hugepages (reserved)": "huge", "Kernel": "kernel", "Free": "free",
		"Unaccounted": "other", "Swap used": "swap",
	}
	for _, r := range sysmem.Breakdown(m.snap.Meminfo, m.snap.Zram) {
		if r.Bytes == 0 {
			continue
		}
		l.add("", short[r.Name]+" ").add(sBold, size(r.Bytes))
		if r.Tag == sysmem.TagUnused {
			l.add("", "  ")
		} else {
			l.add(tagStyle(r.Tag), "["+r.Tag.Short()+"]  ")
		}
	}
	l.add(sDim, "m: explain")
	return l
}

func tagStyle(t sysmem.Tag) string {
	switch t {
	case sysmem.TagKernel:
		return sGreen
	case sysmem.TagAction:
		return sYellow
	}
	return sDim
}

func (m *Model) footer() []line {
	status := line{}
	switch {
	case m.busy != "":
		status.add(sYellow, " … "+m.busy)
	case m.status != "" && time.Since(m.statusT) < 30*time.Second:
		status.add("", " "+m.status)
	default:
		if g := m.current(); g != nil {
			e := model.EstimateOf(g.Mem)
			status.add(sDim, fmt.Sprintf(" %s: %d processes · %s of RAM in use · stopping frees about %s–%s",
				g.Name, len(g.Procs), pct(g.Mem.Used, m.snap.Meminfo["MemTotal"]), size(e.Low), size(e.High)))
			if t, steady := m.trend(g); steady {
				status.add(sYellow, fmt.Sprintf(" · grew %s in %s", signedSize(t.Delta), t.Span.Round(time.Minute)))
			}
		}
	}
	help := line{}
	for _, kv := range [][2]string{
		{"v", "view"}, {"s", "sort"}, {"⏎", "expand"}, {"t", "terminate"}, {"f", "freeze"},
		{"F", "frozen"}, {"c", "commands"}, {"K", "kernel"}, {"m", "memory"}, {"i", "info"}, {"?", "help"}, {"q", "quit"},
	} {
		help.add(sBold+";"+sCyan, " "+kv[0]).add(sDim, " "+kv[1])
	}
	return []line{status, help}
}

func (m *Model) showSysBar() bool { return m.height >= 20 }

func (m *Model) chromeHeight() int {
	n := len(m.headerLines()) + 1 + 2
	if m.showSysBar() {
		n++
	}
	return n
}

// Render draws the whole screen.
func (m *Model) Render() []string {
	w, h := m.width, m.height
	var lines []line
	lines = append(lines, m.headerLines()...)
	cols := m.columns()
	fixed := 5
	for _, c := range cols {
		fixed += c.width + 1
	}
	nameW := max(16, w-fixed)
	lines = append(lines, m.colHeader(cols, nameW))
	listH := max(1, h-m.chromeHeight())
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+listH {
		m.offset = m.cursor - listH + 1
	}
	m.offset = max(0, min(m.offset, max(0, len(m.rows)-listH)))
	listStart := len(lines)
	for i := m.offset; i < m.offset+listH; i++ {
		if i < len(m.rows) {
			lines = append(lines, m.rowLine(m.rows[i], cols, nameW))
		} else {
			lines = append(lines, line{})
		}
	}
	if m.showSysBar() {
		lines = append(lines, m.sysBar())
	}
	lines = append(lines, m.footer()...)

	var overlay []line
	switch m.mode {
	case modeConfirm:
		overlay = m.confirmBox(w)
	case modeSuggest:
		overlay = m.suggestBox(w)
	case modeFrozen:
		overlay = m.frozenBox(w)
	case modeSystem:
		overlay = m.systemBox(w)
	case modeDetail:
		overlay = m.detailBox(w)
	case modeHelp:
		overlay = m.helpBox(w)
	case modeQuit:
		overlay = m.quitBox(w)
	}

	out := make([]string, 0, h)
	sel := listStart + m.cursor - m.offset
	for i, l := range lines {
		if i >= h {
			break
		}
		base := ""
		if i == sel && m.mode == modeList && len(m.rows) > 0 {
			base = sRev
		}
		out = append(out, l.render(w, base))
	}
	if len(overlay) > 0 {
		top := max(0, (h-len(overlay))/2)
		bw := overlay[0].width()
		left := max(0, (w-bw)/2)
		for i, ol := range overlay {
			y := top + i
			if y >= len(out) {
				break
			}
			full := line{{strings.Repeat(" ", left), ""}}
			full = append(full, ol...)
			out[y] = full.render(w, "")
		}
	}
	return out
}

func dialogWidth(w int) int { return max(30, min(w-4, 90)) }

func addWrapped(body *[]line, style, prefix, s string, width int) {
	for i, ln := range wrap(s, width-len([]rune(prefix))) {
		p := prefix
		if i > 0 {
			p = strings.Repeat(" ", len([]rune(prefix)))
		}
		*body = append(*body, text(style, p+ln))
	}
}

func (m *Model) confirmBox(w int) []line {
	p := m.plan
	inner := dialogWidth(w)
	tw := inner - 2
	verb := "Terminate"
	if p.Mode == action.Freeze {
		verb = "Freeze"
	}
	var body []line
	est := line{}
	if p.Mode == action.Terminate {
		est.add("", "Expected to free ").add(sBold+";"+sGreen, fmt.Sprintf("%s – %s", size(p.Estimate.Low), size(p.Estimate.High)))
	} else {
		est.add("", "Private memory that could be swapped out: ").add(sBold, size(p.Estimate.Low))
	}
	body = append(body, est)
	addWrapped(&body, sDim, "", "Low: USS + SwapPss (the kernel doesn't expose private swap; SwapPss is the closest stand-in). High: PSS + SwapPss, which counts memory shared only within the group.", tw)
	if p.Estimate.Partial {
		addWrapped(&body, sYellow, "", "Partial: some processes could not be read.", tw)
	}
	body = append(body, line{})
	how := line{}
	switch p.Mode {
	case action.Terminate:
		how.add("", fmt.Sprintf("SIGTERM, then SIGKILL after %s", p.Grace)).add(sDim, "  (+/- to change)")
		if p.UseCgroup {
			how.add("", ", then cgroup.kill")
		}
	case action.Freeze:
		if p.UseCgroup {
			how.add("", "cgroup.freeze on "+p.Cgroup)
		} else {
			how.add("", "SIGSTOP to each process")
		}
	}
	body = append(body, how)
	var pids []string
	for i, t := range p.Targets {
		if i == 10 {
			pids = append(pids, fmt.Sprintf("+%d more", len(p.Targets)-10))
			break
		}
		pids = append(pids, fmt.Sprintf("%d %s", t.PID, t.Comm))
	}
	addWrapped(&body, "", fmt.Sprintf("PIDs (%d): ", len(p.Targets)), strings.Join(pids, ", "), tw)
	if len(p.Warnings) > 0 {
		body = append(body, line{})
		for _, wn := range p.Warnings {
			addWrapped(&body, sYellow, "! ", wn, tw)
		}
	}
	if len(p.Protected) > 0 {
		body = append(body, line{})
		for _, r := range p.Protected {
			addWrapped(&body, sMagenta+";"+sBold, "Protected: ", r.Text, tw)
		}
		if p.Blocked() {
			body = append(body, text(sRed+";"+sBold, "This group can't be stopped."))
		} else {
			in := line{}
			in.add("", "Type ").add(sBold, p.Name).add("", " to override: ").add(sRev, m.override+" ")
			body = append(body, in)
		}
	}
	body = append(body, line{})
	btn := line{}
	cancel, ok := " Cancel ", " "+verb+" "
	cs, os := sBold, sDim
	if m.focusOK {
		cs, os = sDim, sRev+";"+sBold
		if p.Mode == action.Terminate {
			os += ";" + sRed
		}
	} else {
		cs = sRev + ";" + sBold
	}
	btn.add(cs, "["+cancel+"]")
	if !p.Blocked() {
		btn.add("", "   ").add(os, "["+ok+"]")
	}
	btn.add(sDim, "   tab: switch · enter: choose · esc: cancel")
	body = append(body, btn)
	return box(fmt.Sprintf("%s %s?", verb, p.Name), body, inner, sCyan)
}

func (m *Model) suggestBox(w int) []line {
	inner := dialogWidth(w)
	tw := inner - 2
	var body []line
	addWrapped(&body, sDim, "", "reclaim doesn't run these: copy one (y) and run it yourself.", tw)
	for i, s := range m.suggs {
		body = append(body, line{})
		st := sBold
		mark := "  "
		if i == m.suggCursor {
			st = sBold + ";" + sRev
			mark = "▸ "
		}
		title := s.Title
		if s.Disabled {
			title += " (not offered)"
			st += ";" + sDim
		}
		body = append(body, text(st, mark+title))
		addWrapped(&body, sGreen, "  $ ", s.Cmd, tw)
		if s.Effect != "" {
			addWrapped(&body, "", "    ", s.Effect, tw)
		}
		if s.Caveat != "" {
			addWrapped(&body, sYellow, "    ", s.Caveat, tw)
		}
	}
	body = append(body, line{}, text(sDim, "↑/↓ select · y/enter copy (OSC 52) · esc close"))
	return box(m.suggTitle, m.fit(body), inner, sCyan)
}

// fit trims dialog bodies to the screen height.
func (m *Model) fit(body []line) []line {
	max := m.height - 2
	if len(body) > max && max > 1 {
		body = append(body[:max-1], text(sDim, "…"))
	}
	return body
}

func (m *Model) frozenBox(w int) []line {
	inner := dialogWidth(w)
	var body []line
	entries := m.deps.Registry.Entries
	if len(entries) == 0 {
		body = append(body, text(sDim, "Nothing is frozen."))
	}
	for i, e := range entries {
		st := ""
		if i == m.frozenCur {
			st = sRev
		}
		l := line{}
		l.add(st+";"+sBold, padRight(e.Name, 24)).add(st, fmt.Sprintf(" %-8s %3d processes  %s private  since %s",
			e.Method, len(e.Targets), size(e.Estimate), e.At.Format("15:04")))
		if e.Sudo {
			l.add(st+";"+sDim, " (sudo)")
		}
		body = append(body, l)
	}
	body = append(body, line{})
	addWrapped(&body, sDim, "", "Frozen groups free no RAM by themselves; the kernel can swap their pages out under pressure. r/enter: resume · esc: close", inner-2)
	return box("Frozen groups", m.fit(body), inner, sBlue)
}

func (m *Model) systemBox(w int) []line {
	inner := dialogWidth(w)
	tw := inner - 2
	var body []line
	total := m.snap.Meminfo["MemTotal"]
	s := sysmem.Summarize(m.snap.Meminfo)
	body = append(body, text(sBold, fmt.Sprintf("Why RAM is %s used (%s of %s)", pct(s.Used, total), size(s.Used), size(total))))
	addWrapped(&body, sDim, "", "\"Used\" is total minus available, as free and system monitors count it. Page cache the kernel can drop counts as available. Groups are the top level of the current view ("+m.view.String()+"), so the slices match the list.", tw)
	for i, p := range m.usedParts() {
		l := line{}
		l.add(partStyle(i, p), "█ ").add(sBold, padRight(p.Name, 22)).add("", padLeft(size(p.Bytes), 7)+"  "+padLeft(pct(p.Bytes, total), 5))
		if t := sysmem.PartText(p.Kind); t != "" {
			l.add(sDim, "  "+t)
		}
		body = append(body, l)
	}
	if tmpfs, parts := m.shmemParts(); tmpfs >= total/100 {
		body = append(body, line{}, text(sBold, fmt.Sprintf("Inside tmpfs & shmem (%s): shared memory no process maps", size(tmpfs))))
		for _, p := range parts {
			l := line{}
			l.add("", "  "+padRight(p.Name, 30)).add(sBold, padLeft(size(p.Bytes), 7))
			body = append(body, l)
			if p.Kind == "other" {
				addWrapped(&body, sDim, "    ", sysmem.ShmemOtherText, tw)
			}
		}
		addWrapped(&body, sDim, "  ", "Mount sizes include files swapped out or mapped by a process, so they can add up to more than the slice. c: commands to find and free it.", tw)
	}
	body = append(body, line{}, text(sBold, "All of RAM, by kind"))
	rows := sysmem.Breakdown(m.snap.Meminfo, m.snap.Zram)
	m.sysCursor = min(m.sysCursor, len(rows)-1)
	for i, r := range rows {
		st := ""
		if i == m.sysCursor {
			st = sRev
		}
		l := line{}
		l.add(st+";"+sBold, padRight(r.Name, 21)).add(st, padLeft(size(r.Bytes), 7)+"  ").
			add(st+";"+tagStyle(r.Tag), padRight(r.Tag.String(), 29)).add(st+";"+sDim, " "+r.Meaning)
		body = append(body, l)
	}
	body = append(body, line{})
	if m.sysCursor >= 0 && m.sysCursor < len(rows) {
		addWrapped(&body, "", "", rows[m.sysCursor].Detail, tw)
	}
	if p := m.snap.PSI; p != nil {
		body = append(body, line{})
		body = append(body, text("", fmt.Sprintf("Pressure (PSI): some %.1f%% / %.1f%% / %.1f%% (10s/60s/300s), full %.1f%%",
			p.Some.Avg10, p.Some.Avg60, p.Some.Avg300, p.Full.Avg10)))
		addWrapped(&body, sDim, "", "\"some\" is the share of time at least one task waited for memory; \"full\", the share when all did.", tw)
	}
	body = append(body, line{}, text(sDim, "↑/↓ select · c: kernel-level commands · esc close"))
	return box("Where memory goes", m.fit(body), inner, sCyan)
}

func (m *Model) detailBox(w int) []line {
	g := m.detail
	inner := dialogWidth(w)
	tw := inner - 2
	var body []line
	kv := func(k, v string) {
		l := line{}
		l.add(sDim, padRight(k, 14)).add("", v)
		body = append(body, l)
	}
	kv("kind", string(g.Kind))
	if g.Cgroup != "" {
		kv("cgroup", g.Cgroup)
	}
	if g.Unit != "" {
		kv("unit", g.Unit)
	}
	if g.Container != nil {
		kv("container", g.Container.Runtime+" "+g.Container.ID)
	}
	if g.Pod != nil {
		kv("pod", fmt.Sprintf("%s/%s (uid %s)", g.Pod.Namespace, g.Pod.Name, g.Pod.UID))
	}
	if g.VM != nil {
		kv("vm", g.VM.Name+" on "+g.VM.URI)
	}
	pids := make([]string, 0, 12)
	for i, p := range g.Procs {
		if i == 12 {
			pids = append(pids, fmt.Sprintf("+%d", len(g.Procs)-12))
			break
		}
		pids = append(pids, fmt.Sprint(p.PID))
	}
	kv("processes", fmt.Sprintf("%d: %s", len(g.Procs), strings.Join(pids, " ")))
	mm := g.Mem
	kv("memory", fmt.Sprintf("USS %s · PSS %s · shared %s · swap %s (SwapPss %s) · RSS %s",
		size(mm.USS), size(mm.PSS), size(mm.Shared), size(mm.Swap), size(mm.SwapPSS), size(mm.RSS)))
	if mm.Unreadable > 0 {
		kv("", fmt.Sprintf("%d processes unreadable: their USS/PSS are missing", mm.Unreadable))
	}
	e := model.EstimateOf(mm)
	kv("stop frees", fmt.Sprintf("%s – %s", size(e.Low), size(e.High)))
	if c := g.CgMem; c != nil {
		kv("cgroup", fmt.Sprintf("current %s · anon %s · page cache %s · shmem %s · kernel %s · swap %s",
			size(c.Current), size(c.Anon), size(c.File), size(c.Shmem), size(c.Kernel), size(c.Swap)))
	}
	if p := g.PSI; p != nil {
		v := fmt.Sprintf("some %.1f%% / %.1f%% / %.1f%% · full %.1f%%", p.Some.Avg10, p.Some.Avg60, p.Some.Avg300, p.Full.Avg10)
		if g.PSIShared {
			v += " (shared cgroup)"
		}
		kv("pressure", v)
	}
	if d, ok := m.growth(g); ok {
		kv("growth", signedSize(d)+" over the last "+shortDur(m.deps.Config.GrowthWindow))
	}
	if t, steady := m.trend(g); steady {
		kv("", fmt.Sprintf("steady growth: %s in %s (%s/min, R² %.2f)", signedSize(t.Delta), t.Span.Round(time.Minute),
			signedSize(int64(t.Slope*60)), t.R2))
	}
	var series []uint64
	for _, p := range m.hist.Series(g.ID) {
		series = append(series, p.Footprint)
	}
	if len(series) > 1 {
		kv("history", sparkline(series, tw-14))
	}
	if m.isCulprit(g) {
		addWrapped(&body, sRed, "culprit       ", m.culprit.Scores[m.culpritG.ID].Evidence(), tw)
	}
	if m.protector != nil && g.Kind.Actionable() {
		for _, r := range m.protector.Check(g) {
			addWrapped(&body, sMagenta, "protected     ", r.Text, tw)
		}
	}
	body = append(body, line{}, text(sDim, "esc close"))
	return box(g.Name, m.fit(body), inner, sCyan)
}

func (m *Model) helpBox(w int) []line {
	inner := dialogWidth(w)
	var body []line
	for _, kv := range [][2]string{
		{"↑↓ j k, PgUp PgDn", "move"},
		{"enter, → ←", "expand / collapse"},
		{"v", "switch view: apps & scopes → containers, pods, VMs → process tree"},
		{"s", "cycle sort: RAM%, USS, PSS, swap, growth, PSI, name"},
		{"t", "terminate the group (SIGTERM, grace, SIGKILL), after confirmation"},
		{"f", "freeze the group (cgroup.freeze or SIGSTOP), after confirmation"},
		{"F", "frozen groups; resume them"},
		{"c", "commands to copy for containers, pods, VMs, services"},
		{"K", "kernel-level commands (drop caches, compaction, swap flush)"},
		{"m", "system memory breakdown, explained"},
		{"i", "details of the selected group"},
		{"r", "refresh now"},
		{"q", "quit"},
	} {
		l := line{}
		l.add(sBold+";"+sCyan, padRight(kv[0], 20)).add("", kv[1])
		body = append(body, l)
	}
	body = append(body, line{})
	for _, kv := range [][2]string{
		{"C", "drives memory pressure now (stall share + recent growth)"},
		{"G", "steady growth over the session"},
		{"P", "protected: stopping it needs an explicit override"},
		{"F", "frozen by reclaim"},
		{"*", "some processes unreadable: the number is a lower bound"},
	} {
		l := line{}
		l.add(sBold, padRight("  "+kv[0], 20)).add("", kv[1])
		body = append(body, l)
	}
	body = append(body, line{})
	addWrapped(&body, sDim, "", "RAM% is the group's share of RAM counted as used (anonymous and shared memory, split fairly among sharers); the bar at the top adds these up to the system's used percentage. USS is memory only this group maps; PSS splits shared pages among their users. Estimates use these, never RSS. Containers, pods, VMs and the kernel only get commands to copy.", inner-2)
	return box("reclaim help", m.fit(body), inner, sCyan)
}

func (m *Model) quitBox(w int) []line {
	inner := min(dialogWidth(w), 70)
	var body []line
	n := len(m.deps.Registry.Entries)
	addWrapped(&body, "", "", fmt.Sprintf("%d groups are still frozen. They stay frozen after reclaim exits; the list is saved and shown next time.", n), inner-2)
	body = append(body, line{})
	l := line{}
	l.add(sBold+";"+sCyan, "r").add("", " resume all and quit   ").add(sBold+";"+sCyan, "k").add("", " keep frozen and quit   ").add(sBold+";"+sCyan, "esc").add("", " cancel")
	body = append(body, l)
	return box("Quit reclaim?", body, inner, sYellow)
}

// pct formats part/total as a percentage: 18%, 4.2%, <0.1%.
func pct(part, total uint64) string {
	if total == 0 {
		return "?"
	}
	v := float64(part) / float64(total) * 100
	switch {
	case part == 0:
		return "0%"
	case v < 0.1:
		return "<0.1%"
	case v < 10:
		return fmt.Sprintf("%.1f%%", v)
	}
	return fmt.Sprintf("%.0f%%", v)
}

// usedTopN is how many groups get their own slice of the usage bar.
const usedTopN = 5

var (
	groupColors = []string{sCyan, sMagenta, sBlue, sGreen, sYellow}
	partColors  = map[sysmem.PartKind]string{
		sysmem.PartOthers: "37",
		sysmem.PartKernel: sRed,
		sysmem.PartTmpfs:  "93",
		sysmem.PartZram:   "95",
		sysmem.PartHuge:   "94",
		sysmem.PartRest:   "90",
	}
)

// usedParts explains the used percentage with the current view's top-level
// groups, which are disjoint, so the bar matches the list below it.
func (m *Model) usedParts() []sysmem.Part {
	var gs []sysmem.GroupUse
	for _, g := range m.views[m.view] {
		gs = append(gs, sysmem.GroupUse{ID: g.ID, Name: g.Name, Used: g.Mem.Used, Shmem: g.Mem.UsedShmem})
	}
	return sysmem.ExplainUsed(m.snap.Meminfo, m.snap.Zram, gs, usedTopN)
}

// shmemParts returns the size of the "tmpfs & shmem" slice and where it lives.
func (m *Model) shmemParts() (uint64, []sysmem.ShmemPart) {
	var slice uint64
	for _, p := range m.usedParts() {
		if p.Kind == sysmem.PartTmpfs {
			slice = p.Bytes
		}
	}
	return slice, sysmem.ExplainShmem(slice, m.snap.Tmpfs, m.snap.Shm)
}

func partStyle(i int, p sysmem.Part) string {
	if p.Kind == sysmem.PartGroup {
		return groupColors[i%len(groupColors)]
	}
	return partColors[p.Kind]
}

func (m *Model) showUsageBar() bool { return m.height >= 16 && m.width >= 40 }

// usageLines draws "used" as a stacked bar over the whole of RAM, followed
// by a legend, so the percentage maps onto the groups in the list.
func (m *Model) usageLines() []line {
	total := m.snap.Meminfo["MemTotal"]
	parts := m.usedParts()
	barW := m.width - 2
	bar := line{{" ", ""}}
	var cum uint64
	drawn := 0
	for i, p := range parts {
		cum += p.Bytes
		end := int(float64(cum) / float64(total) * float64(barW))
		if end > drawn {
			bar.add(partStyle(i, p), strings.Repeat("█", end-drawn))
			drawn = end
		}
	}
	if drawn < barW {
		bar.add(sDim, strings.Repeat("·", barW-drawn))
	}

	var legend []line
	cur := line{{" ", ""}}
	add := func(item line) {
		if cur.width()+item.width() > m.width-1 && len(cur) > 1 {
			legend = append(legend, cur)
			cur = line{{" ", ""}}
		}
		cur = append(cur, item...)
	}
	for i, p := range parts {
		item := line{}
		item.add(partStyle(i, p), "█ ").add("", truncate(p.Name, 20)+" ").add(sBold, pct(p.Bytes, total)).add("", "  ")
		add(item)
	}
	s := sysmem.Summarize(m.snap.Meminfo)
	item := line{}
	item.add(sDim, "· available ").add(sBold, pct(s.Available, total))
	add(item)
	legend = append(legend, cur)
	if len(legend) > 2 {
		legend = legend[:2]
	}
	return append([]line{bar}, legend...)
}
