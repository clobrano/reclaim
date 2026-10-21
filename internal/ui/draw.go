package ui

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// SGR styles.
const (
	sBold    = "1"
	sDim     = "2"
	sRev     = "7"
	sRed     = "31"
	sGreen   = "32"
	sYellow  = "33"
	sBlue    = "34"
	sMagenta = "35"
	sCyan    = "36"
)

type seg struct{ text, style string }

// line is a sequence of styled segments. Every rune is assumed to occupy one
// cell; the UI only uses such characters in its own text.
type line []seg

func (l *line) add(style, text string) *line {
	*l = append(*l, seg{text, style})
	return l
}

func (l line) width() int {
	n := 0
	for _, s := range l {
		n += utf8.RuneCountInString(s.text)
	}
	return n
}

func text(style, s string) line { return line{{s, style}} }

// render draws the line clipped and padded to width. base applies to the
// whole line (e.g. reverse video for the selected row).
func (l line) render(width int, base string) string {
	var b strings.Builder
	left := width
	for _, s := range l {
		if left <= 0 {
			break
		}
		t := sanitize(s.text)
		if n := utf8.RuneCountInString(t); n > left {
			t = truncate(t, left)
		}
		left -= utf8.RuneCountInString(t)
		b.WriteString(sgr(base, s.style))
		b.WriteString(t)
	}
	b.WriteString(sgr(base, ""))
	if left > 0 {
		b.WriteString(strings.Repeat(" ", left))
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

func sgr(base, style string) string {
	parts := []string{"0"}
	if base != "" {
		parts = append(parts, base)
	}
	if style != "" {
		parts = append(parts, style)
	}
	return "\x1b[" + strings.Join(parts, ";") + "m"
}

// sanitize drops control characters, which could come from process names.
func sanitize(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func padRight(s string, n int) string {
	s = truncate(s, n)
	if w := utf8.RuneCountInString(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func padLeft(s string, n int) string {
	s = truncate(s, n)
	if w := utf8.RuneCountInString(s); w < n {
		return strings.Repeat(" ", n-w) + s
	}
	return s
}

// wrap breaks text into lines of at most width runes, on spaces.
func wrap(s string, width int) []string {
	if width < 10 {
		width = 10
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		cur := ""
		for _, w := range words {
			switch {
			case cur == "":
				cur = w
			case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) <= width:
				cur += " " + w
			default:
				out = append(out, cur)
				cur = w
			}
			for utf8.RuneCountInString(cur) > width {
				r := []rune(cur)
				out = append(out, string(r[:width]))
				cur = string(r[width:])
			}
		}
		out = append(out, cur)
	}
	return out
}

// size formats bytes compactly for table cells: 0, 812K, 3.8G, 512M.
func size(b uint64) string {
	if b == 0 {
		return "0"
	}
	units := []string{"B", "K", "M", "G", "T", "P"}
	v := float64(b)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v < 10 && i > 0 {
		return fmt.Sprintf("%.1f%s", v, units[i])
	}
	return fmt.Sprintf("%.0f%s", v, units[i])
}

func signedSize(d int64) string {
	if d == 0 {
		return "0"
	}
	if d < 0 {
		return "-" + size(uint64(-d))
	}
	return "+" + size(uint64(d))
}

var sparks = []rune("▁▂▃▄▅▆▇█")

// sparkline draws values scaled between their min and max.
func sparkline(vals []uint64, width int) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	lo, hi := vals[0], vals[0]
	for _, v := range vals {
		lo, hi = min(lo, v), max(hi, v)
	}
	var b strings.Builder
	for _, v := range vals {
		i := 0
		if hi > lo {
			i = int(float64(v-lo) / float64(hi-lo) * float64(len(sparks)-1))
		}
		b.WriteRune(sparks[i])
	}
	return b.String()
}

// box frames content lines for a dialog of the given inner width.
func box(title string, body []line, inner int, style string) []line {
	out := []line{}
	top := line{}
	t := " " + title + " "
	top.add(style, "┌─").add(style+";1", t)
	if rest := inner - utf8.RuneCountInString(t) - 1; rest > 0 {
		top.add(style, strings.Repeat("─", rest))
	}
	top.add(style, "┐")
	out = append(out, top)
	for _, b := range body {
		l := line{{"│ ", style}}
		w := b.width()
		if w > inner-2 {
			b = clip(b, inner-2)
			w = inner - 2
		}
		l = append(l, b...)
		l.add("", strings.Repeat(" ", inner-2-w))
		l.add(style, " │")
		out = append(out, l)
	}
	out = append(out, text(style, "└"+strings.Repeat("─", inner)+"┘"))
	return out
}

// clip truncates a styled line to n cells.
func clip(l line, n int) line {
	var out line
	for _, s := range l {
		w := utf8.RuneCountInString(s.text)
		if w <= n {
			out = append(out, s)
			n -= w
			continue
		}
		out = append(out, seg{truncate(s.text, n), s.style})
		break
	}
	return out
}
