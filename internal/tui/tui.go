// Package tui is nobet's interactive terminal interface: live progress
// while hosts are scanned, then a browsable host list with findings.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/olgacveysel/nobet/internal/brand"
	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/keys"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
)

// Scanner runs a scan, calling report as each host finishes. i is the
// host's index in the names passed to Run. report is safe to call from
// several goroutines.
type Scanner func(report func(i int, r scan.HostResult))

// Run shows the TUI while scanner runs, and returns the results of every
// host that finished before the user quit. owners (may be nil) names the
// keys in the root access view.
func Run(names []string, owners *keys.Owners, scanner Scanner) ([]scan.HostResult, error) {
	m := model{
		owners:  owners,
		names:   names,
		results: make([]scan.HostResult, len(names)),
		done:    make([]bool, len(names)),
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	go func() {
		scanner(func(i int, r scan.HostResult) { p.Send(hostDoneMsg{i: i, res: r}) })
		p.Send(scanDoneMsg{})
	}()

	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	fm := final.(model)
	var out []scan.HostResult
	for i, d := range fm.done {
		if d {
			out = append(out, fm.results[i])
		}
	}
	return out, nil
}

type (
	hostDoneMsg struct {
		i   int
		res scan.HostResult
	}
	scanDoneMsg struct{}
	tickMsg     struct{}
)

type model struct {
	owners   *keys.Owners
	names    []string
	results  []scan.HostResult
	done     []bool
	ndone    int
	finished bool

	rootView bool            // showing the root access map instead of hosts
	cursor   int             // selected host
	scroll   int             // first visible line of the details pane
	minSev   checks.Severity // hide findings below this
	frame    int             // spinner frame

	width, height int
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var (
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Background(lipgloss.Color("24"))
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleCursor = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	styleAmber  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	stylePane   = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)
)

func sevStyle(s checks.Severity) lipgloss.Style {
	switch s {
	case checks.Critical:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	case checks.High:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("202"))
	case checks.Medium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	case checks.Low:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	}
	return styleDim
}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m model) Init() tea.Cmd { return tick() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		if m.finished {
			return m, nil
		}
		m.frame++
		return m, tick()
	case hostDoneMsg:
		m.results[msg.i] = msg.res
		if !m.done[msg.i] {
			m.done[msg.i] = true
			m.ndone++
		}
	case scanDoneMsg:
		m.finished = true
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.scroll = 0
			}
		case "down", "j":
			if m.cursor < len(m.names)-1 {
				m.cursor++
				m.scroll = 0
			}
		case "home", "g":
			m.cursor, m.scroll = 0, 0
		case "end", "G":
			m.cursor, m.scroll = len(m.names)-1, 0
		case "pgdown", "ctrl+d", " ":
			m.scroll += m.paneHeight() / 2
		case "pgup", "ctrl+u":
			m.scroll -= m.paneHeight() / 2
		case "f":
			m.minSev = (m.minSev + 1) % (checks.Critical + 1)
			m.scroll = 0
		case "r", "tab":
			m.rootView = !m.rootView
			m.scroll = 0
		}
		m.scroll = clamp(m.scroll, 0, m.maxScroll())
	}
	return m, nil
}

// Layout: one header line, two bordered panes, one footer line.
func (m model) paneHeight() int { return max(m.height-4, 3) }
func (m model) leftWidth() int  { return clamp(m.width/3, 22, 40) }
func (m model) rightWidth() int { return max(m.width-m.leftWidth()-4, 24) }

func (m model) maxScroll() int {
	if m.rootView {
		return max(len(m.rootLines(m.width-4))-m.paneHeight(), 0)
	}
	return max(len(m.detailLines(m.rightWidth()-2))-m.paneHeight(), 0)
}

func (m model) View() string {
	if m.width == 0 {
		return "starting…"
	}
	h := m.paneHeight()
	if m.rootView {
		w := max(m.width-2, 24)
		pane := stylePane.Width(w).Height(h).Render(m.scrolled(m.rootLines(w-2), h))
		return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), pane, m.footerView())
	}
	lw, rw := m.leftWidth(), m.rightWidth()

	left := stylePane.Width(lw).Height(h).Render(m.hostList(lw-2, h))
	right := stylePane.Width(rw).Height(h).Render(m.detailsView(rw-2, h))

	return lipgloss.JoinVertical(lipgloss.Left,
		m.headerView(),
		lipgloss.JoinHorizontal(lipgloss.Top, left, right),
		m.footerView(),
	)
}

func (m model) headerView() string {
	title := styleTitle.Render(" nöbet ")
	if !m.finished {
		return fmt.Sprintf("%s  scanning %d/%d hosts %s", title, m.ndone, len(m.names), spinner[m.frame%len(spinner)])
	}
	counts := map[checks.Severity]int{}
	unreachable := 0
	for i, r := range m.results {
		if !m.done[i] {
			continue
		}
		if r.Error != "" {
			unreachable++
		}
		for _, f := range r.Findings {
			counts[f.Severity]++
		}
	}
	parts := []string{fmt.Sprintf("%d hosts", len(m.names))}
	for _, s := range []checks.Severity{checks.Critical, checks.High, checks.Medium, checks.Low} {
		if counts[s] > 0 {
			parts = append(parts, sevStyle(s).Render(fmt.Sprintf("%d %s", counts[s], s)))
		}
	}
	if unreachable > 0 {
		parts = append(parts, sevStyle(checks.Critical).Render(fmt.Sprintf("%d unreachable", unreachable)))
	}
	return title + "  " + strings.Join(parts, styleDim.Render(" · "))
}

func (m model) footerView() string {
	filter := "all"
	if m.minSev > checks.Info {
		filter = m.minSev.String() + "+"
	}
	if m.rootView {
		return styleDim.Render(" pgup/pgdn scroll · r back to hosts · q quit")
	}
	return styleDim.Render(fmt.Sprintf(" ↑/↓ host · pgup/pgdn scroll · f filter: %s · r root access · q quit", filter))
}

// hostStatus returns the status icon and right-hand badge for host i.
func (m model) hostStatus(i int) (icon, badge string) {
	if !m.done[i] {
		return styleDim.Render(spinner[m.frame%len(spinner)]), ""
	}
	r := m.results[i]
	if r.Error != "" {
		return sevStyle(checks.Critical).Render("✗"), sevStyle(checks.Critical).Render("error")
	}
	worst, n := checks.Info, 0
	for _, f := range r.Findings {
		switch {
		case f.Severity > worst:
			worst, n = f.Severity, 1
		case f.Severity == worst:
			n++
		}
	}
	if worst == checks.Info {
		return styleOK.Render("✓"), styleDim.Render("ok")
	}
	st := sevStyle(worst)
	return st.Render("●"), st.Render(fmt.Sprintf("%d %s", n, worst))
}

func (m model) hostList(w, h int) string {
	start := 0
	if m.cursor >= h {
		start = m.cursor - h + 1
	}
	var lines []string
	for i := start; i < len(m.names) && i < start+h; i++ {
		icon, badge := m.hostStatus(i)
		marker, name := " ", m.names[i]
		nameMax := w - 3 - lipgloss.Width(badge) - 1
		name = truncate(name, nameMax)
		if i == m.cursor {
			marker, name = styleCursor.Render("›"), styleCursor.Render(name)
		}
		pad := max(w-3-lipgloss.Width(name)-lipgloss.Width(badge), 1)
		lines = append(lines, marker+icon+" "+name+strings.Repeat(" ", pad)+badge)
	}
	return strings.Join(lines, "\n")
}

func (m model) detailsView(w, h int) string {
	return m.scrolled(m.detailLines(w), h)
}

// scrolled returns the visible window of lines for the current scroll
// position, with a "more" marker when content continues below.
func (m model) scrolled(lines []string, h int) string {
	start := clamp(m.scroll, 0, max(len(lines)-h, 0))
	end := min(start+h, len(lines))
	visible := lines[start:end]
	if end < len(lines) && len(visible) > 0 {
		visible[len(visible)-1] = styleDim.Render(fmt.Sprintf("↓ %d more lines", len(lines)-end+1))
	}
	return strings.Join(visible, "\n")
}

// detailLines renders the selected host's details, wrapped to width w.
func (m model) detailLines(w int) []string {
	if len(m.names) == 0 || w < 10 {
		return nil
	}
	var lines []string
	add := func(s string, indent int) {
		block := lipgloss.NewStyle().Width(w).PaddingLeft(indent).Render(s)
		lines = append(lines, strings.Split(block, "\n")...)
	}

	i := m.cursor
	if !m.done[i] {
		// While the selected host is still being scanned, show the owl on watch.
		if w >= brand.Width()+2 {
			lines = append(lines, "")
			for _, l := range brand.Lines(tuiPainter) {
				lines = append(lines, " "+l)
			}
			lines = append(lines, "", " "+styleDim.Render("nöbet · "+brand.Tagline), "")
		}
		add(styleBold.Render(m.names[i]), 0)
		add(styleDim.Render("scanning "+spinner[m.frame%len(spinner)]), 0)
		return lines
	}
	add(styleBold.Render(m.names[i]), 0)

	r := m.results[i]
	if r.Error != "" {
		add(sevStyle(checks.Critical).Render("Could not scan: ")+r.Error, 0)
		return lines
	}

	meta := []string{}
	if r.OS != "" {
		meta = append(meta, r.OS)
	}
	if r.Local {
		meta = append(meta, "local")
	}
	if r.Privileged {
		meta = append(meta, "privileged")
	} else {
		meta = append(meta, sevStyle(checks.Medium).Render("not privileged: some checks skipped"))
	}
	meta = append(meta, fmt.Sprintf("%.1fs", float64(r.DurationMS)/1000))
	add(styleDim.Render(strings.Join(meta, " · ")), 0)
	lines = append(lines, "")

	shown, hidden := 0, 0
	for _, f := range r.Findings {
		if f.Severity < m.minSev {
			hidden++
			continue
		}
		shown++
		label := sevStyle(f.Severity).Render(fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String())))
		add(label+" "+styleDim.Render(f.CheckID)+"  "+f.Title, 0)
		if f.Detail != "" {
			add(f.Detail, 9)
		}
		if f.Fix != "" {
			add(styleOK.Render("fix: ")+f.Fix, 9)
		}
		lines = append(lines, "")
	}
	if shown == 0 {
		if len(r.Findings) == 0 {
			add(styleOK.Render("No findings."), 0)
		} else {
			add(styleDim.Render("No findings at this filter level."), 0)
		}
		lines = append(lines, "")
	}
	if hidden > 0 {
		add(styleDim.Render(fmt.Sprintf("%d finding(s) hidden by filter (press f)", hidden)), 0)
	}
	if n := len(r.Suppressed); n > 0 {
		add(styleDim.Render(fmt.Sprintf("%d finding(s) suppressed by the allowlist", n)), 0)
	}
	for _, s := range r.Skipped {
		add(styleDim.Render("skipped "+s.CheckID+": "+s.Reason), 0)
	}
	return lines
}

// rootLines renders the fleet-wide root access map for the hosts scanned
// so far, wrapped to width w.
func (m model) rootLines(w int) []string {
	if w < 10 {
		return nil
	}
	var lines []string
	add := func(s string, indent int) {
		block := lipgloss.NewStyle().Width(w).PaddingLeft(indent).Render(s)
		lines = append(lines, strings.Split(block, "\n")...)
	}
	routes := func(rs []rootmap.Route) string {
		parts := make([]string, len(rs))
		for i, r := range rs {
			parts[i] = r.Via
		}
		return strings.Join(parts, "; ")
	}

	var results []scan.HostResult
	for i, d := range m.done {
		if d {
			results = append(results, m.results[i])
		}
	}
	rm := rootmap.Build(results)
	if m.owners.Loaded() {
		rm.SetOwners(m.owners.Path, m.owners.Owner)
	}

	add(styleBold.Render("Root access by SSH key"), 0)
	if !m.finished {
		add(styleDim.Render(fmt.Sprintf("partial map: %d of %d hosts scanned so far", m.ndone, len(m.names))), 0)
	}
	lines = append(lines, "")
	if len(rm.Keys) == 0 {
		add(styleDim.Render("No SSH key leads to root on the scanned hosts."), 0)
		lines = append(lines, "")
	}
	for _, k := range rm.Keys {
		label := k.Label(rm.OwnersFile)
		add(styleCursor.Render(label), 0)
		n := k.Hosts()
		st := styleDim
		if n > 1 {
			st = sevStyle(checks.High)
		}
		add(st.Render(fmt.Sprintf("root on %d host(s)", n)), 2)
		for _, g := range k.Grants {
			line := fmt.Sprintf("%s  as %s  via %s", styleBold.Render(g.Host), g.User, routes(g.Routes))
			if g.Restricted != "" {
				line += styleDim.Render("  [" + g.Restricted + "]")
			}
			if l := g.LoginText(); l != "" {
				line += styleDim.Render("  (" + l + ")")
			}
			add(line, 4)
		}
		lines = append(lines, "")
	}
	if len(rm.KeylessUsers) > 0 {
		add(styleBold.Render("Root-capable accounts without SSH key access"), 0)
		for _, a := range rm.KeylessUsers {
			add(fmt.Sprintf("%s  %s  via %s", styleBold.Render(a.Host), a.User, routes(a.Routes)), 2)
		}
		lines = append(lines, "")
	}
	if len(rm.Gaps) > 0 {
		add(styleBold.Render("Incomplete"), 0)
		for _, g := range rm.Gaps {
			add(styleDim.Render(g.Host+": "+g.Reason), 2)
		}
	}
	return lines
}

func tuiPainter(s string, amber bool) string {
	if amber {
		return styleAmber.Render(s)
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 1 {
		return "…"
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		hi = lo
	}
	return max(lo, min(v, hi))
}
