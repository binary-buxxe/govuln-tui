package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── govulncheck JSON types ────────────────────────────────────────────────────

type Message struct {
	MessageType string    `json:"message_type"`
	Config      *Config   `json:"config,omitempty"`
	Progress    *Progress `json:"progress,omitempty"`
	OSV         *OSVEntry `json:"osv,omitempty"`
	Finding     *Finding  `json:"finding,omitempty"`
}

type Config struct {
	ProtocolVersion string `json:"protocol_version"`
	GoVersion       string `json:"go_version"`
	GoVulncheck     struct {
		Version string `json:"version"`
	} `json:"govulncheck"`
}

type Progress struct {
	Message string `json:"message"`
}

type OSVEntry struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []OSVAffected `json:"affected"`
}

type OSVAffected struct {
	Ranges []OSVRange `json:"ranges"`
}

type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

type Finding struct {
	OSVId        string  `json:"osv"`
	Trace        []Frame `json:"trace"`
	FixedVersion string  `json:"fixed_version,omitempty"`
}

type Frame struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Position *Pos   `json:"position,omitempty"`
}

type Pos struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// ── aggregated vulnerability ──────────────────────────────────────────────────

type Tier int

const (
	TierCalled  Tier = iota // finding with full call stack into user code
	TierPackage             // finding at package level, no user call stack
	TierModule              // finding at module level only
	TierOSVOnly             // OSV emitted but no findings at all
)

func (t Tier) Label() string {
	switch t {
	case TierCalled:
		return "called"
	case TierPackage:
		return "package"
	case TierModule:
		return "module"
	default:
		return "info"
	}
}

type Vuln struct {
	ID       string
	OSV      *OSVEntry
	Findings []Finding
	Tier     Tier
}

func (v *Vuln) fixedVersion() string {
	if len(v.Findings) > 0 && v.Findings[0].FixedVersion != "" {
		return v.Findings[0].FixedVersion
	}
	// Fall back to OSV affected ranges
	if v.OSV != nil {
		for _, a := range v.OSV.Affected {
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	return "unknown"
}

func (v *Vuln) summary() string {
	if v.OSV != nil && v.OSV.Summary != "" {
		return v.OSV.Summary
	}
	return v.ID
}

// module returns the short name of the vulnerable module extracted from findings.
// For called/package/module-tier vulns the first trace frame carries the module.
// Falls back to OSV affected packages if no findings exist.
func (v *Vuln) module() string {
	for _, f := range v.Findings {
		if len(f.Trace) > 0 && f.Trace[0].Module != "" {
			return shortModule(f.Trace[0].Module)
		}
	}
	return ""
}

// ── scan result ───────────────────────────────────────────────────────────────

type ScanResult struct {
	Vulns    []*Vuln
	Err      error
	Progress string
}

// ── messages ──────────────────────────────────────────────────────────────────

type scanDoneMsg ScanResult
type progressMsg string
type windowSizeMsg struct{ w, h int }

// ── styles ────────────────────────────────────────────────────────────────────

var (
	styleNormal   = lipgloss.NewStyle().Padding(0, 1)
	styleSelected = lipgloss.NewStyle().Padding(0, 1).
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230")).
		Bold(true)
	stylePaneTitle = lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("205")).
		Padding(0, 1)
	stylePaneBorder = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240"))
	styleDetail = lipgloss.NewStyle().Padding(0, 1)
	styleLabel  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
	styleHelp   = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Padding(0, 1)
	styleFilter = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("205")).
		Padding(0, 1)
	styleTierCalled    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // red
	styleTierPackage   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true) // orange
	styleTierModule    = lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true) // yellow
	styleTierOSV       = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Bold(true) // grey
	styleInformational = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleModuleTag     = lipgloss.NewStyle().Foreground(lipgloss.Color("39")) // cyan
)

// ── model ─────────────────────────────────────────────────────────────────────

type state int

const (
	stateLoading state = iota
	stateList
	stateFilter
	stateHelp
)

type model struct {
	packages []string
	ignored  map[string]bool

	width, height int

	st         state
	vulns      []*Vuln // all non-ignored
	filtered   []*Vuln // after filter applied
	cursor     int
	listOffset int // first visible row index
	filter     string
	filterBuf  string

	progress string
	err      error
}

func initialModel(packages []string, ignored map[string]bool) model {
	return model{
		packages: packages,
		ignored:  ignored,
		st:       stateLoading,
	}
}

func (m model) Init() tea.Cmd {
	return runScan(m.packages)
}

// ── update ────────────────────────────────────────────────────────────────────

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case progressMsg:
		m.progress = string(msg)

	case scanDoneMsg:
		res := ScanResult(msg)
		m.err = res.Err
		m.vulns = filterIgnored(res.Vulns, m.ignored)
		m.filtered = applyFilter(m.vulns, m.filter)
		m.cursor = 0
		m.listOffset = 0
		m.st = stateList

	case tea.KeyMsg:
		switch m.st {
		case stateLoading:
			if msg.String() == "q" || msg.String() == "ctrl+c" {
				return m, tea.Quit
			}

		case stateList:
			switch msg.String() {
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
					m.listOffset = clampOffset(m.listOffset, m.cursor, m.visibleRows())
				}
			case "down", "j":
				if m.cursor < len(m.filtered)-1 {
					m.cursor++
					m.listOffset = clampOffset(m.listOffset, m.cursor, m.visibleRows())
				}
			case "r":
				m.st = stateLoading
				m.progress = "rescanning…"
				return m, runScan(m.packages)
			case "/":
				m.st = stateFilter
				m.filterBuf = m.filter
			case "?":
				m.st = stateHelp
			}

		case stateHelp:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "q", "esc", "?":
				m.st = stateList
			}

		case stateFilter:
			switch msg.String() {
			case "enter":
				m.filter = m.filterBuf
				m.st = stateList
			case "esc":
				m.filterBuf = m.filter
				m.filtered = applyFilter(m.vulns, m.filter)
				m.cursor = 0
				m.listOffset = 0
				m.st = stateList
			case "ctrl+c":
				return m, tea.Quit
			case "ctrl+u":
				m.filterBuf = ""
				m.filtered = applyFilter(m.vulns, "")
				m.cursor = 0
				m.listOffset = 0
			case "backspace", "ctrl+h":
				if len(m.filterBuf) > 0 {
					runes := []rune(m.filterBuf)
					m.filterBuf = string(runes[:len(runes)-1])
					m.filtered = applyFilter(m.vulns, m.filterBuf)
					m.cursor = 0
					m.listOffset = 0
				}
			default:
				// Use msg.String() — it returns the single character for printable keys
				s := msg.String()
				if len([]rune(s)) == 1 {
					m.filterBuf += s
					m.filtered = applyFilter(m.vulns, m.filterBuf)
					m.cursor = 0
					m.listOffset = 0
				}
			}
		}
	}

	return m, nil
}

// ── view ──────────────────────────────────────────────────────────────────────

func (m model) View() string {
	if m.width == 0 {
		return "initialising…"
	}
	if m.height < 12 || m.width < 60 {
		return fmt.Sprintf("\n  Terminal too small (%dx%d). Resize to at least 60×12.", m.width, m.height)
	}

	if m.st == stateLoading {
		return fmt.Sprintf("\n  Running govulncheck…\n\n  %s\n", m.progress)
	}

	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n  Press q to quit, r to retry.\n", m.err)
	}

	if m.st == stateHelp {
		return m.renderHelp()
	}

	var helpText string
	if m.st == stateFilter {
		helpText = styleHelp.Render("type to filter  enter confirm  esc cancel  ctrl+u clear")
	} else {
		helpText = styleHelp.Render("↑/↓ j/k move  r rescan  / filter  ? help  q quit")
	}

	// filter box is 3 lines tall (border top + content + border bottom)
	filterBoxH := 0
	if m.st == stateFilter {
		filterBoxH = 3
	}
	paneH := m.height - 1 - filterBoxH - 2

	leftW := m.width / 3
	rightW := m.width - leftW - 1

	left := m.renderLeft(leftW, paneH)
	right := m.renderRight(rightW, paneH)

	panes := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	if m.st == stateFilter {
		filterBox := styleFilter.Width(leftW - 4).Render("Filter: " + m.filterBuf + "█")
		return lipgloss.JoinVertical(lipgloss.Left, panes, filterBox, helpText)
	}

	return lipgloss.JoinVertical(lipgloss.Left, panes, helpText)
}

func (m model) renderLeft(w, h int) string {
	counts := [4]int{}
	for _, v := range m.filtered {
		counts[v.Tier]++
	}
	// w includes the border (1 each side); inner content width = w - 2.
	// Rows have Padding(0,1) so row content must fit in w - 2 - 2 = w - 4.
	innerW := w - 4
	if innerW < 1 {
		innerW = 1
	}

	// Title — single line, truncated hard to innerW runes
	titleStr := fmt.Sprintf("Vulns  %d called  %d pkg  %d mod  %d info",
		counts[TierCalled], counts[TierPackage], counts[TierModule], counts[TierOSVOnly])
	if m.filter != "" {
		titleStr += fmt.Sprintf("  [%s]", m.filter)
	}
	titleRunes := []rune(titleStr)
	if len(titleRunes) > innerW {
		titleStr = string(titleRunes[:max(0, innerW-1)]) + "…"
	}
	title := stylePaneTitle.Render(titleStr)

	var rows []string
	for i, v := range m.filtered {
		mod := v.module()
		idPart := tierIDStyle(v.Tier).Render(v.ID)
		var modPart string
		if mod != "" {
			modPart = styleModuleTag.Render(mod) + "  "
		}
		// Measure the rendered prefix to get exact budget for summary
		prefix := idPart + "  " + modPart
		prefixW := lipgloss.Width(prefix)
		sumBudget := innerW - prefixW
		if sumBudget < 1 {
			sumBudget = 1
		}

		sum := v.summary()
		sumRunes := []rune(sum)
		if len(sumRunes) > sumBudget {
			sum = string(sumRunes[:max(0, sumBudget-1)]) + "…"
		}

		var line string
		if v.Tier == TierOSVOnly {
			line = prefix + styleInformational.Render(sum)
		} else {
			line = prefix + sum
		}

		// Width(innerW+2): Padding(0,1) takes 2 chars, so content area = innerW.
		// line is innerW wide → fits exactly, no wrapping.
		if i == m.cursor {
			rows = append(rows, styleSelected.Width(innerW+2).Render(line))
		} else {
			rows = append(rows, styleNormal.Width(innerW+2).Render(line))
		}
	}

	if len(rows) == 0 {
		rows = append(rows, styleNormal.Render("No vulnerabilities found."))
	}

	visH := m.visibleRows()
	offset := m.listOffset
	end := offset + visH
	if end > len(rows) {
		end = len(rows)
	}
	if offset > end {
		offset = end
	}
	visible := rows[offset:end]

	content := title + "\n" + strings.Join(visible, "\n")
	// MaxHeight(h) clips the pane so it never exceeds the allocated height,
	// preventing JoinHorizontal from inflating the left pane beyond terminal height.
	pane := stylePaneBorder.Width(w - 2).MaxHeight(h).Render(content)
	return pane
}

func (m model) renderRight(w, h int) string {
	title := stylePaneTitle.Render("Details")

	if len(m.filtered) == 0 {
		return stylePaneBorder.Width(w - 2).MaxHeight(h).Render(
			lipgloss.JoinVertical(lipgloss.Left, title, styleDetail.Render("Select a vulnerability.")),
		)
	}

	v := m.filtered[m.cursor]
	innerW := w - 6

	var sb strings.Builder

	writeLine := func(label, val string) {
		sb.WriteString(styleLabel.Render(label))
		sb.WriteString("\n")
		sb.WriteString(styleDetail.Width(innerW).Render(val))
		sb.WriteString("\n\n")
	}

	writeLine("OSV ID", v.ID)
	writeLine("Summary", v.summary())
	writeLine("Fixed Version", v.fixedVersion())
	switch v.Tier {
	case TierCalled:
		writeLine("Status", fmt.Sprintf("Called — your code has a call stack reaching the vulnerable symbol (%d trace(s))", len(v.Findings)))
	case TierPackage:
		writeLine("Status", "Package — you import the affected package but don't call the vulnerable symbol")
	case TierModule:
		writeLine("Status", "Module — the module is in go.mod but you don't import the affected package")
	default:
		writeLine("Status", "Informational — in vulnerability DB; not found in your dependency graph")
	}

	if v.OSV != nil && v.OSV.Details != "" {
		details := v.OSV.Details
		if len(details) > 400 {
			details = details[:397] + "…"
		}
		writeLine("Details", details)
	}

	// Call traces — show up to 3 findings
	sb.WriteString(styleLabel.Render("Call Traces"))
	sb.WriteString("\n")
	shown := v.Findings
	if len(shown) > 3 {
		shown = shown[:3]
	}
	for fi, f := range shown {
		sb.WriteString(styleDetail.Render(fmt.Sprintf("Finding %d:", fi+1)))
		sb.WriteString("\n")
		for _, fr := range f.Trace {
			sb.WriteString(renderFrame(fr, innerW))
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	if len(v.Findings) > 3 {
		sb.WriteString(styleDetail.Render(fmt.Sprintf("… and %d more findings", len(v.Findings)-3)))
		sb.WriteString("\n")
	}

	pane := stylePaneBorder.Width(w - 2).MaxHeight(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, title, sb.String()),
	)
	return pane
}

func (m model) renderHelp() string {
	styleHelpTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205")).Padding(0, 1)
	styleHelpBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("205")).
		Padding(1, 3)
	styleKey := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))

	var b strings.Builder

	b.WriteString(styleHelpTitle.Render("Color Legend"))
	b.WriteString("\n\n")

	writeLegend := func(dot lipgloss.Style, label, desc string) {
		b.WriteString(dot.Render("●  " + label))
		b.WriteString("  " + desc + "\n")
	}
	writeLegend(styleTierCalled, "Called   ", "your code calls the vulnerable function — fix immediately")
	writeLegend(styleTierPackage, "Package  ", "you import the package but don't call the vulnerable symbol")
	writeLegend(styleTierModule, "Module   ", "module is in go.mod but you don't import the affected package")
	writeLegend(styleTierOSV, "Info     ", "in the OSV database; not found in your dependency graph")
	writeLegend(styleModuleTag, "cyan tag ", "the vulnerable module / library name")

	b.WriteString("\n")
	b.WriteString(styleHelpTitle.Render("Keyboard Shortcuts"))
	b.WriteString("\n\n")

	writeShortcut := func(keys, desc string) {
		b.WriteString(styleKey.Render(fmt.Sprintf("%-16s", keys)))
		b.WriteString(desc + "\n")
	}
	writeShortcut("↑ / ↓  j / k", "navigate list")
	writeShortcut("/", "filter vulnerabilities")
	writeShortcut("r", "rescan")
	writeShortcut("?", "toggle this help")
	writeShortcut("q / esc", "quit")

	b.WriteString("\n")
	b.WriteString(styleHelp.Render("press ? or esc to close"))

	content := styleHelpBox.Render(b.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

func renderFrame(f Frame, maxW int) string {
	var parts []string
	if f.Function != "" {
		parts = append(parts, f.Function)
	} else if f.Package != "" {
		parts = append(parts, f.Package)
	} else if f.Module != "" {
		parts = append(parts, f.Module+"@"+f.Version)
	}
	if f.Position != nil {
		parts = append(parts, fmt.Sprintf("%s:%d", f.Position.Filename, f.Position.Line))
	}
	line := "  → " + strings.Join(parts, " ")
	if len(line) > maxW {
		line = line[:maxW-1] + "…"
	}
	return styleDetail.Render(line)
}

// ── scan command ──────────────────────────────────────────────────────────────

// govulncheck -format json emits a stream of pretty-printed JSON objects
// (one object per message, separated by newlines but NOT one-per-line).
// json.Decoder handles this correctly; bufio line scanning does not.
func runScan(packages []string) tea.Cmd {
	return func() tea.Msg {
		args := []string{"-format", "json"}
		if len(packages) > 0 {
			args = append(args, packages...)
		} else {
			args = append(args, "./...")
		}

		cmd := exec.Command("govulncheck", args...)
		stdout, err := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if err != nil {
			return scanDoneMsg{Err: err}
		}
		if err := cmd.Start(); err != nil {
			return scanDoneMsg{Err: fmt.Errorf("govulncheck not found: %w", err)}
		}

		osvMap := map[string]*OSVEntry{}
		osvOrder := []string{} // preserve OSV arrival order
		findingsMap := map[string][]Finding{}

		dec := json.NewDecoder(stdout)
		for dec.More() {
			var raw map[string]json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				break
			}
			if v, ok := raw["osv"]; ok {
				var entry OSVEntry
				if json.Unmarshal(v, &entry) == nil && entry.ID != "" {
					if _, seen := osvMap[entry.ID]; !seen {
						osvOrder = append(osvOrder, entry.ID)
					}
					osvMap[entry.ID] = &entry
				}
			}
			if v, ok := raw["finding"]; ok {
				var f Finding
				if json.Unmarshal(v, &f) == nil && f.OSVId != "" {
					findingsMap[f.OSVId] = append(findingsMap[f.OSVId], f)
				}
			}
		}

		_ = cmd.Wait()

		// Build vulns ordered: called → package → module → osv-only
		seen := map[string]bool{}
		var vulns []*Vuln

		for id, findings := range findingsMap {
			seen[id] = true
			vulns = append(vulns, &Vuln{
				ID:       id,
				OSV:      osvMap[id],
				Findings: findings,
				Tier:     computeTier(findings),
			})
		}
		for _, id := range osvOrder {
			if !seen[id] {
				vulns = append(vulns, &Vuln{
					ID:   id,
					OSV:  osvMap[id],
					Tier: TierOSVOnly,
				})
			}
		}

		// Sort: called < package < module < osv-only
		sortVulns(vulns)

		return scanDoneMsg{Vulns: vulns}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// visibleRows returns the number of list rows that fit in the left pane.
// 4 = 2 border lines + 1 title line + 1 safety margin for potential title wrap.
func (m model) visibleRows() int {
	paneH := m.height - 1 - 2 // mirror View() paneH calculation (no filter)
	v := paneH - 4
	if v < 1 {
		return 1
	}
	return v
}

// shortModule trims common host prefixes so module names fit in the list.
//
//	stdlib                                    → stdlib
//	github.com/foo/bar                        → foo/bar
//	golang.org/x/net                          → x/net
//	dev.azure.com/org/repo/_git/service.git   → service
func shortModule(m string) string {
	if m == "stdlib" {
		return "stdlib"
	}
	// strip known host prefixes
	for _, pfx := range []string{
		"dev.azure.com/",
		"github.com/",
		"golang.org/x/",
		"google.golang.org/",
		"go.uber.org/",
	} {
		if after, ok := strings.CutPrefix(m, pfx); ok {
			m = after
			break
		}
	}
	// for azure paths like org/repo/_git/name.git → keep only name
	if idx := strings.Index(m, "/_git/"); idx != -1 {
		m = m[idx+6:]
	}
	m = strings.TrimSuffix(m, ".git")
	// strip /vN version suffix
	if idx := strings.LastIndex(m, "/v"); idx != -1 {
		if tail := m[idx+2:]; tail != "" && tail == strings.TrimLeft(tail, "0123456789") == false {
			m = m[:idx]
		}
	}
	return m
}

func clampOffset(offset, cursor, visH int) int {
	if cursor < offset {
		return cursor
	}
	if cursor >= offset+visH {
		return cursor - visH + 1
	}
	return offset
}

func tierIDStyle(t Tier) lipgloss.Style {
	switch t {
	case TierCalled:
		return styleTierCalled
	case TierPackage:
		return styleTierPackage
	case TierModule:
		return styleTierModule
	default:
		return styleTierOSV
	}
}

// computeTier picks the highest-severity tier across all findings for an OSV.
// govulncheck emits one finding per granularity level (module, package, symbol)
// so we pick the most specific one present.
func computeTier(findings []Finding) Tier {
	best := TierModule
	for _, f := range findings {
		hasFunc := false
		hasPkg := false
		for _, fr := range f.Trace {
			if fr.Function != "" {
				hasFunc = true
			}
			if fr.Package != "" {
				hasPkg = true
			}
		}
		var t Tier
		switch {
		case hasFunc:
			t = TierCalled
		case hasPkg:
			t = TierPackage
		default:
			t = TierModule
		}
		if t < best {
			best = t
		}
	}
	return best
}

func sortVulns(vulns []*Vuln) {
	// stable sort by tier so called vulns always appear first
	n := len(vulns)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && vulns[j].Tier < vulns[j-1].Tier; j-- {
			vulns[j], vulns[j-1] = vulns[j-1], vulns[j]
		}
	}
}

func filterIgnored(vulns []*Vuln, ignored map[string]bool) []*Vuln {
	var out []*Vuln
	for _, v := range vulns {
		if !ignored[v.ID] {
			out = append(out, v)
		}
	}
	return out
}

func applyFilter(vulns []*Vuln, q string) []*Vuln {
	if q == "" {
		return vulns
	}
	q = strings.ToLower(q)
	var out []*Vuln
	for _, v := range vulns {
		if strings.Contains(strings.ToLower(v.ID), q) ||
			strings.Contains(strings.ToLower(v.summary()), q) {
			out = append(out, v)
		}
	}
	return out
}

func loadIgnoreFile() map[string]bool {
	ignored := map[string]bool{}
	f, err := os.Open(".govulnignore")
	if err != nil {
		return ignored
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "GO-") {
			ignored[line] = true
		}
	}
	return ignored
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	packages := os.Args[1:]
	ignored := loadIgnoreFile()

	p := tea.NewProgram(
		initialModel(packages, ignored),
		tea.WithAltScreen(),
	)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
