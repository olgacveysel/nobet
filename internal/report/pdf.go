package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/signintech/gopdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/sfnt"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
)

// A4 in points, and the layout inside it.
const (
	pageW, pageH = 595.0, 842.0
	margin       = 42.0
	contentW     = pageW - 2*margin
	pageBottom   = pageH - 58 // the footer sits below
)

const (
	fontRegular = "go"
	fontBold    = "go-bold"
	fontMono    = "go-mono"
)

type rgb struct{ r, g, b uint8 }

// Brand and severity colors, as in the HTML report.
var (
	colInk    = rgb{0x0B, 0x14, 0x26}
	colMuted  = rgb{0x5b, 0x65, 0x77}
	colLine   = rgb{0xe3, 0xe1, 0xda}
	colHead   = rgb{0xf4, 0xf2, 0xec}
	colAmber  = rgb{0xD9, 0x89, 0x0F}
	colOK     = rgb{0x2e, 0x7d, 0x4f}
	colWhite  = rgb{0xff, 0xff, 0xff}
	sevColors = map[string]rgb{
		"critical": {0xb3, 0x26, 0x1e}, "high": {0xd1, 0x54, 0x1b}, "medium": {0xb7, 0x79, 0x1f},
		"low": {0x2f, 0x6f, 0xb5}, "info": {0x6b, 0x72, 0x80}, "ok": colOK, "error": colInk,
	}
)

// pdfWriter lays text out top to bottom, starting new pages as needed.
type pdfWriter struct {
	pdf   *gopdf.GoPdf
	y     float64
	font  string
	size  float64
	color rgb
	has   func(rune) bool // whether the fonts have a glyph for the rune
	cont  string          // repeated at the top of a new page: the host whose findings go on
}

func newPDFWriter(meta HTMLMeta) (*pdfWriter, error) {
	p := &pdfWriter{pdf: &gopdf.GoPdf{}}
	p.pdf.Start(gopdf.Config{PageSize: *gopdf.PageSizeA4})
	for name, data := range map[string][]byte{fontRegular: goregular.TTF, fontBold: gobold.TTF, fontMono: gomono.TTF} {
		if err := p.pdf.AddTTFFontData(name, data); err != nil {
			return nil, err
		}
	}
	f, err := sfnt.Parse(goregular.TTF)
	if err != nil {
		return nil, err
	}
	var buf sfnt.Buffer
	p.has = func(r rune) bool {
		i, err := f.GlyphIndex(&buf, r)
		return err == nil && i != 0
	}
	p.pdf.SetInfo(gopdf.PdfInfo{
		Title: "nöbet security report", Author: "nöbet", Creator: "nöbet " + meta.Version,
		CreationDate: meta.Generated,
	})
	generated := meta.Generated.UTC().Format("2006-01-02 15:04 UTC")
	p.pdf.AddFooter(func() {
		p.pdf.SetStrokeColor(colLine.r, colLine.g, colLine.b)
		p.pdf.SetLineWidth(0.5)
		p.pdf.Line(margin, pageH-44, pageW-margin, pageH-44)
		p.pdf.SetFont(fontRegular, "", 7.5)
		p.pdf.SetTextColor(colMuted.r, colMuted.g, colMuted.b)
		p.pdf.SetXY(margin, pageH-38)
		p.pdf.Cell(nil, "nöbet security report · "+generated)
		page := "page " + strconv.Itoa(p.pdf.GetNumberOfPages())
		w, _ := p.pdf.MeasureTextWidth(page)
		p.pdf.SetXY(pageW-margin-w, pageH-38)
		p.pdf.Cell(nil, page)
	})
	p.newPage()
	return p, nil
}

func (p *pdfWriter) newPage() {
	p.pdf.AddPage()
	p.y = margin
	if p.cont != "" {
		font, size, color := p.font, p.size, p.color
		p.setFont(fontBold, 9, colMuted)
		p.text(margin, p.cont+" (continued)")
		p.y += 16
		p.setFont(font, size, color)
	} else if p.font != "" { // the footer changed the font and color
		p.setFont(p.font, p.size, p.color)
	}
}

func (p *pdfWriter) setFont(name string, size float64, c rgb) {
	p.font, p.size, p.color = name, size, c
	p.pdf.SetFont(name, "", size)
	p.pdf.SetTextColor(c.r, c.g, c.b)
}

// need starts a new page unless h more points fit on this one.
func (p *pdfWriter) need(h float64) {
	if p.y+h > pageBottom {
		p.newPage()
	}
}

// clean replaces what the fonts cannot draw.
func (p *pdfWriter) clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		case !p.has(r):
			return '?'
		}
		return r
	}, s)
}

// wrap splits s into lines no wider than width in the current font,
// breaking long words (paths, fingerprints) when they do not fit.
func (p *pdfWriter) wrap(s string, width float64) []string {
	var out []string
	for _, para := range strings.Split(p.clean(s), "\n") {
		if strings.TrimSpace(para) == "" {
			continue
		}
		lines, err := p.pdf.SplitTextWithWordWrap(para, width)
		if err != nil || len(lines) == 0 {
			lines, err = p.pdf.SplitText(para, width)
			if err != nil {
				lines = []string{para}
			}
		}
		for _, l := range lines {
			if w, _ := p.pdf.MeasureTextWidth(l); w > width {
				if parts, err := p.pdf.SplitText(l, width); err == nil {
					out = append(out, parts...)
					continue
				}
			}
			out = append(out, l)
		}
	}
	return out
}

// text writes one line at x on the current line, without moving down.
func (p *pdfWriter) text(x float64, s string) {
	p.pdf.SetXY(x, p.y)
	p.pdf.Cell(nil, p.clean(s))
}

// para writes wrapped text at x, moving down line by line.
func (p *pdfWriter) para(x, width, lineH float64, s string) {
	for _, l := range p.wrap(s, width) {
		p.need(lineH)
		p.pdf.SetXY(x, p.y)
		p.pdf.Cell(nil, l)
		p.y += lineH
	}
}

// fit shortens s with an ellipsis to fit width in the current font.
func (p *pdfWriter) fit(s string, width float64) string {
	s = p.clean(s)
	if w, _ := p.pdf.MeasureTextWidth(s); w <= width {
		return s
	}
	r := []rune(s)
	for len(r) > 1 {
		r = r[:len(r)-1]
		if w, _ := p.pdf.MeasureTextWidth(string(r) + "…"); w <= width {
			return string(r) + "…"
		}
	}
	return "…"
}

func (p *pdfWriter) fill(c rgb, x, y, w, h float64) {
	p.pdf.SetFillColor(c.r, c.g, c.b)
	p.pdf.RectFromUpperLeftWithStyle(x, y, w, h, "F")
}

func (p *pdfWriter) rule(y float64) {
	p.pdf.SetStrokeColor(colLine.r, colLine.g, colLine.b)
	p.pdf.SetLineWidth(0.6)
	p.pdf.Line(margin, y, pageW-margin, y)
}

// pill draws a severity label at x on the current line.
func (p *pdfWriter) pill(x float64, sev string, w float64) {
	p.fill(sevColors[sev], x, p.y-2.5, w, 11.5) // text is drawn from its top, so the box starts above it
	font, size, color := p.font, p.size, p.color
	p.setFont(fontBold, 6.8, colWhite)
	label := strings.ToUpper(sev)
	tw, _ := p.pdf.MeasureTextWidth(label)
	p.text(x+(w-tw)/2, label)
	p.setFont(font, size, color)
}

// sortedFindings returns findings worst first, keeping check order within
// a severity.
func sortedFindings(fs []checks.Finding) []checks.Finding {
	out := append([]checks.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

func (p *pdfWriter) heading(s string) {
	p.need(60)
	p.y += 14
	p.setFont(fontBold, 15, colInk)
	p.text(margin, s)
	p.y += 22
}

// PDF writes the report as an A4 PDF: the same content as the HTML report,
// for auditors who want a file to archive or print.
func PDF(w io.Writer, results []scan.HostResult, meta HTMLMeta) error {
	d := buildData(results, meta)
	p, err := newPDFWriter(meta)
	if err != nil {
		return err
	}

	// Title.
	p.setFont(fontBold, 24, colInk)
	p.text(margin, "nöbet")
	nw, _ := p.pdf.MeasureTextWidth("nöbet ")
	p.setFont(fontRegular, 24, colMuted)
	p.text(margin+nw, "security report")
	p.y += 32
	p.setFont(fontRegular, 9, colMuted)
	p.text(margin, fmt.Sprintf("Generated %s · nöbet %s · %d host(s) · read-only scan of SSH, sudo, accounts, network, updates and files",
		meta.Generated.UTC().Format("2006-01-02 15:04 UTC"), meta.Version, len(d.Hosts)))
	p.y += 14
	p.rule(p.y)
	p.y += 16

	// Summary tiles.
	tiles := []struct {
		label string
		n     int
		c     rgb
	}{
		{"critical", d.Totals["critical"], sevColors["critical"]}, {"high", d.Totals["high"], sevColors["high"]},
		{"medium", d.Totals["medium"], sevColors["medium"]}, {"low", d.Totals["low"], sevColors["low"]},
		{"unreachable", d.Failed, colInk}, {"allowlisted", d.Allowed, colMuted},
	}
	const gap = 8.0
	tw := (contentW - gap*float64(len(tiles)-1)) / float64(len(tiles))
	for i, t := range tiles {
		x := margin + float64(i)*(tw+gap)
		p.fill(colHead, x, p.y, tw, 46)
		p.fill(t.c, x, p.y, 3, 46)
		saveY := p.y
		p.y += 8
		p.setFont(fontBold, 18, t.c)
		p.text(x+10, strconv.Itoa(t.n))
		p.y += 22
		p.setFont(fontRegular, 7, colMuted)
		p.text(x+10, strings.ToUpper(t.label))
		p.y = saveY
	}
	p.y += 62

	// Hosts table.
	p.heading("Hosts")
	cols := []struct {
		title string
		w     float64
	}{{"Host", 150}, {"Operating system", 156}, {"Status", 65}, {"Crit", 36}, {"High", 36}, {"Med", 36}, {"Low", 36}}
	header := func() {
		p.fill(colHead, margin, p.y-3, contentW, 16)
		p.setFont(fontBold, 7.5, colMuted)
		x := margin + 6
		for _, c := range cols {
			p.text(x, strings.ToUpper(c.title))
			x += c.w
		}
		p.y += 17
	}
	header()
	for _, h := range d.Hosts {
		if p.y+16 > pageBottom {
			p.newPage()
			header()
		}
		x := margin + 6
		p.setFont(fontBold, 8.5, colInk)
		p.text(x, p.fit(h.Host, cols[0].w-8))
		x += cols[0].w
		p.setFont(fontRegular, 8.5, colMuted)
		os := h.OS
		if h.Error != "" {
			os = "not scanned"
		}
		p.text(x, p.fit(os, cols[1].w-8))
		x += cols[1].w
		p.setFont(fontRegular, 8.5, colInk)
		p.pill(x, h.Worst, 54)
		x += cols[2].w
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			n := h.Counts[sev]
			c := colMuted
			if n > 0 {
				c = sevColors[sev]
			}
			p.setFont(fontBold, 8.5, c)
			p.text(x, strconv.Itoa(n))
			x += 36
		}
		p.y += 14
		p.rule(p.y - 3)
	}

	// Findings per host.
	p.heading("Findings")
	for i, h := range d.Hosts {
		if i > 0 {
			p.y += 6
		}
		p.cont = ""
		p.need(48)
		p.setFont(fontBold, 12, colInk)
		p.text(margin, h.Host)
		p.y += 16
		p.cont = h.Host
		p.setFont(fontRegular, 8.5, colMuted)
		sub := h.OS
		if h.Privileged {
			sub += " · scanned with root"
		} else if h.Error == "" {
			sub += " · scanned without root: some checks were skipped"
		}
		if h.Error != "" {
			p.setFont(fontBold, 8.5, sevColors["critical"])
			p.para(margin, contentW, 11, "Not scanned: "+h.Error)
			continue
		}
		p.para(margin, contentW, 11, strings.TrimPrefix(sub, " · "))
		p.y += 4
		if len(h.Findings) == 0 {
			p.setFont(fontRegular, 9, colOK)
			p.para(margin, contentW, 12, "No findings.")
		}
		for _, f := range sortedFindings(h.Findings) {
			p.setFont(fontRegular, 8.5, colInk)
			detail := p.wrap(f.Detail, contentW-66)
			p.need(16 + 11*float64(min(len(detail), 3)))
			p.pill(margin, f.Severity.String(), 56)
			p.setFont(fontBold, 9.5, colInk)
			titleLines := p.wrap(f.CheckID+"  "+f.Title, contentW-66)
			for j, l := range titleLines {
				if j > 0 {
					p.need(12)
				}
				p.text(margin+66, l)
				p.y += 12.5
			}
			if f.Detail != "" {
				p.setFont(fontRegular, 8.5, colInk)
				p.para(margin+66, contentW-66, 11, f.Detail)
			}
			if f.Fix != "" {
				p.setFont(fontRegular, 8.5, colOK)
				p.para(margin+66, contentW-66, 11, "Fix: "+f.Fix)
			}
			p.y += 5
		}
		if len(h.Suppressed) > 0 {
			var parts []string
			for _, s := range h.Suppressed {
				part := s.CheckID + " " + s.Title
				if s.Reason != "" {
					part += " (" + s.Reason + ")"
				}
				parts = append(parts, part)
			}
			p.setFont(fontRegular, 8, colMuted)
			p.para(margin, contentW, 10.5, "Allowlisted: "+strings.Join(parts, "; "))
		}
		if len(h.Skipped) > 0 {
			var parts []string
			for _, s := range h.Skipped {
				parts = append(parts, s.CheckID+" ("+s.Reason+")")
			}
			p.setFont(fontRegular, 8, colMuted)
			p.para(margin, contentW, 10.5, "Skipped: "+strings.Join(parts, "; "))
		}
		p.y += 4
		p.rule(p.y)
		p.y += 8
	}

	p.cont = ""
	if d.HasRoot {
		p.rootMap(d.Root)
	}
	_, err = p.pdf.WriteTo(w)
	return err
}

// rootMap writes the root access map: SSH keys with the hosts they open,
// then accounts without key access, then what kept the map incomplete.
func (p *pdfWriter) rootMap(m rootmap.Map) {
	p.heading("Root access map")
	p.setFont(fontRegular, 8.5, colMuted)
	p.para(margin, contentW, 11, "Who can become root on which host, and how, grouped by SSH key.")
	if n := len(m.Unclaimed()); n > 0 {
		p.setFont(fontBold, 8.5, colAmber)
		p.para(margin, contentW, 11, fmt.Sprintf("%d key(s) with root access have no owner in the keys file.", n))
	}
	p.y += 4
	if len(m.Keys) == 0 {
		p.setFont(fontRegular, 9, colInk)
		p.para(margin, contentW, 12, "No SSH key leads to root on the scanned hosts.")
	}
	for _, k := range m.Keys {
		p.need(40)
		p.setFont(fontMono, 8.5, colInk)
		p.para(margin, contentW, 11, k.Label(m.OwnersFile))
		p.setFont(fontRegular, 8, colMuted)
		p.para(margin, contentW, 10.5, fmt.Sprintf("root on %d host(s)", k.Hosts()))
		for _, g := range k.Grants {
			line := g.Host + "  as " + g.User + "  via " + routeVia(g.Routes)
			if g.Restricted != "" {
				line += "  [" + g.Restricted + "]"
			}
			if l := g.LoginText(); l != "" {
				line += "  (" + l + ")"
			}
			p.setFont(fontRegular, 8.5, colInk)
			p.para(margin+12, contentW-12, 11, line)
		}
		p.y += 6
	}
	if len(m.KeylessUsers) > 0 {
		p.need(30)
		p.setFont(fontBold, 10, colInk)
		p.para(margin, contentW, 14, "Root-capable accounts without SSH key access")
		for _, a := range m.KeylessUsers {
			p.setFont(fontRegular, 8.5, colInk)
			p.para(margin+12, contentW-12, 11, a.Host+"  "+a.User+"  via "+routeVia(a.Routes))
		}
		p.y += 6
	}
	if len(m.Gaps) > 0 {
		p.need(30)
		p.setFont(fontBold, 10, colInk)
		p.para(margin, contentW, 14, "Incomplete")
		for _, g := range m.Gaps {
			p.setFont(fontRegular, 8, colMuted)
			p.para(margin+12, contentW-12, 10.5, g.Host+": "+g.Reason)
		}
	}
}

func routeVia(rs []rootmap.Route) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.Via
	}
	return strings.Join(parts, "; ")
}
