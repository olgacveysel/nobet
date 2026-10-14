// Package brand holds nöbet's terminal logo: the owl perched on the "o",
// drawn with half-block characters so each terminal cell shows two square
// pixels.
package brand

import "strings"

// Tagline is shown under the logo.
const Tagline = "your servers' night watch"

// grid is the logo as pixels: '#' is the letter color (the terminal's
// default foreground, so it works on dark and light themes), 'o' is amber
// (the owl's eyes and beak), '.' is empty. Two pixel rows make one
// terminal row.
var grid = []string{
	".........##......##............................",
	"..........########.............................",
	".........##oo##oo##..##....................##..",
	".........##oo##oo##..##....................##..",
	"..........###oo###...##....................##..",
	".....................##....................##..",
	"######......####.....######.....#####....######",
	"#######....######....#######...#######...######",
	"##...##...##....##...##...##...##...##.....##..",
	"##...##...##....##...##...##...#######.....##..",
	"##...##...##....##...##...##...#######.....##..",
	"##...##...##....##...##...##...##..........##..",
	"##...##....######....#######...#######.....####",
	"##...##.....####.....######.....######......###",
}

// Width is the logo width in terminal columns.
func Width() int {
	w := 0
	for _, r := range grid {
		w = max(w, len(r))
	}
	return w
}

// Painter colors a run of logo text; amber is true for the owl's eyes and
// beak.
type Painter func(s string, amber bool) string

// ANSI paints amber runs with a 256-color escape code.
func ANSI(s string, amber bool) string {
	if !amber {
		return s
	}
	return "\x1b[38;5;214m" + s + "\x1b[0m"
}

// Lines renders the logo, one string per terminal row, without trailing
// spaces. With a nil painter the logo is monochrome and the eyes and beak
// are left as holes, which still reads as a face.
func Lines(paint Painter) []string {
	w := Width()
	at := func(row, x int) byte {
		if x < len(grid[row]) {
			return grid[row][x]
		}
		return '.'
	}

	var out []string
	for y := 0; y+1 < len(grid); y += 2 {
		type cell struct {
			ch    string
			amber bool
		}
		cells := make([]cell, w)
		for x := 0; x < w; x++ {
			t, b := at(y, x), at(y+1, x)
			amber := paint != nil && (t == 'o' || b == 'o')
			on := func(c byte) bool { return c == '#' || (c == 'o' && paint != nil) }
			var ch string
			switch {
			case on(t) && on(b):
				ch = "█"
			case on(t):
				ch = "▀"
			case on(b):
				ch = "▄"
			default:
				ch = " "
			}
			cells[x] = cell{ch, amber}
		}
		for len(cells) > 0 && cells[len(cells)-1].ch == " " {
			cells = cells[:len(cells)-1]
		}

		var line, run strings.Builder
		runAmber := false
		flush := func() {
			if run.Len() == 0 {
				return
			}
			if paint != nil {
				line.WriteString(paint(run.String(), runAmber))
			} else {
				line.WriteString(run.String())
			}
			run.Reset()
		}
		for _, c := range cells {
			if c.amber != runAmber {
				flush()
				runAmber = c.amber
			}
			run.WriteString(c.ch)
		}
		flush()
		out = append(out, line.String())
	}
	return out
}
