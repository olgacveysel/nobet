// Package web is nobet-web: a read-only dashboard over the scan history
// that `nobet scan` saves. It never scans, never connects to servers and
// never holds SSH credentials; scans run elsewhere (for example from a
// systemd timer under a service account) and write to a history directory
// that this only reads. It has no login of its own: it listens on
// localhost and is meant to sit behind a reverse proxy that authenticates.
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olgacveysel/nobet/internal/keys"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
)

//go:embed templates/*.tmpl static/*
var files embed.FS

// Options configures a Server.
type Options struct {
	HistoryDir string        // where `nobet scan` saves scans
	Version    string        // shown in the footer
	StaleAfter time.Duration // hosts without a successful scan for this long are flagged
	UserHeader string        // header an authenticating proxy sets to the user name; logged only
	KeysFile   string        // names the owners of SSH keys on the root page; read on each view, "" for none
	Metrics    bool          // serve /metrics in the Prometheus text format
	Log        *log.Logger   // request log; nil for none
	Now        func() time.Time
}

// Server serves the dashboard.
type Server struct {
	opts  Options
	pages map[string]*template.Template

	mu  sync.Mutex
	sig string
	ix  *index
}

// New prepares a server. Nothing is read until the first request.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.StaleAfter <= 0 {
		opts.StaleAfter = 48 * time.Hour
	}
	s := &Server{opts: opts, pages: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"ago":    func(t time.Time) string { return ago(opts.Now(), t) },
		"when":   func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"upper":  strings.ToUpper,
		"routes": routeText,
	}
	for _, name := range []string{"fleet", "host", "changes", "root", "message"} {
		t, err := template.New("").Funcs(funcs).ParseFS(files, "templates/layout.tmpl", "templates/"+name+".tmpl")
		if err != nil {
			return nil, err
		}
		s.pages[name] = t
	}
	return s, nil
}

// Handler returns the dashboard's HTTP handler. Only GET and HEAD are
// served.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(files, "static")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleFleet)
	mux.HandleFunc("GET /host/{name}", s.handleHost)
	mux.HandleFunc("GET /changes", s.handleChanges)
	mux.HandleFunc("GET /root", s.handleRoot)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	if s.opts.Metrics {
		mux.HandleFunc("GET /metrics", s.handleMetrics)
	}
	assets := http.StripPrefix("/static/", http.FileServerFS(static))
	mux.HandleFunc("GET /static/{file}", func(w http.ResponseWriter, r *http.Request) {
		// Styles and logos hold nothing sensitive, unlike the pages.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		assets.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})
	return s.secure(s.logged(mux))
}

// page holds what every page shows.
type page struct {
	Title    string
	Nav      string
	Version  string
	LastScan time.Time
}

func (s *Server) page(ix *index, title, nav string) page {
	return page{Title: title, Nav: nav, Version: s.opts.Version, LastScan: ix.lastScan}
}

// load returns the index for the current history directory, rebuilding it
// only when files were added, removed or changed.
func (s *Server) load() (*index, error) {
	sig, err := signature(s.opts.HistoryDir)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ix != nil && sig == s.sig {
		return s.ix, nil
	}
	ix, err := buildIndex(s.opts.HistoryDir)
	if err != nil {
		return nil, err
	}
	s.ix, s.sig = ix, sig
	return s.ix, nil
}

// signature summarizes the snapshot files' names, sizes and times.
func signature(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		// Windows reports a file in the way as "not found" too.
		if st, serr := os.Stat(dir); serr == nil && !st.IsDir() {
			return "", fmt.Errorf("%s is not a directory", dir)
		}
		return "", nil // no scans saved yet
	}
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s/%d/%d;", e.Name(), info.Size(), info.ModTime().UnixNano())
	}
	return b.String(), nil
}

type fleetPage struct {
	page
	Empty       bool
	HistoryDir  string
	Severities  []string
	Totals      map[string]int
	Unreachable int
	Stale       int
	StaleAfter  string
	Rows        []hostRow
	Trend       *trend
	Recent      []changeGroup
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	ix, ok := s.index(w)
	if !ok {
		return
	}
	now := s.opts.Now()
	p := fleetPage{
		page:       s.page(ix, "Fleet", "fleet"),
		Empty:      len(ix.hosts) == 0,
		HistoryDir: s.opts.HistoryDir,
		Severities: severities[:4],
		Totals:     map[string]int{},
		Rows:       ix.rows(now, s.opts.StaleAfter),
		Trend:      ix.buildTrend(now, 30),
		StaleAfter: human(s.opts.StaleAfter),
	}
	for _, row := range p.Rows {
		for sev, n := range row.Counts {
			p.Totals[sev] += n
		}
		if row.Error != "" {
			p.Unreachable++
		}
		if row.Stale {
			p.Stale++
		}
	}
	p.Recent = ix.groups
	if len(p.Recent) > 8 {
		p.Recent = p.Recent[:8]
	}
	s.render(w, http.StatusOK, "fleet", p)
}

type hostPage struct {
	page
	Row        hostRow
	Scanned    bool // at least one successful scan
	ScanTime   time.Time
	Findings   []hostFinding
	Allowed    []scan.Suppressed
	Skipped    []scan.Skip
	History    []historyRow
	Severities []string
	Changes    []changeGroup
}

type hostFinding struct {
	Severity                    string
	CheckID, Title, Detail, Fix string
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	ix, ok := s.index(w)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if _, known := ix.latest[name]; !known {
		s.message(w, http.StatusNotFound, "Unknown host", "There is no saved scan for "+name+".")
		return
	}
	p := hostPage{
		page:       s.page(ix, name, "fleet"),
		Row:        ix.row(name, s.opts.Now(), s.opts.StaleAfter),
		Severities: severities,
	}
	if cur, ok := ix.current[name]; ok {
		p.Scanned, p.ScanTime = true, cur.Time
		active := cur.Active()
		sort.SliceStable(active, func(i, j int) bool { return active[i].Severity > active[j].Severity })
		for _, f := range active {
			p.Findings = append(p.Findings, hostFinding{f.Severity.String(), f.CheckID, f.Title, f.Detail, f.Fix})
		}
		p.Allowed, p.Skipped = cur.Allowlisted, cur.Skipped
		hist := ix.hist[name]
		for i := len(hist) - 1; i >= 0 && len(p.History) < 30; i-- {
			p.History = append(p.History, hist[i])
		}
	}
	for _, g := range ix.groups {
		if g.Host == name && len(p.Changes) < 50 {
			p.Changes = append(p.Changes, g)
		}
	}
	s.render(w, http.StatusOK, "host", p)
}

type changesPage struct {
	page
	Days    int
	Choices []int
	Groups  []changeGroup
	Total   int
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	ix, ok := s.index(w)
	if !ok {
		return
	}
	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v >= 1 && v <= 366 {
		days = v
	}
	p := changesPage{page: s.page(ix, "Changes", "changes"), Days: days, Choices: []int{7, 30, 90, 365}}
	since := s.opts.Now().Add(-time.Duration(days) * 24 * time.Hour)
	for _, g := range ix.groups {
		if g.To.Before(since) {
			break // newest first
		}
		if len(p.Groups) < 500 {
			p.Groups = append(p.Groups, g)
		}
		p.Total += len(g.Changes)
	}
	s.render(w, http.StatusOK, "changes", p)
}

type rootPage struct {
	page
	Map   rootmap.Map
	Empty bool
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	ix, ok := s.index(w)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "root", rootPage{page: s.page(ix, "Root access", "root"), Map: s.rootMap(ix), Empty: len(ix.hosts) == 0})
}

// rootMap builds the access map with key owners from the keys file, which
// is read every time, so edits show up without a restart.
func (s *Server) rootMap(ix *index) rootmap.Map {
	m := ix.rootMap()
	if s.opts.KeysFile != "" {
		if owners, err := keys.Load(s.opts.KeysFile, true); err != nil {
			m.Gaps = append(m.Gaps, rootmap.Gap{Host: "keys file", Reason: err.Error()})
		} else {
			m.SetOwners(owners.Path, owners.Owner)
		}
	}
	return m
}

// index loads the history, answering with an error page when it cannot.
func (s *Server) index(w http.ResponseWriter) (*index, bool) {
	ix, err := s.load()
	if err != nil {
		if s.opts.Log != nil {
			s.opts.Log.Printf("reading scan history: %v", err)
		}
		s.message(w, http.StatusInternalServerError, "Scan history unavailable",
			"nobet-web could not read the scan history directory. Check that it exists and that this service may read it; the server log has details.")
		return nil, false
	}
	return ix, true
}

type messagePage struct {
	page
	Text string
}

func (s *Server) message(w http.ResponseWriter, status int, title, text string) {
	s.render(w, status, "message", messagePage{page: page{Title: title, Version: s.opts.Version}, Text: text})
}

// render executes a page into a buffer first, so a template error never
// leaves a half-written page.
func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		if s.opts.Log != nil {
			s.opts.Log.Printf("rendering %s: %v", name, err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// secure adds headers that keep the pages from being framed, cached or
// leaking URLs, and forbids every script and every outside resource.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// logged writes one line per request, with the user name the
// authenticating proxy reported when UserHeader is set.
func (s *Server) logged(next http.Handler) http.Handler {
	if s.opts.Log == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		user := ""
		if s.opts.UserHeader != "" {
			if u := r.Header.Get(s.opts.UserHeader); u != "" {
				user = " user=" + strconv.Quote(u)
			}
		}
		s.opts.Log.Printf("%s %s %d %s remote=%s%s", r.Method, r.URL.RequestURI(), sw.status,
			time.Since(start).Round(time.Millisecond), r.RemoteAddr, user)
	})
}
