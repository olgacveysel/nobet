package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/olgacveysel/nobet/internal/queue"
)

// scanBox is what pages show about scans asked for from the dashboard.
type scanBox struct {
	Allowed bool            // the viewer may ask for a scan
	Host    string          // on a host's page: the host a request would be for
	Pending []queue.Pending // waiting or running
	Last    *queue.Done     // the newest finished request
	Error   string          // the queue directory could not be read
}

// mayScan reports whether the viewer may ask for scans: with built-in
// sign-in as decided when they signed in, behind a proxy by ScanUsers
// (everyone when it is empty).
func (s *Server) mayScan(r *http.Request) bool {
	switch {
	case s.opts.ScanQueue == "":
		return false
	case s.auth != nil:
		return s.auth.session(r, s.opts.Now()).Scan
	case len(s.opts.ScanUsers) == 0:
		return true
	}
	user := s.viewer(r)
	for _, u := range s.opts.ScanUsers {
		if user != "" && strings.EqualFold(u, user) {
			return true
		}
	}
	return false
}

func (s *Server) scanBox(r *http.Request) *scanBox {
	if s.opts.ScanQueue == "" {
		return nil
	}
	b := &scanBox{Allowed: s.mayScan(r)}
	pending, err := queue.List(s.opts.ScanQueue)
	if err != nil {
		if s.opts.Log != nil {
			s.opts.Log.Printf("reading the scan queue: %v", err)
		}
		b.Error = "the scan queue directory cannot be read; the server log has details"
		return b
	}
	b.Pending = pending
	if done, err := queue.Recent(s.opts.ScanQueue, 1); err == nil && len(done) > 0 {
		b.Last = &done[0]
	}
	return b
}

// handleScan queues a scan of every host, or of the host in the form. The
// scanner (nobet scan -queue) decides what it actually scans: only hosts
// from its own inventory.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	user := s.viewer(r)
	if !s.mayScan(r) {
		s.audit("scan_denied", user, r, http.StatusForbidden, "")
		s.message(w, r, http.StatusForbidden, "Not allowed", "You can view this dashboard but not ask for scans.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.message(w, r, http.StatusBadRequest, "Bad request", "The scan request could not be read.")
		return
	}
	var hosts []string
	back := "/"
	if host := r.PostForm.Get("host"); host != "" {
		ix, ok := s.index(w, r)
		if !ok {
			return
		}
		if _, known := ix.latest[host]; !known {
			s.message(w, r, http.StatusBadRequest, "Unknown host", "There is no saved scan for "+host+".")
			return
		}
		hosts, back = []string{host}, hostHref(host)
	}
	s.scanMu.Lock()
	_, err := queue.Submit(s.opts.ScanQueue, user, hosts, s.opts.Now())
	s.scanMu.Unlock()
	switch {
	case errors.Is(err, queue.ErrBusy):
		s.messageFor(w, user, http.StatusConflict, "A scan is already queued",
			"Another scan is waiting or running. Its results show up here when it finishes.", back, "Back")
	case err != nil:
		if s.opts.Log != nil {
			s.opts.Log.Printf("queueing a scan: %v", err)
		}
		s.message(w, r, http.StatusInternalServerError, "Could not queue the scan", "The scan queue directory is not writable for nobet-web; the server log has details.")
	default:
		what := "all hosts"
		if len(hosts) > 0 {
			what = strings.Join(hosts, ", ")
		}
		s.audit("scan_requested", user, r, http.StatusSeeOther, what)
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}
