package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// public paths are served without a session: styles and logos, the health
// check, and the sign-in flow itself.
func public(p string) bool {
	return strings.HasPrefix(p, "/static/") || p == "/healthz" || p == "/favicon.ico" || strings.HasPrefix(p, "/auth/")
}

// viewer names who is making the request: the signed-in user with
// built-in login, or what the authenticating proxy reports in UserHeader.
func (s *Server) viewer(r *http.Request) string {
	if s.auth != nil {
		return s.auth.user(r, s.opts.Now())
	}
	if s.opts.UserHeader != "" {
		return r.Header.Get(s.opts.UserHeader)
	}
	return ""
}

// authorized sends requests without a valid session to sign in first.
func (s *Server) authorized(next http.Handler) http.Handler {
	if s.auth == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !public(r.URL.Path) && s.auth.user(r, s.opts.Now()) == "" {
			http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logURI is the request URI for logs. The sign-in callback carries a
// one-time code and the state, which stay out of logs.
func logURI(r *http.Request) string {
	if r.URL.Path == "/auth/callback" {
		return r.URL.Path
	}
	return r.URL.RequestURI()
}

// auditEvent is one line of the audit log.
type auditEvent struct {
	Time   string `json:"time"`
	Event  string `json:"event"` // view, login, logout, denied, login_failed, scan_requested, scan_denied
	User   string `json:"user,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	Remote string `json:"remote"`
	Reason string `json:"reason,omitempty"`
}

// audit appends an event to the audit log, if there is one.
func (s *Server) audit(event, user string, r *http.Request, status int, reason string) {
	if s.opts.Audit == nil {
		return
	}
	line, _ := json.Marshal(auditEvent{
		Time: s.opts.Now().UTC().Format(time.RFC3339), Event: event, User: user,
		Method: r.Method, Path: logURI(r), Status: status, Remote: r.RemoteAddr, Reason: reason,
	})
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if _, err := s.opts.Audit.Write(append(line, '\n')); err != nil && s.opts.Log != nil {
		s.opts.Log.Printf("writing the audit log: %v", err)
	}
}

// audited records every page view (not styles or health checks; the
// sign-in pages record their own events).
func (s *Server) audited(next http.Handler) http.Handler {
	if s.opts.Audit == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// Scan requests (POST) record their own events.
		if !public(r.URL.Path) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			s.audit("view", s.viewer(r), r, sw.status, "")
		}
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.auth.login(w, r, s.opts.Now())
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	user, next, err := s.auth.callback(w, r, s.opts.Now())
	switch {
	case errors.Is(err, errDenied):
		s.audit("denied", user, r, http.StatusForbidden, "")
		s.messageFor(w, "", http.StatusForbidden, "Not allowed",
			user+" signed in, but is not allowed to view this dashboard. Ask whoever runs nöbet to add you.", "/auth/login", "Sign in as someone else")
	case err != nil:
		s.audit("login_failed", user, r, http.StatusBadRequest, err.Error())
		if s.opts.Log != nil {
			s.opts.Log.Printf("sign-in failed: %v", err)
		}
		s.messageFor(w, "", http.StatusBadRequest, "Sign-in failed", err.Error(), "/auth/login", "Try again")
	default:
		s.audit("login", user, r, http.StatusFound, "")
		http.Redirect(w, r, next, http.StatusFound)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	user := s.viewer(r)
	s.auth.clearCookie(w, "nobet_session")
	s.audit("logout", user, r, http.StatusOK, "")
	s.messageFor(w, "", http.StatusOK, "Signed out",
		"You are signed out of nöbet (you may still be signed in at your identity provider).", "/auth/login", "Sign in again")
}

// MetricsHandler serves only /metrics, for a separate listener that
// Prometheus can scrape without signing in.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	return s.secure(s.logged(mux))
}
