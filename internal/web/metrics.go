package web

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleMetrics serves the fleet's state in the Prometheus text format,
// for alerting on new findings and on hosts that stopped being scanned.
// It is off unless Options.Metrics is set.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ix, err := s.load()
	if err != nil {
		if s.opts.Log != nil {
			s.opts.Log.Printf("reading scan history: %v", err)
		}
		http.Error(w, "scan history unavailable", http.StatusInternalServerError)
		return
	}
	now := s.opts.Now()
	var b bytes.Buffer
	metric := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	sample := func(name string, value float64, labels ...string) {
		b.WriteString(name)
		if len(labels) > 0 {
			b.WriteByte('{')
			for i := 0; i+1 < len(labels); i += 2 {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, "%s=\"%s\"", labels[i], labelValue(labels[i+1]))
			}
			b.WriteByte('}')
		}
		fmt.Fprintf(&b, " %g\n", value)
	}
	unix := func(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }
	boolean := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}

	metric("nobet_build_info", "gauge", "Version of nobet-web.")
	sample("nobet_build_info", 1, "version", s.opts.Version)
	metric("nobet_hosts", "gauge", "Hosts in the scan history.")
	sample("nobet_hosts", float64(len(ix.hosts)))
	if !ix.lastScan.IsZero() {
		metric("nobet_last_scan_timestamp_seconds", "gauge", "When the newest scan in the history ran.")
		sample("nobet_last_scan_timestamp_seconds", unix(ix.lastScan))
	}

	rows := make([]hostRow, len(ix.hosts))
	for i, h := range ix.hosts {
		rows[i] = ix.row(h, now, s.opts.StaleAfter)
	}
	metric("nobet_host_up", "gauge", "1 if the host's newest scan attempt succeeded, 0 if it failed.")
	for _, r := range rows {
		sample("nobet_host_up", boolean(r.Error == ""), "host", r.Name)
	}
	metric("nobet_host_stale", "gauge", "1 if the host has no successful scan within the stale period (-stale).")
	for _, r := range rows {
		sample("nobet_host_stale", boolean(r.Stale), "host", r.Name)
	}
	metric("nobet_host_last_attempt_timestamp_seconds", "gauge", "When the host's newest scan attempt ran.")
	for _, r := range rows {
		sample("nobet_host_last_attempt_timestamp_seconds", unix(r.Last), "host", r.Name)
	}
	metric("nobet_host_last_success_timestamp_seconds", "gauge", "When the host's newest successful scan ran (absent if it never succeeded).")
	for _, r := range rows {
		if !r.LastOK.IsZero() {
			sample("nobet_host_last_success_timestamp_seconds", unix(r.LastOK), "host", r.Name)
		}
	}
	metric("nobet_host_privileged", "gauge", "1 if the host's newest successful scan had root or passwordless sudo, so root-only checks ran.")
	for _, r := range rows {
		if !r.LastOK.IsZero() {
			sample("nobet_host_privileged", boolean(r.Privileged), "host", r.Name)
		}
	}
	metric("nobet_host_findings", "gauge", "Findings in the host's newest successful scan, by severity, not counting allowlisted ones.")
	for _, r := range rows {
		if r.LastOK.IsZero() {
			continue
		}
		for _, sev := range severities {
			sample("nobet_host_findings", float64(r.Counts[sev]), "host", r.Name, "severity", sev)
		}
	}
	metric("nobet_host_allowlisted_findings", "gauge", "Findings the allowlist accepted in the host's newest successful scan.")
	for _, r := range rows {
		if !r.LastOK.IsZero() {
			sample("nobet_host_allowlisted_findings", float64(r.Allowlisted), "host", r.Name)
		}
	}

	// How long findings have been open, for alerts such as "a critical
	// finding open for more than 7 days" (time() minus the timestamp).
	oldest := map[string]map[string]time.Time{}
	fresh := map[string]map[string]int{}
	for _, h := range ix.hosts {
		cur, ok := ix.current[h]
		if !ok {
			continue
		}
		oldest[h], fresh[h] = map[string]time.Time{}, map[string]int{}
		for _, f := range cur.Active() {
			sev := f.Severity.String()
			if t, ok := ix.openings.Opened(h, f); ok && (oldest[h][sev].IsZero() || t.Before(oldest[h][sev])) {
				oldest[h][sev] = t
			}
			if ix.openings.IsNew(h, f) {
				fresh[h][sev]++
			}
		}
	}
	metric("nobet_host_oldest_finding_opened_timestamp_seconds", "gauge", "When the host's oldest open finding of a severity was first reported (the oldest kept scan if it was there already), not counting allowlisted ones; absent when there is none.")
	for _, h := range ix.hosts {
		for _, sev := range severities {
			if t := oldest[h][sev]; !t.IsZero() {
				sample("nobet_host_oldest_finding_opened_timestamp_seconds", unix(t), "host", h, "severity", sev)
			}
		}
	}
	metric("nobet_host_new_findings", "gauge", "Findings first reported in the host's newest successful scan, by severity, not counting allowlisted ones.")
	for _, h := range ix.hosts {
		if fresh[h] == nil {
			continue
		}
		for _, sev := range severities {
			sample("nobet_host_new_findings", float64(fresh[h][sev]), "host", h, "severity", sev)
		}
	}

	m := s.rootMap(ix)
	metric("nobet_root_keys", "gauge", "SSH keys that lead to root on at least one host.")
	sample("nobet_root_keys", float64(len(m.Keys)))
	if m.OwnersFile != "" {
		metric("nobet_root_keys_unclaimed", "gauge", "SSH keys that lead to root but have no owner in the keys file.")
		sample("nobet_root_keys_unclaimed", float64(len(m.Unclaimed())))
	}
	metric("nobet_root_accounts_without_keys", "gauge", "Root-capable accounts that cannot be reached with an SSH key, across hosts.")
	sample("nobet_root_accounts_without_keys", float64(len(m.KeylessUsers)))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write(b.Bytes())
}

// labelValue escapes a Prometheus label value.
func labelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
