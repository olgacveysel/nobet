// Command nobet-web serves a read-only dashboard over nobet's scan history.
//
// It never scans and never holds SSH credentials: `nobet scan` runs
// elsewhere (for example from a systemd timer under a service account) and
// saves to a shared history directory, which nobet-web only reads. Either
// it listens on localhost behind a reverse proxy that authenticates your
// team, or it signs users in itself with OpenID Connect (-oidc-issuer).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/olgacveysel/nobet/internal/buildinfo"
	"github.com/olgacveysel/nobet/internal/keys"
	"github.com/olgacveysel/nobet/internal/store"
	"github.com/olgacveysel/nobet/internal/web"
)

// version is set at build time with -ldflags "-X main.version=0.1.0";
// main falls back to the module version (go install).
var version = "dev"

func main() {
	version = buildinfo.Version(version)
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("nobet-web", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on; keep it on localhost behind an authenticating reverse proxy")
	histDir := fs.String("history-dir", "", "scan history to show (default: $NOBET_DATA_DIR/scans, or ~/.local/share/nobet/scans)")
	stale := fs.Duration("stale", 48*time.Hour, "flag hosts without a successful scan for this long")
	userHeader := fs.String("user-header", "", "request header in which your proxy passes the signed-in user (e.g. X-Forwarded-User), to log who viewed what")
	keysFile := fs.String("keys", "", "file naming who each SSH key belongs to (as for nobet rootmap -keys), shown on the root access page")
	metrics := fs.Bool("metrics", false, "also serve /metrics in the Prometheus text format (findings per host and severity, scan times, root keys)")
	metricsListen := fs.String("metrics-listen", "", "serve /metrics on this separate address instead (for example 127.0.0.1:9187), which needs no sign-in")
	auditLog := fs.String("audit-log", "", "append every page view and sign-in, with the user, to this file as JSON lines")
	scanQueue := fs.String("scan-queue", "", "let users ask for scans: requests go to this directory, where `nobet scan -queue` (run as the scanner account) picks them up; nobet-web itself never scans")
	scanUsers := fs.String("scan-users", "", "who may ask for scans, comma-separated (default: everyone who can view)")
	scanGroups := fs.String("scan-groups", "", "with -oidc-issuer: groups whose members may ask for scans, comma-separated")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with this certificate (PEM; with -tls-key)")
	tlsKey := fs.String("tls-key", "", "private key for -tls-cert")
	var oc oidcFlags
	oc.add(fs)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Serve a read-only dashboard over nobet's saved scans.\n\n"+
			"nobet-web never scans and holds no SSH keys. Run it on localhost behind a\n"+
			"reverse proxy that authenticates users, or let it sign users in with your\n"+
			"OpenID Connect provider (-oidc-issuer and the other -oidc flags).\n\n"+
			"Usage:\n  nobet-web [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println("nobet-web", version)
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "nobet-web: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	dir := *histDir
	if dir == "" {
		d, err := store.Dir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet-web:", err)
			return 2
		}
		dir = d
	}
	if *keysFile != "" {
		if _, err := keys.Load(*keysFile, true); err != nil {
			fmt.Fprintln(os.Stderr, "nobet-web: keys:", err)
			return 2
		}
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "nobet-web: -tls-cert and -tls-key go together")
		return 2
	}
	authCfg, err := oc.config()
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 2
	}
	if authCfg != nil && *userHeader != "" {
		fmt.Fprintln(os.Stderr, "nobet-web: -user-header is for a proxy that signs users in; with -oidc-issuer nobet-web does that itself")
		return 2
	}
	if *scanQueue != "" {
		if st, err := os.Stat(*scanQueue); err != nil || !st.IsDir() {
			fmt.Fprintf(os.Stderr, "nobet-web: -scan-queue %s: not a directory nobet-web can use\n", *scanQueue)
			return 2
		}
	} else if *scanUsers != "" || *scanGroups != "" {
		fmt.Fprintln(os.Stderr, "nobet-web: -scan-users and -scan-groups need -scan-queue")
		return 2
	}
	var audit io.Writer
	if *auditLog != "" {
		f, err := os.OpenFile(*auditLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet-web: audit log:", err)
			return 2
		}
		defer f.Close()
		audit = f
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	srv, err := web.New(web.Options{HistoryDir: dir, Version: version, StaleAfter: *stale, UserHeader: *userHeader, KeysFile: *keysFile,
		Metrics: *metrics && *metricsListen == "", Auth: authCfg, Audit: audit, Log: logger,
		ScanQueue: *scanQueue, ScanUsers: list(*scanUsers), ScanGroups: list(*scanGroups)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 1
	}
	switch {
	case authCfg == nil && !loopback(*listen):
		logger.Printf("WARNING: listening on %s, beyond localhost. Without -oidc-issuer nobet-web has no login and shows which keys open root on which servers; make sure only an authenticating reverse proxy can reach it.", *listen)
	case authCfg != nil && *metrics && *metricsListen == "":
		logger.Printf("note: with sign-in, /metrics needs a session too; Prometheus cannot sign in, so use -metrics-listen")
	case authCfg != nil && !strings.HasPrefix(authCfg.PublicURL, "https://") && !loopback(*listen):
		logger.Printf("WARNING: -public-url is not https, so session cookies cross the network unencrypted")
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 1
	}
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	logger.Printf("nobet-web %s serving %s on %s://%s", version, dir, scheme, ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 2)
	go func() {
		if *tlsCert != "" {
			done <- httpSrv.ServeTLS(ln, *tlsCert, *tlsKey)
		} else {
			done <- httpSrv.Serve(ln)
		}
	}()
	servers := []*http.Server{httpSrv}
	if *metrics && *metricsListen != "" {
		mln, err := net.Listen("tcp", *metricsListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet-web: metrics:", err)
			return 1
		}
		msrv := &http.Server{Handler: srv.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
		servers = append(servers, msrv)
		go func() { done <- msrv.Serve(mln) }()
		logger.Printf("metrics on http://%s/metrics", mln.Addr())
	}
	select {
	case err := <-done:
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 1
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdown); err != nil {
			fmt.Fprintln(os.Stderr, "nobet-web: shutdown:", err)
			return 1
		}
	}
	return 0
}

// loopback reports whether a listen address only accepts local
// connections.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
