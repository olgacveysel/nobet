// Command nobet-web serves a read-only dashboard over nobet's scan history.
//
// It never scans and never holds SSH credentials: `nobet scan` runs
// elsewhere (for example from a systemd timer under a service account) and
// saves to a shared history directory, which nobet-web only reads. It has
// no login of its own, so it listens on localhost by default; put it behind
// a reverse proxy that authenticates your team.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olgacveysel/nobet/internal/keys"
	"github.com/olgacveysel/nobet/internal/store"
	"github.com/olgacveysel/nobet/internal/web"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("nobet-web", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on; keep it on localhost behind an authenticating reverse proxy")
	histDir := fs.String("history-dir", "", "scan history to show (default: $NOBET_DATA_DIR/scans, or ~/.local/share/nobet/scans)")
	stale := fs.Duration("stale", 48*time.Hour, "flag hosts without a successful scan for this long")
	userHeader := fs.String("user-header", "", "request header in which your proxy passes the signed-in user (e.g. X-Forwarded-User), to log who viewed what")
	keysFile := fs.String("keys", "", "file naming who each SSH key belongs to (as for nobet rootmap -keys), shown on the root access page")
	metrics := fs.Bool("metrics", false, "also serve /metrics in the Prometheus text format (findings per host and severity, scan times, root keys)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Serve a read-only dashboard over nobet's saved scans.\n\n"+
			"nobet-web never scans and holds no SSH keys. It has no login of its own:\n"+
			"run it on localhost behind a reverse proxy that authenticates users.\n\n"+
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
	logger := log.New(os.Stderr, "", log.LstdFlags)
	srv, err := web.New(web.Options{HistoryDir: dir, Version: version, StaleAfter: *stale, UserHeader: *userHeader, KeysFile: *keysFile, Metrics: *metrics, Log: logger})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 1
	}
	if !loopback(*listen) {
		logger.Printf("WARNING: listening on %s, beyond localhost. nobet-web has no login and shows which keys open root on which servers; make sure only an authenticating reverse proxy can reach it.", *listen)
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
	logger.Printf("nobet-web %s serving %s on http://%s", version, dir, ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- httpSrv.Serve(ln) }()
	select {
	case err := <-done:
		fmt.Fprintln(os.Stderr, "nobet-web:", err)
		return 1
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdown); err != nil {
		fmt.Fprintln(os.Stderr, "nobet-web: shutdown:", err)
		return 1
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
