// Package fleet scans the local machine or many remote hosts in parallel.
// It is the only package that connects to hosts; only the nobet CLI uses
// it.
package fleet

import (
	"sync"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/transport"
)

// Local scans the machine nobet is running on.
func Local(cmdTimeout time.Duration) scan.HostResult {
	start := time.Now()
	res := scan.HostResult{Host: scan.LocalName(), Local: true, Findings: []checks.Finding{}}

	if r, err := transport.NewLocal(cmdTimeout); err != nil {
		res.Error = err.Error()
	} else {
		scan.Evaluate(&res, r)
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

// Target is a remote host to scan: its display name and either a resolved
// SSH destination or the error that stopped resolution.
type Target struct {
	Name string
	SSH  transport.SSHTarget
	Err  error
}

// Remote scans targets over SSH with at most concurrency connections open
// at once. Results are returned in input order. If onDone is not nil, it is
// called (from several goroutines) as each host finishes, with the host's
// index in targets.
func Remote(targets []Target, opts transport.SSHOptions, concurrency int, onDone func(i int, r scan.HostResult)) []scan.HostResult {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]scan.HostResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = remoteHost(t, opts)
			if onDone != nil {
				onDone(i, results[i])
			}
		}(i, t)
	}
	wg.Wait()
	return results
}

func remoteHost(t Target, opts transport.SSHOptions) scan.HostResult {
	start := time.Now()
	res := scan.HostResult{Host: t.Name, Findings: []checks.Finding{}}

	switch client, err := dial(t, opts); {
	case err != nil:
		res.Error = err.Error()
	default:
		scan.Evaluate(&res, client)
		client.Close()
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func dial(t Target, opts transport.SSHOptions) (*transport.SSH, error) {
	if t.Err != nil {
		return nil, t.Err
	}
	return transport.DialSSH(t.SSH, opts)
}
