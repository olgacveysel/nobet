package fleet

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/runner"
	"github.com/olgacveysel/nobet/internal/scan"
)

// panicky stands in for a host whose output makes a parser panic.
type panicky struct{}

func (panicky) Run(string) (runner.Result, error) { panic("index out of range [3] with length 2") }

func TestEvaluateRecovers(t *testing.T) {
	res := scan.HostResult{Host: "odd", Findings: []checks.Finding{}}
	evaluate(&res, panicky{}) // must not panic
	if !strings.Contains(res.Error, "internal error") || !strings.Contains(res.Error, "index out of range") {
		t.Errorf("error %q", res.Error)
	}
	if res.Findings == nil || len(res.Findings) != 0 || res.Facts != nil {
		t.Errorf("partial result kept: %+v", res)
	}
}
