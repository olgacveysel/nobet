package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A real ed25519 public key and its fingerprint (ssh-keygen -lf).
const (
	pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@desktop"
	fp  = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
)

func TestParse(t *testing.T) {
	in := strings.Join([]string{
		"# owner key",
		"",
		"alice  " + pub + "   # desktop",
		"ci     SHA256:HRmMEMU9cyejr7STBxyzzOI4cfmC7Xkho7aTuOfNdNA  # deploy pipeline",
		"alice  " + fp + "   # the same key again is fine",
	}, "\n")
	m, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if m[fp] != "alice" || m["SHA256:HRmMEMU9cyejr7STBxyzzOI4cfmC7Xkho7aTuOfNdNA"] != "ci" || len(m) != 2 {
		t.Errorf("got %v", m)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"alice":                           "line 1: want <owner>",
		"alice SHA256:short":              "not a SHA256 fingerprint",
		"alice ssh-ed25519 notbase64":     "not a fingerprint or a public key",
		"alice " + fp + "\nbob " + pub:    "line 2: key " + fp + " already belongs to alice (line 1)",
		"alice " + fp + " trailing words": "not a SHA256 fingerprint",
	}
	for in, want := range cases {
		if _, err := Parse(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q): err %v, want %q", in, err, want)
		}
	}
}

// The example shipped in archives and packages must stay valid.
func TestExample(t *testing.T) {
	o, err := Load("../../keys.example", true)
	if err != nil {
		t.Fatal(err)
	}
	if o.Owner(fp) != "alice" || !o.Has("ci") {
		t.Errorf("got %+v", o)
	}
}

func TestLoad(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "keys")
	o, err := Load(missing, false)
	if err != nil || o.Loaded() {
		t.Errorf("optional missing file: %+v, %v", o, err)
	}
	if _, err := Load(missing, true); err == nil {
		t.Error("required missing file should fail")
	}
	if err := os.WriteFile(missing, []byte("alice "+fp+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err = Load(missing, true)
	if err != nil || !o.Loaded() || o.Owner(fp) != "alice" || !o.Has("alice") || o.Has("bob") {
		t.Errorf("got %+v, %v", o, err)
	}
	var none *Owners
	if none.Owner(fp) != "" || none.Loaded() || none.Has("alice") {
		t.Error("nil Owners should know nothing")
	}
}
