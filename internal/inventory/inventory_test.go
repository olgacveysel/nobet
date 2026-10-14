package inventory

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Host
	}{
		{"web01", Host{Name: "web01", Addr: "web01", User: "me"}},
		{"admin@db02:2222", Host{Name: "admin@db02:2222", Addr: "db02", Port: 2222, User: "admin"}},
		{"[2001:db8::1]:2200", Host{Name: "[2001:db8::1]:2200", Addr: "2001:db8::1", Port: 2200, User: "me"}},
		{"2001:db8::1", Host{Name: "2001:db8::1", Addr: "2001:db8::1", User: "me"}},
	}
	for _, c := range cases {
		got, err := Parse(c.in, "me")
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}

	if h, _ := Parse("web01", ""); h.User != "" || h.Target() != "web01:22" {
		t.Errorf("no user/port: %+v, target %s", h, h.Target())
	}

	for _, bad := range []string{"host:abc", "host:0", "user@", ""} {
		if _, err := Parse(bad, "me"); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", bad)
		}
	}
}
