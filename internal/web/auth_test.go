package web

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeProvider is a minimal OpenID Connect provider: discovery, JWKS and a
// token endpoint that checks PKCE and issues signed ID tokens.
type fakeProvider struct {
	*httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]fakeGrant // code -> what the user consented to
	nonce string               // overrides the nonce in the next token
}

type fakeGrant struct {
	nonce, challenge string
	claims           map[string]any
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key, codes: map[string]fakeGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
			"jwks_uri": p.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.mu.Lock()
		g, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		nonce := p.nonce
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		if nonce == "" {
			nonce = g.nonce
		}
		claims := map[string]any{"iss": p.URL, "aud": "nobet", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
		for k, v := range g.claims {
			claims[k] = v
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// authorize plays the provider's sign-in page: it reads nobet-web's
// redirect and returns the callback URL with a fresh code.
func (p *fakeProvider) authorize(t *testing.T, location string, claims map[string]any) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, p.URL+"/authorize") {
		t.Fatalf("not sent to the provider: %q", location)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorization request lacks PKCE, nonce or state: %v", q)
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = fakeGrant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), claims: claims}
	p.mu.Unlock()
	return q.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(q.Get("state"))
}

type browser struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]*http.Cookie
}

func (b *browser) get(target string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

func authServer(t *testing.T, p *fakeProvider, cfg OIDCConfig, audit io.Writer) (*browser, *Server) {
	t.Helper()
	dir := t.TempDir()
	history(t, dir)
	cfg.Issuer, cfg.ClientID, cfg.PublicURL = p.URL, "nobet", "https://nobet.example.com"
	s, err := New(Options{HistoryDir: dir, Version: "test", Now: func() time.Time { return now }, Auth: &cfg, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, h: s.Handler(), cookies: map[string]*http.Cookie{}}, s
}

// signIn starts at path, goes through the provider and returns the final response.
func signIn(t *testing.T, b *browser, p *fakeProvider, path string, claims map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := b.get(path)
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "/auth/login?return=") {
		t.Fatalf("GET %s without a session: %d %q", path, rec.Code, rec.Header().Get("Location"))
	}
	rec = b.get(rec.Header().Get("Location"))
	callback := p.authorize(t, rec.Header().Get("Location"), claims)
	u, _ := url.Parse(callback)
	if u.Path != "/auth/callback" || u.Host != "nobet.example.com" {
		t.Fatalf("callback %q", callback)
	}
	return b.get(u.RequestURI())
}

func TestSignIn(t *testing.T) {
	p := newFakeProvider(t)
	var audit bytes.Buffer
	b, _ := authServer(t, p, OIDCConfig{Users: []string{"Alice@Example.com"}}, &audit)

	rec := signIn(t, b, p, "/root?x=1", map[string]any{"sub": "u1", "email": "alice@example.com", "email_verified": true})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/root?x=1" {
		t.Fatalf("callback: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	c := b.cookies["__Host-nobet_session"]
	if c == nil || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("session cookie %+v", c)
	}
	if _, ok := b.cookies["__Host-nobet_login"]; ok {
		t.Error("the login cookie should be cleared after the callback")
	}
	page := b.get("/root")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `<span class="who">alice@example.com</span>`) || !strings.Contains(page.Body.String(), `href="/auth/logout"`) {
		t.Errorf("signed-in page: %d", page.Code)
	}
	// The callback cannot be replayed: the login cookie is gone.
	if rec := b.get("/auth/callback?code=x&state=y"); rec.Code != http.StatusBadRequest {
		t.Errorf("replayed callback: %d", rec.Code)
	}

	if rec := b.get("/auth/logout"); rec.Code != 200 || b.cookies["__Host-nobet_session"] != nil {
		t.Errorf("logout: %d, cookie %v", rec.Code, b.cookies["__Host-nobet_session"])
	}
	if rec := b.get("/"); rec.Code != http.StatusFound {
		t.Errorf("after logout: %d", rec.Code)
	}

	var events []string
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		var e auditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		events = append(events, e.Event+" "+e.User+" "+e.Path)
		if strings.Contains(e.Path, "code=") || strings.Contains(e.Path, "state=") {
			t.Errorf("the audit log holds the one-time code or state: %q", line)
		}
	}
	want := []string{"login alice@example.com /auth/callback", "view alice@example.com /root", "login_failed  /auth/callback", "logout alice@example.com /auth/logout"}
	if len(events) != len(want) {
		t.Fatalf("audit events %q", events)
	}
	for i := range want {
		if !strings.HasPrefix(events[i], want[i]) {
			t.Errorf("audit event %d = %q, want prefix %q", i, events[i], want[i])
		}
	}
}

func TestSignInDenied(t *testing.T) {
	p := newFakeProvider(t)
	var audit bytes.Buffer
	b, _ := authServer(t, p, OIDCConfig{Users: []string{"alice@example.com"}, Groups: []string{"nobet-viewers"}, GroupsClaim: "realm_access.roles"}, &audit)

	cases := []struct {
		name   string
		claims map[string]any
		code   int
	}{
		{"not listed", map[string]any{"sub": "u2", "email": "mallory@example.com"}, http.StatusForbidden},
		{"unverified email", map[string]any{"sub": "u3", "email": "alice@example.com", "email_verified": false}, http.StatusForbidden},
		{"group via dotted claim", map[string]any{"sub": "u4", "email": "bob@example.com", "realm_access": map[string]any{"roles": []any{"nobet-viewers"}}}, http.StatusFound},
		{"subject", map[string]any{"sub": "alice@example.com"}, http.StatusFound},
	}
	for _, c := range cases {
		b.cookies = map[string]*http.Cookie{}
		rec := signIn(t, b, p, "/", c.claims)
		if rec.Code != c.code {
			t.Errorf("%s: got %d, want %d", c.name, rec.Code, c.code)
		}
		if c.code == http.StatusForbidden && b.cookies["__Host-nobet_session"] != nil {
			t.Errorf("%s: a denied user got a session", c.name)
		}
	}
	if !strings.Contains(audit.String(), `"event":"denied","user":"mallory@example.com"`) {
		t.Errorf("audit log lacks the denial:\n%s", audit.String())
	}
}

func TestSignInRejectsTampering(t *testing.T) {
	p := newFakeProvider(t)
	b, s := authServer(t, p, OIDCConfig{AnyUser: true}, nil)

	// Wrong state.
	b.get("/auth/login")
	rec := b.get("/auth/callback?code=c&state=wrong")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "state mismatch") {
		t.Errorf("wrong state: %d %s", rec.Code, rec.Body)
	}

	// A token whose nonce belongs to another sign-in.
	b.cookies = map[string]*http.Cookie{}
	p.nonce = "someone-elses-nonce"
	if rec := signIn(t, b, p, "/", map[string]any{"sub": "u"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "nonce mismatch") {
		t.Errorf("wrong nonce: %d", rec.Code)
	}
	p.nonce = ""

	// A forged or expired session cookie.
	forged := &http.Cookie{Name: "__Host-nobet_session", Value: s.auth.sign(session{User: "x", Expires: now.Add(time.Hour).Unix()})}
	forged.Value = forged.Value[:len(forged.Value)-2] + "AA"
	b.cookies = map[string]*http.Cookie{forged.Name: forged}
	if rec := b.get("/"); rec.Code != http.StatusFound {
		t.Errorf("forged cookie: %d", rec.Code)
	}
	expired := &http.Cookie{Name: "__Host-nobet_session", Value: s.auth.sign(session{User: "x", Expires: now.Unix()})}
	b.cookies = map[string]*http.Cookie{expired.Name: expired}
	if rec := b.get("/"); rec.Code != http.StatusFound {
		t.Errorf("expired cookie: %d", rec.Code)
	}

	// Public paths need no session.
	b.cookies = map[string]*http.Cookie{}
	for _, path := range []string{"/healthz", "/static/style.css"} {
		if rec := b.get(path); rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestPKCEChecked(t *testing.T) {
	p := newFakeProvider(t)
	b, _ := authServer(t, p, OIDCConfig{AnyUser: true}, nil)
	rec := b.get("/auth/login")
	callback := p.authorize(t, rec.Header().Get("Location"), map[string]any{"sub": "u"})
	p.mu.Lock()
	for code, g := range p.codes {
		g.challenge = "not-the-challenge"
		p.codes[code] = g
	}
	p.mu.Unlock()
	u, _ := url.Parse(callback)
	if rec := b.get(u.RequestURI()); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "code exchange") {
		t.Errorf("bad verifier: %d %s", rec.Code, rec.Body)
	}
}

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"/root?x=1":            "/root?x=1",
		"":                     "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"/host/web01\r\nX: y":  "/",
	}
	for in, want := range cases {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthConfigErrors(t *testing.T) {
	p := newFakeProvider(t)
	cases := map[string]OIDCConfig{
		"allowed users or groups": {Issuer: p.URL, ClientID: "nobet", PublicURL: "https://n.example"},
		"32 bytes":                {Issuer: p.URL, ClientID: "nobet", PublicURL: "https://n.example", AnyUser: true, SessionKey: []byte("short")},
		"public URL":              {Issuer: p.URL, ClientID: "nobet", PublicURL: "nobet.example", AnyUser: true},
		"OIDC provider":           {Issuer: p.URL + "/nope", ClientID: "nobet", PublicURL: "https://n.example", AnyUser: true},
	}
	for want, cfg := range cases {
		cfg := cfg
		if _, err := New(Options{HistoryDir: t.TempDir(), Auth: &cfg}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err %v, want %q", err, want)
		}
	}
}

// Without built-in login, the audit log names the user the proxy reports.
func TestAuditBehindProxy(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	var audit bytes.Buffer
	s, err := New(Options{HistoryDir: dir, Now: func() time.Time { return now }, UserHeader: "X-Forwarded-User", Audit: &audit})
	if err != nil {
		t.Fatal(err)
	}
	get(t, s.Handler(), "GET", "/changes?days=7")
	get(t, s.Handler(), "GET", "/static/style.css")
	var e auditEvent
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &e) != nil || e.Event != "view" || e.User != "alice@example.com" || e.Path != "/changes?days=7" || e.Status != 200 {
		t.Errorf("audit: %q", audit.String())
	}
}
