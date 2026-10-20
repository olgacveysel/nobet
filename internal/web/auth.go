package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configures built-in login with an OpenID Connect provider
// (Keycloak, Authentik, Entra ID, Google, Okta, Dex, ...). Everyone who may
// sign in has the same read-only view; who may sign in is decided by Users,
// Groups or AnyUser, and nobody is allowed by default.
type OIDCConfig struct {
	Issuer       string   // provider URL; its /.well-known/openid-configuration is read at startup
	ClientID     string   //
	ClientSecret string   // "" for a public client (PKCE is always used)
	PublicURL    string   // where users reach nobet-web, e.g. https://nobet.example.com; the callback is <PublicURL>/auth/callback
	Scopes       []string // besides openid; default profile and email
	Users        []string // allowed users, by email, preferred_username or subject (case-insensitive)
	Groups       []string // allowed groups, from GroupsClaim
	GroupsClaim  string   // default "groups"
	AnyUser      bool     // allow everyone the provider authenticates
	SessionKey   []byte   // signs cookies; at least 32 bytes, random when empty (sessions then end on restart)
	SessionTTL   time.Duration
}

const (
	defaultSessionTTL = 8 * time.Hour
	loginTTL          = 10 * time.Minute // from leaving for the provider to coming back
)

// auth is a configured OIDC login.
type auth struct {
	cfg      OIDCConfig
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	secure   bool // cookies only over HTTPS
	client   *http.Client
}

// newAuth reads the provider's configuration. It fails when the provider
// is unreachable, so a misconfiguration shows at startup.
func newAuth(ctx context.Context, cfg OIDCConfig) (*auth, error) {
	if cfg.ClientID == "" || cfg.PublicURL == "" {
		return nil, errors.New("OIDC needs a client ID and the public URL")
	}
	if len(cfg.Users) == 0 && len(cfg.Groups) == 0 && !cfg.AnyUser {
		return nil, errors.New("OIDC needs allowed users or groups (or explicitly any user)")
	}
	pub, err := url.Parse(strings.TrimSuffix(cfg.PublicURL, "/"))
	if err != nil || (pub.Scheme != "https" && pub.Scheme != "http") || pub.Host == "" {
		return nil, fmt.Errorf("public URL %q: want http(s)://host[:port]", cfg.PublicURL)
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if len(cfg.SessionKey) == 0 {
		cfg.SessionKey = make([]byte, 32)
		if _, err := rand.Read(cfg.SessionKey); err != nil {
			return nil, err
		}
	} else if len(cfg.SessionKey) < 32 {
		return nil, errors.New("the session key must be at least 32 bytes")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"profile", "email"}
	}
	client := &http.Client{Timeout: 15 * time.Second}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider %s: %w", cfg.Issuer, err)
	}
	return &auth{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  pub.String() + "/auth/callback",
			Scopes:       append([]string{oidc.ScopeOpenID}, cfg.Scopes...),
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		secure:   pub.Scheme == "https",
		client:   client,
	}, nil
}

// session is what the session cookie holds.
type session struct {
	User    string `json:"u"`
	Expires int64  `json:"e"`
}

// pending is what the login cookie holds while the user is at the provider.
type pending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Expires  int64  `json:"e"`
}

// cookieName uses the __Host- prefix over HTTPS, which browsers only
// accept for Secure, host-only cookies on path /.
func (a *auth) cookieName(base string) string {
	if a.secure {
		return "__Host-" + base
	}
	return base
}

func (a *auth) setCookie(w http.ResponseWriter, base string, v any, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(base), Value: a.sign(v), Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *auth) clearCookie(w http.ResponseWriter, base string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.cookieName(base), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

// sign encodes v and appends an HMAC over it.
func (a *auth) sign(v any) string {
	data, _ := json.Marshal(v)
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + base64.RawURLEncoding.EncodeToString(a.mac(payload))
}

func (a *auth) mac(payload string) []byte {
	m := hmac.New(sha256.New, a.cfg.SessionKey)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// read decodes a signed cookie into v, checking the HMAC.
func (a *auth) read(r *http.Request, base string, v any) bool {
	c, err := r.Cookie(a.cookieName(base))
	if err != nil {
		return false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, a.mac(payload)) {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	return err == nil && json.Unmarshal(data, v) == nil
}

// user returns the signed-in user, or "".
func (a *auth) user(r *http.Request, now time.Time) string {
	var s session
	if !a.read(r, "nobet_session", &s) || now.Unix() >= s.Expires || s.User == "" {
		return ""
	}
	return s.User
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// login sends the browser to the provider, remembering where to return.
func (a *auth) login(w http.ResponseWriter, r *http.Request, now time.Time) {
	p := pending{
		State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier(),
		Return: safeReturn(r.URL.Query().Get("return")), Expires: now.Add(loginTTL).Unix(),
	}
	a.setCookie(w, "nobet_login", p, loginTTL)
	target := a.oauth.AuthCodeURL(p.State, oidc.Nonce(p.Nonce), oauth2.S256ChallengeOption(p.Verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

// errDenied means the user signed in but is not allowed to view.
var errDenied = errors.New("not allowed to view nobet-web")

// callback finishes the login: it checks the state, exchanges the code
// (with the PKCE verifier), verifies the ID token and its nonce, and
// checks the user against the allowed users and groups. It returns the
// user and where to go next.
func (a *auth) callback(w http.ResponseWriter, r *http.Request, now time.Time) (user, next string, err error) {
	var p pending
	ok := a.read(r, "nobet_login", &p)
	a.clearCookie(w, "nobet_login")
	switch {
	case !ok || now.Unix() >= p.Expires:
		return "", "", errors.New("the sign-in took too long or did not start here; try again")
	case r.URL.Query().Get("error") != "":
		return "", "", fmt.Errorf("the provider refused: %s %s", r.URL.Query().Get("error"), r.URL.Query().Get("error_description"))
	case !hmac.Equal([]byte(r.URL.Query().Get("state")), []byte(p.State)):
		return "", "", errors.New("state mismatch")
	}
	ctx := oidc.ClientContext(r.Context(), a.client)
	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(p.Verifier))
	if err != nil {
		return "", "", fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", "", errors.New("the provider returned no ID token")
	}
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return "", "", fmt.Errorf("ID token: %w", err)
	}
	if !hmac.Equal([]byte(idt.Nonce), []byte(p.Nonce)) {
		return "", "", errors.New("nonce mismatch")
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("ID token claims: %w", err)
	}
	user = identity(idt.Subject, claims)
	if !a.allowed(idt.Subject, claims) {
		return user, "", errDenied
	}
	a.setCookie(w, "nobet_session", session{User: user, Expires: now.Add(a.cfg.SessionTTL).Unix()}, a.cfg.SessionTTL)
	return user, p.Return, nil
}

// identity names the user for logs: email, else preferred_username, else
// the subject.
func identity(sub string, claims map[string]any) string {
	for _, k := range []string{"email", "preferred_username"} {
		if v, ok := claims[k].(string); ok && v != "" {
			return v
		}
	}
	return sub
}

func (a *auth) allowed(sub string, claims map[string]any) bool {
	if a.cfg.AnyUser {
		return true
	}
	names := []string{sub}
	for _, k := range []string{"email", "preferred_username"} {
		if v, ok := claims[k].(string); ok && v != "" {
			if k == "email" && claims["email_verified"] == false {
				continue // an unverified address could be anyone's
			}
			names = append(names, v)
		}
	}
	for _, u := range a.cfg.Users {
		for _, n := range names {
			if strings.EqualFold(u, n) {
				return true
			}
		}
	}
	var groups []string
	switch g := claimPath(claims, a.cfg.GroupsClaim).(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		groups = []string{g}
	}
	for _, want := range a.cfg.Groups {
		for _, g := range groups {
			if g == want {
				return true
			}
		}
	}
	return false
}

// claimPath looks up a claim by a dotted path, such as Keycloak's
// realm_access.roles; a claim whose own name has a dot is found first.
func claimPath(claims map[string]any, path string) any {
	if v, ok := claims[path]; ok {
		return v
	}
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// safeReturn keeps only local paths, so a login link cannot send the user
// to another site afterwards.
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.ContainsAny(p, "\r\n") {
		return "/"
	}
	return p
}
