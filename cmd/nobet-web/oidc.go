package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/web"
)

// oidcFlags are the flags for built-in sign-in. Secrets come from files,
// so they never show up in the process list.
type oidcFlags struct {
	issuer, clientID, secretFile, publicURL *string
	scopes, users, groups, groupsClaim      *string
	anyUser                                 *bool
	sessionKeyFile                          *string
	sessionTTL                              *time.Duration
}

func (o *oidcFlags) add(fs *flag.FlagSet) {
	o.issuer = fs.String("oidc-issuer", "", "sign users in with this OpenID Connect provider (issuer URL), instead of relying on a reverse proxy")
	o.clientID = fs.String("oidc-client-id", "", "client ID registered at the provider")
	o.secretFile = fs.String("oidc-client-secret-file", "", "file holding the client secret (none for a public client)")
	o.publicURL = fs.String("public-url", "", "URL users open, e.g. https://nobet.example.com; register <public-url>/auth/callback at the provider")
	o.scopes = fs.String("oidc-scopes", "profile,email", "scopes to request besides openid (add groups if the provider needs it for -allow-groups)")
	o.users = fs.String("allow-users", "", "users who may sign in: email, preferred_username or subject, comma-separated")
	o.groups = fs.String("allow-groups", "", "groups whose members may sign in, comma-separated (see -groups-claim)")
	o.groupsClaim = fs.String("groups-claim", "groups", "ID token claim with the user's groups; dotted paths work, e.g. realm_access.roles")
	o.anyUser = fs.Bool("allow-any-user", false, "let everyone the provider authenticates sign in")
	o.sessionKeyFile = fs.String("session-key-file", "", "file with at least 32 random bytes to sign session cookies (default: a new key each start, which signs everyone out)")
	o.sessionTTL = fs.Duration("session-ttl", 8*time.Hour, "how long a sign-in lasts")
}

// config returns the sign-in configuration, or nil without -oidc-issuer.
func (o *oidcFlags) config() (*web.OIDCConfig, error) {
	if *o.issuer == "" {
		for _, f := range []*string{o.clientID, o.secretFile, o.publicURL, o.users, o.groups, o.sessionKeyFile} {
			if *f != "" {
				return nil, errors.New("the -oidc, -allow and -session flags need -oidc-issuer")
			}
		}
		return nil, nil
	}
	if *o.clientID == "" || *o.publicURL == "" {
		return nil, errors.New("-oidc-issuer needs -oidc-client-id and -public-url")
	}
	cfg := &web.OIDCConfig{
		Issuer: *o.issuer, ClientID: *o.clientID, PublicURL: *o.publicURL,
		Scopes: list(*o.scopes), Users: list(*o.users), Groups: list(*o.groups),
		GroupsClaim: *o.groupsClaim, AnyUser: *o.anyUser, SessionTTL: *o.sessionTTL,
	}
	if len(cfg.Users) == 0 && len(cfg.Groups) == 0 && !cfg.AnyUser {
		return nil, errors.New("say who may sign in: -allow-users, -allow-groups, or -allow-any-user")
	}
	if *o.secretFile != "" {
		b, err := os.ReadFile(*o.secretFile)
		if err != nil {
			return nil, fmt.Errorf("client secret: %w", err)
		}
		cfg.ClientSecret = strings.TrimSpace(string(b))
	}
	if *o.sessionKeyFile != "" {
		b, err := os.ReadFile(*o.sessionKeyFile)
		if err != nil {
			return nil, fmt.Errorf("session key: %w", err)
		}
		if len(b) < 32 {
			return nil, fmt.Errorf("session key %s: want at least 32 bytes, e.g. head -c 32 /dev/urandom > %s", *o.sessionKeyFile, *o.sessionKeyFile)
		}
		cfg.SessionKey = b
	}
	return cfg, nil
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
