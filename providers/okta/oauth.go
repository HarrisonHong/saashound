package okta

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
)

// This file holds the OAuth 2.0 vocabulary of the okta provider that involves
// no secret: which scopes a session asks for, and what an operator is told
// when the org refuses. Everything that touches the private key, a signed
// assertion or an access token is in transport.go.

// OAuth endpoints of the org authorization server, and the client assertion
// type for private_key_jwt (RFC 7523).
const (
	tokenPath           = "/oauth2/v1/token"
	introspectPath      = "/oauth2/v1/introspect"
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// assertionLifetime is how long a signed client assertion is valid. Okta
// accepts at most an hour; each one is single-use (its jti) and sent once, so
// a few minutes covers clock skew and nothing more.
const assertionLifetime = 5 * time.Minute

// assertionBackdate is how far before now an assertion says it was issued.
// Okta refuses an iat later than the moment it receives the request, so a
// local clock a little fast would otherwise fail every run.
const assertionBackdate = 30 * time.Second

// refreshMargin is how long before its expiry a token is replaced, so a call
// never goes out on a token about to lapse. It is capped at a fifth of the
// lifetime so a short-lived token is still reused.
const refreshMargin = 5 * time.Minute

// baseScopes are what every session reads outside the ops: the org and the
// lab-size user count for Whoami, and the ownership-marker group. They are
// read-only. No session ever asks for okta.groups.manage, so even a service
// app granted it cannot create the marker group with a token this tool holds:
// a token alone cannot self-authorise.
var baseScopes = []string{scopeOrgsRead, scopeUsersRead, scopeGroupsRead}

// sessionScopes is what one session asks the org for.
type sessionScopes struct {
	// required must all be granted, or the session fails before any call.
	required []string
	// optional are requested only if granted.
	optional []string
	// fallback maps an optional okta.X.manage scope to okta.X.read, asked
	// for only if the manage scope is not granted: a manage scope implies
	// read, so a session that cannot get it can still list what it may see
	// (sweep relies on this), without ever carrying both.
	fallback map[string]string
}

// planSessionScopes adds the base scopes to what the caller needs. A
// read-only session asks for each okta.X.manage scope's okta.X.read instead.
func planSessionScopes(required, optional []string, readOnly bool) sessionScopes {
	if readOnly {
		required, optional = readCounterparts(required), readCounterparts(optional)
	}
	req := scopeSet(append(append([]string{}, baseScopes...), required...)...)
	ss := sessionScopes{required: req, fallback: map[string]string{}}
	for _, s := range scopeSet(optional...) {
		if containsStr(req, s) {
			continue
		}
		ss.optional = append(ss.optional, s)
		if family, ok := strings.CutSuffix(s, ".manage"); ok && !containsStr(req, family+".read") {
			ss.fallback[s] = family + ".read"
		}
	}
	return ss
}

// readCounterparts maps each okta.X.manage scope to okta.X.read.
func readCounterparts(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if family, ok := strings.CutSuffix(s, ".manage"); ok {
			s = family + ".read"
		}
		out = append(out, s)
	}
	return out
}

// all is every scope the session asks for first, required first.
func (s sessionScopes) all() []string {
	return append(append([]string{}, s.required...), s.optional...)
}

// scopeSet returns the distinct scopes, sorted.
func scopeSet(scopes ...string) []string {
	set := map[string]bool{}
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// hasScope reports whether a token's scopes allow reading (or, if manage is
// true, managing) the scope family, e.g. "okta.users". A manage scope implies
// read.
func hasScope(scopes []string, family string, manage bool) bool {
	if containsStr(scopes, family+".manage") {
		return true
	}
	return !manage && containsStr(scopes, family+".read")
}

// authError is a credential problem explained for the operator. It never
// holds any part of the key, an assertion or a token.
type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

// oauthError is a non-2xx answer from the org's token or introspection
// endpoint (RFC 6749 section 5.2).
type oauthError struct {
	Status      int
	Code        string
	Description string
}

// explain turns a token-endpoint refusal into what the operator must fix.
func explain(oe *oauthError, clientID, keyID string) error {
	desc := sanitize(oe.Description)
	detail := oe.Code
	if desc != "" {
		detail += ": " + desc
	}
	switch {
	case oe.Code == "invalid_dpop_proof" || oe.Code == "use_dpop_nonce":
		return &authError{fmt.Sprintf("okta: service app %s requires DPoP-bound tokens, which saashound does not use (%s); "+
			"in the app's General Settings, clear \"Require Demonstrating Proof of Possession (DPoP) header in token requests\"", clientID, detail)}
	case oe.Code == "invalid_client":
		kid := "with no key ID (set options.key_id, or use the JWK the console generated, which carries one)"
		if keyID != "" {
			kid = "with key ID " + keyID
		}
		return &authError{fmt.Sprintf("okta: the org did not accept principal (client ID) %s with this private key, signed %s (%s); "+
			"check that the target's principal is the API Services app's client ID, that the app's client authentication is "+
			"\"Public key / Private key\", and that this key's public half is registered on the app", clientID, kid, detail)}
	case oe.Code == "unauthorized_client" || oe.Code == "unsupported_grant_type":
		return &authError{fmt.Sprintf("okta: app %s may not use the client credentials grant (%s); it must be an API Services app", clientID, detail)}
	case oe.Code == "" && oe.Status == http.StatusNotFound:
		return &authError{"okta: the org has no OAuth endpoint here (HTTP 404); check that the target's tenant is the Okta org URL, e.g. https://your-org.okta.com"}
	case oe.Status == http.StatusTooManyRequests:
		return &authError{"okta: the org's OAuth endpoint is still rate limiting this client (HTTP 429) after the tool backed off; try again in a minute"}
	default:
		msg := fmt.Sprintf("okta: the org refused a token for service app %s (HTTP %d", clientID, oe.Status)
		if detail != "" {
			msg += ", " + detail
		}
		return &authError{msg + ")"}
	}
}

// missingScopesError says which required scopes the app was not granted.
func missingScopesError(clientID string, missing []string) error {
	return &authError{fmt.Sprintf("okta: service app %s is not granted %s, which this command needs; "+
		"a Super Admin grants scopes in the Admin Console under Applications > Applications > (the app) > Okta API Scopes",
		clientID, strings.Join(missing, " "))}
}

// maxDescription bounds how much of the org's error text is repeated.
const maxDescription = 300

// sanitize keeps an org-supplied error description printable and short.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > maxDescription {
		s = string(r[:maxDescription]) + "…"
	}
	return s
}

// fmtLifetime renders a token lifetime compactly: 1h, 59m, 1h30m.
func fmtLifetime(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "under a minute"
	}
	h, m := d/time.Hour, (d%time.Hour)/time.Minute
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
