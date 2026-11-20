package mockokta

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"
)

// This file is the mock org's OAuth 2.0 side: the API Services app the tool
// authenticates as, the org authorization server's token and introspection
// endpoints with private_key_jwt client authentication, and the scope check
// every Management API call goes through. It models what a real org enforces,
// closely enough that a provider which signs a malformed assertion, asks for
// a scope it was not granted, or calls an endpoint its token's scopes do not
// cover fails here the way it would against Okta.

// Endpoint paths and the client assertion type (RFC 7523).
const (
	tokenPath           = "/oauth2/v1/token"
	introspectPath      = "/oauth2/v1/introspect"
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// DefaultClientID is the client ID of the mock org's service app.
const DefaultClientID = "0oa1saashoundmock7"

// AdminLogin is the human Super Admin the mock org is seeded with.
const AdminLogin = "admin@example.com"

// maxAssertionLifetime is the longest a client assertion may be valid; Okta
// refuses one whose exp is more than an hour away.
const maxAssertionLifetime = time.Hour

// allScopes is every Okta API scope the mock knows. A new mock app is granted
// all of them, okta.groups.manage included, so tests prove the provider
// narrows its own requests rather than relying on the org to refuse.
var allScopes = []string{
	"okta.appGrants.manage", "okta.appGrants.read",
	"okta.apps.manage", "okta.apps.read",
	"okta.groups.manage", "okta.groups.read",
	"okta.idps.manage", "okta.idps.read",
	"okta.logs.read",
	"okta.networkZones.manage", "okta.networkZones.read",
	"okta.orgs.manage", "okta.orgs.read",
	"okta.policies.manage", "okta.policies.read",
	"okta.roles.manage", "okta.roles.read",
	"okta.users.manage", "okta.users.read",
}

// serviceApp is the OAuth 2.0 API Services app the tool authenticates as.
type serviceApp struct {
	clientID string
	label    string
	// keys are the registered public keys, by kid.
	keys    map[string]crypto.PublicKey
	granted map[string]bool
	// roles are the admin roles assigned to the app; with none, the
	// Management API refuses every call, as a real org does.
	roles []string
	dpop  bool
}

// accessToken is one token the org issued.
type accessToken struct {
	clientID string
	scopes   []string
	issued   time.Time
	expires  time.Time
	revoked  bool
}

func (t *accessToken) valid(now time.Time) bool { return !t.revoked && now.Before(t.expires) }

// WithClientID sets the service app's client ID.
func WithClientID(id string) Option { return func(s *Server) { s.app.clientID = id } }

// WithClientKey registers k's public half on the service app under k.ID. The
// first use replaces the default key; further uses add keys.
func WithClientKey(k *Key) Option {
	return func(s *Server) {
		if !s.customKeys {
			s.app.keys = map[string]crypto.PublicKey{}
			s.customKeys = true
		}
		s.app.keys[k.ID] = k.Public()
	}
}

// WithGrantedScopes replaces the scopes the service app is granted.
func WithGrantedScopes(scopes ...string) Option {
	return func(s *Server) {
		s.app.granted = map[string]bool{}
		for _, sc := range scopes {
			s.app.granted[sc] = true
		}
	}
}

// WithoutScopes withdraws scopes from the service app.
func WithoutScopes(scopes ...string) Option {
	return func(s *Server) {
		for _, sc := range scopes {
			delete(s.app.granted, sc)
		}
	}
}

// WithClientRoles sets the admin roles assigned to the service app. The
// default is SUPER_ADMIN.
func WithClientRoles(roles ...string) Option {
	return func(s *Server) { s.app.roles = append([]string(nil), roles...) }
}

// WithTokenTTL sets the access token lifetime. Okta fixes it at an hour.
func WithTokenTTL(d time.Duration) Option { return func(s *Server) { s.tokenTTL = d } }

// WithDPoPRequired makes the app require DPoP-bound tokens, as the Admin
// Console's "Require Demonstrating Proof of Possession" setting does.
func WithDPoPRequired() Option { return func(s *Server) { s.app.dpop = true } }

// ClientID is the service app's client ID (what a target's principal holds).
func (s *Server) ClientID() string { return s.app.clientID }

// Mints is how many access tokens the org has issued.
func (s *Server) Mints() int {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	return len(s.issued)
}

// TokenScopes returns the scopes of every access token issued, in order.
func (s *Server) TokenScopes() [][]string {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	out := make([][]string, 0, len(s.issued))
	for _, t := range s.issued {
		out = append(out, append([]string(nil), t.scopes...))
	}
	return out
}

// Credentials returns every access token the org issued and every client
// assertion it received, so a canary test can prove none of them leaked.
func (s *Server) Credentials() []string {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	return append([]string(nil), s.credentials...)
}

// RevokeTokens revokes every access token issued so far, as an admin
// revoking the app's tokens would.
func (s *Server) RevokeTokens() {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	for _, t := range s.tokens {
		t.revoked = true
	}
}

// InjectTokenRateLimit makes the next n token or introspection requests
// answer 429.
func (s *Server) InjectTokenRateLimit(n int) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	s.failToken429 = n
}

// writeOAuthErr writes an RFC 6749 error.
func writeOAuthErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// serveOAuth serves the org authorization server's endpoints. It runs under
// g.mu.
func (s *Server) serveOAuth(w http.ResponseWriter, r *http.Request) {
	if s.failToken429 > 0 {
		s.failToken429--
		w.Header().Set("X-Rate-Limit-Reset", fmt.Sprint(s.now().Add(time.Second).Unix()))
		writeErr(w, http.StatusTooManyRequests, "E0000047", "API call exceeded rate limit")
		return
	}
	if r.Method != http.MethodPost {
		writeOAuthErr(w, http.StatusMethodNotAllowed, "invalid_request", "The endpoint only accepts POST.")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "The request must be form-encoded.")
		return
	}
	switch r.URL.Path {
	case tokenPath:
		s.serveToken(w, r)
	case introspectPath:
		s.serveIntrospect(w, r)
	}
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.PostForm.Get("grant_type") != "client_credentials" {
		writeOAuthErr(w, http.StatusBadRequest, "unsupported_grant_type", "The service app only supports the client_credentials grant.")
		return
	}
	if s.app.dpop && r.Header.Get("DPoP") == "" {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_dpop_proof", "The DPoP proof JWT header is missing.")
		return
	}
	clientID, err := s.authenticateClient(r, tokenPath)
	if err != nil {
		writeOAuthErr(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	if len(scopes) == 0 {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_scope", "The authorization server resource does not have any configured default scopes, 'scope' must be provided.")
		return
	}
	for _, sc := range scopes {
		if !s.app.granted[sc] {
			// A real org does not say which scope it refused.
			writeOAuthErr(w, http.StatusBadRequest, "invalid_scope", "One or more scopes are not configured for the authorization server resource.")
			return
		}
	}
	sort.Strings(scopes)
	tok := "mock-at-" + rand.Text()
	now := s.now()
	at := &accessToken{clientID: clientID, scopes: scopes, issued: now, expires: now.Add(s.tokenTTL)}
	s.tokens[tok] = at
	s.issued = append(s.issued, at)
	s.credentials = append(s.credentials, tok)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":   "Bearer",
		"expires_in":   int64(s.tokenTTL / time.Second),
		"access_token": tok,
		"scope":        strings.Join(scopes, " "),
	})
}

func (s *Server) serveIntrospect(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.authenticateClient(r, introspectPath)
	if err != nil {
		writeOAuthErr(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	at := s.tokens[r.PostForm.Get("token")]
	if at == nil || !at.valid(s.now()) || at.clientID != clientID {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	iss := orgURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"scope":      strings.Join(at.scopes, " "),
		"client_id":  at.clientID,
		"sub":        at.clientID,
		"token_type": "Bearer",
		"iat":        at.issued.Unix(),
		"exp":        at.expires.Unix(),
		"iss":        iss,
		"aud":        iss,
	})
}

// orgURL is the org base URL a request reached.
func orgURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// authenticateClient checks a private_key_jwt client assertion for the
// endpoint at path and returns the authenticated client ID. Its errors are the
// descriptions a real org gives.
func (s *Server) authenticateClient(r *http.Request, path string) (string, error) {
	if r.PostForm.Get("client_secret") != "" {
		return "", refusal("Client authentication failed: the app's client authentication is private_key_jwt.")
	}
	if r.PostForm.Get("client_assertion_type") != clientAssertionType {
		return "", refusal("The client_assertion_type is invalid.")
	}
	a := r.PostForm.Get("client_assertion")
	if a == "" {
		return "", refusal("Client authentication failed. Either the client or the client credentials are invalid.")
	}
	s.credentials = append(s.credentials, a)
	c, err := s.verifyAssertion(a, orgURL(r)+path)
	if err != nil {
		return "", err
	}
	if id := r.PostForm.Get("client_id"); id != "" && id != c.Iss {
		return "", refusal("The client_id does not match the client_assertion's issuer.")
	}
	return c.Iss, nil
}

// refusal is an org's error description, worded as a real org words it.
type refusal string

func (r refusal) Error() string { return string(r) }

// assertionClaims are the claims a client assertion must carry.
type assertionClaims struct {
	Iss string           `json:"iss"`
	Sub string           `json:"sub"`
	Aud *json.RawMessage `json:"aud"`
	Exp *int64           `json:"exp"`
	Iat *int64           `json:"iat"`
	Jti string           `json:"jti"`
}

// verifyAssertion validates a compact JWS client assertion: its signature
// with the app's registered key, and its claims (RFC 7523 section 3).
func (s *Server) verifyAssertion(a, aud string) (assertionClaims, error) {
	var c assertionClaims
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		return c, refusal("The client_assertion is not a valid JWT.")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &c) != nil {
		return c, refusal("The client_assertion is not a valid JWT.")
	}
	if c.Iss != s.app.clientID {
		return c, refusal("Client authentication failed. Either the client or the client credentials are invalid.")
	}
	if c.Sub != c.Iss {
		return c, refusal("The client_assertion sub claim must be the client_id.")
	}
	pub, err := s.app.key(hdr.Kid)
	if err != nil {
		return c, err
	}
	if err := verifyJWS(hdr.Alg, pub, parts[0]+"."+parts[1], sig); err != nil {
		return c, err
	}
	var gotAud string
	if c.Aud == nil || json.Unmarshal(*c.Aud, &gotAud) != nil || gotAud != aud {
		return c, refusal(fmt.Sprintf("The audience [aud] claim for client_assertion must be %s.", aud))
	}
	now := s.now().Unix()
	switch {
	case c.Exp == nil:
		return c, refusal("The client_assertion token has no expiration (exp) claim.")
	case *c.Exp <= now:
		return c, refusal("The client_assertion token is expired.")
	case *c.Exp > now+int64(maxAssertionLifetime/time.Second):
		return c, refusal("The client_assertion token has an expiration too far in the future.")
	case c.Iat != nil && *c.Iat > now+60:
		return c, refusal("The client_assertion token was issued in the future (iat).")
	case c.Jti == "":
		return c, refusal("The client_assertion token has no jti claim.")
	case s.jtis[c.Jti]:
		return c, refusal("The client_assertion token has already been used.")
	}
	s.jtis[c.Jti] = true
	return c, nil
}

// key finds the registered key an assertion names; with no kid, a single
// registered key is used.
func (a *serviceApp) key(kid string) (crypto.PublicKey, error) {
	if k, ok := a.keys[kid]; ok {
		return k, nil
	}
	if kid == "" && len(a.keys) == 1 {
		for _, k := range a.keys {
			return k, nil
		}
	}
	if kid == "" {
		return nil, refusal("The client_assertion token has no kid, and the app has several keys.")
	}
	return nil, refusal(fmt.Sprintf("The client_assertion token has an invalid kid (%s).", kid))
}

// verifyJWS checks a JWS signature over input.
func verifyJWS(alg string, pub crypto.PublicKey, input string, sig []byte) error {
	hashes := map[string]crypto.Hash{
		"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
		"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
	}
	h, ok := hashes[alg]
	if !ok {
		return refusal(fmt.Sprintf("The client_assertion signing algorithm %q is not supported.", alg))
	}
	hh := h.New()
	hh.Write([]byte(input))
	digest := hh.Sum(nil)
	invalid := refusal("The client_assertion signature is invalid.")
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") || rsa.VerifyPKCS1v15(k, h, digest, sig) != nil {
			return invalid
		}
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		want := map[int]string{32: "ES256", 48: "ES384", 66: "ES512"}[size]
		if alg != want || len(sig) != 2*size {
			return invalid
		}
		r, sv := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, sv) {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}

// bearer resolves a request's access token. It runs under g.mu.
func (s *Server) bearer(r *http.Request) (*accessToken, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return nil, false
	}
	at := s.tokens[tok]
	if at == nil || !at.valid(s.now()) {
		return nil, false
	}
	return at, true
}

// writeInvalidToken is a real org's answer to a missing, unknown, expired or
// revoked token (or an SSWS token where an OAuth one is expected).
func writeInvalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="IdpServer", error="invalid_token", error_description="The token is not valid."`)
	writeErr(w, http.StatusUnauthorized, "E0000011", "Invalid token provided")
}

// writeInsufficientScope is a real org's answer to a token without the scope
// an endpoint needs.
func writeInsufficientScope(w http.ResponseWriter, scope string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="IdpServer", scope=%q, error="insufficient_scope", error_description="The access token provided does not contain the required scopes."`, scope))
	writeErr(w, http.StatusForbidden, "E0000006", "You do not have permission to perform the requested action")
}

// requiredScope is the scope family a Management API call needs, per Okta's
// API reference, and whether it needs .manage (any write) or just .read (a
// GET). seg is the path after /api/v1. An unknown family needs nothing; its
// route answers 404.
func requiredScope(method string, seg []string) (family string, manage bool) {
	manage = method != http.MethodGet
	sub := ""
	if len(seg) >= 3 {
		sub = seg[2]
	}
	switch {
	case len(seg) == 0:
		return "", false
	case seg[0] == "org":
		return "okta.orgs", manage
	case seg[0] == "users" && sub == "roles":
		return "okta.roles", manage
	case seg[0] == "users":
		return "okta.users", manage
	case seg[0] == "groups":
		return "okta.groups", manage
	case seg[0] == "iam":
		return "okta.roles", manage
	case seg[0] == "zones":
		return "okta.networkZones", manage
	case seg[0] == "idps":
		return "okta.idps", manage
	case seg[0] == "apps" && sub == "grants":
		return "okta.appGrants", manage
	case seg[0] == "apps":
		return "okta.apps", manage
	case seg[0] == "policies":
		return "okta.policies", manage
	case seg[0] == "logs":
		return "okta.logs", manage
	}
	return "", false
}

// allows reports whether a token may call an endpoint of family.
func (t *accessToken) allows(family string, manage bool) bool {
	for _, sc := range t.scopes {
		if sc == family+".manage" || (!manage && sc == family+".read") {
			return true
		}
	}
	return false
}

// routeClients serves /oauth2/v1/clients/{clientId}/roles: the admin roles
// assigned to a client app.
func (s *Server) routeClients(w http.ResponseWriter, r *http.Request, at *accessToken, seg []string) {
	if len(seg) != 2 || seg[1] != "roles" || r.Method != http.MethodGet {
		writeErr(w, 404, "E0000007", "Not found: "+r.URL.Path)
		return
	}
	if !at.allows("okta.roles", false) {
		writeInsufficientScope(w, "okta.roles.read")
		return
	}
	if seg[0] != s.app.clientID {
		writeErr(w, 404, "E0000007", "client not found")
		return
	}
	items := []jsonItem{}
	for i, role := range s.app.roles {
		items = append(items, map[string]string{"id": fmt.Sprintf("irb%010d", i+1), "type": role, "status": statusActive, "assignmentType": "CLIENT"})
	}
	writeJSON(w, 200, items)
}
