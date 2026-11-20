package okta

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
)

// This file is the okta provider's credential boundary, and the only file in
// it that reads a raw secret (the policy test allows Reveal() solely in a
// provider's transport.go).
//
// The operator supplies the private key of an OAuth 2.0 API Services app
// (from an environment variable or a 0600 key file; never a flag, never
// written anywhere by the tool). Each session signs a short-lived, single-use
// private_key_jwt client assertion with it and exchanges that at the org's
// token endpoint for an access token carrying exactly the scopes the session
// needs (the client credentials grant). The token lives in memory only, is
// reused until shortly before it expires (Okta fixes the lifetime at an hour),
// and is sent as `Authorization: Bearer <token>` to the org and nowhere else.
// No key, assertion or token ever reaches a log, a trace, the journal, an
// error or the disk: traces carry method, path, status and latency only.

// maxOAuthBody bounds an OAuth endpoint response.
const maxOAuthBody = 1 << 20

// tokenConfig is what a session's token source is built from.
type tokenConfig struct {
	base     *url.URL
	clientID string
	// key is the private key, PEM or JWK.
	key secret.Value
	// keyID is options.key_id: the kid to send when the key does not carry one.
	keyID  string
	scopes sessionScopes
	clk    clock.Clock
	trace  func(provider.Request)
	// rt is the underlying transport; nil means http.DefaultTransport.
	rt http.RoundTripper
}

// tokenSource mints, caches and refreshes one session's access token.
type tokenSource struct {
	cfg  tokenConfig
	http *http.Client
	alg  string
	kid  string

	mu sync.Mutex
	// token is the current access token, empty until the first call.
	token secret.Value
	// granted are the scopes the current token carries.
	granted  []string
	lifetime time.Duration
	// refreshAt is when the current token is replaced.
	refreshAt time.Time
	// request is the scope set every mint after the first asks for: the
	// required scopes plus the optional ones the app turned out to hold.
	request []string
}

// newTokenSource parses the key once, so a malformed key fails Open rather
// than the first call, and drops the parsed form straight away.
func newTokenSource(cfg tokenConfig) (*tokenSource, error) {
	k, err := cfg.signingKey()
	if err != nil {
		return nil, err
	}
	rt := cfg.rt
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &tokenSource{
		cfg:  cfg,
		http: &http.Client{Transport: rt, Timeout: 30 * time.Second, CheckRedirect: noRedirects},
		alg:  k.alg,
		kid:  k.kid,
	}, nil
}

// signingKey parses the private key for one signature. The revealed copy is
// cleared as soon as it is parsed.
func (c tokenConfig) signingKey() (*signingKey, error) {
	raw := []byte(c.key.Reveal())
	defer clear(raw)
	return parseSigningKey(raw, c.keyID)
}

// assertionClaims are the private_key_jwt client assertion's claims (RFC
// 7523 section 3): the app asserts itself (iss = sub = client ID) to exactly
// one endpoint (aud), for a few minutes, once (jti).
type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// assertion signs a fresh client assertion for the endpoint at path.
func (s *tokenSource) assertion(path string) (string, error) {
	k, err := s.cfg.signingKey()
	if err != nil {
		return "", err
	}
	now := s.cfg.clk.Now()
	return k.sign(assertionClaims{
		Iss: s.cfg.clientID,
		Sub: s.cfg.clientID,
		Aud: s.cfg.base.String() + path,
		Iat: now.Add(-assertionBackdate).Unix(),
		Exp: now.Add(assertionLifetime).Unix(),
		Jti: rand.Text(),
	})
}

// authorization returns the Authorization header value for one request,
// minting or refreshing the token first if needed. The header is built under
// the lock, so a concurrent refresh cannot wipe the token mid-copy.
func (s *tokenSource) authorization(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLocked(ctx); err != nil {
		return "", err
	}
	return "Bearer " + s.token.Reveal(), nil
}

// scopes returns the scopes this session's token carries.
func (s *tokenSource) scopes(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLocked(ctx); err != nil {
		return nil, err
	}
	return append([]string(nil), s.granted...), nil
}

// tokenLifetime is the current token's lifetime as the org stated it.
func (s *tokenSource) tokenLifetime() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lifetime
}

// invalidate drops the current token, so the next request mints a new one.
// The client calls it when the org answers 401: the token was revoked or
// expired early.
func (s *tokenSource) invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token.Wipe()
	s.token = secret.Value{}
}

// wipe scrubs the token and the key from memory.
func (s *tokenSource) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token.Wipe()
	s.cfg.key.Wipe()
}

// describe says how the session authenticates, for display.
func (s *tokenSource) describe() string {
	d := "OAuth 2.0 service app, private_key_jwt (" + s.alg
	if s.kid != "" {
		d += ", key " + s.kid
	}
	return d + ")"
}

func (s *tokenSource) ensureLocked(ctx context.Context) error {
	if !s.token.Empty() && s.cfg.clk.Now().Before(s.refreshAt) {
		return nil
	}
	var (
		tok issued
		err error
	)
	if s.request == nil {
		tok, err = s.firstMint(ctx)
	} else if tok, err = s.exchange(ctx, s.request); err != nil {
		err = s.explain(err)
	}
	if err != nil {
		return err
	}
	s.token.Wipe()
	s.token, s.granted, s.lifetime = tok.value, tok.scopes, tok.lifetime
	s.refreshAt = tok.issued.Add(tok.lifetime - min(refreshMargin, tok.lifetime/5))
	return nil
}

// firstMint asks for every scope the session may use in one request, which
// is all it takes when the app holds them. Only if the org refuses a scope
// does it work out which: a missing required scope fails the session, naming
// it; a missing optional one is left out (or replaced by its read fallback)
// of this and every later mint.
func (s *tokenSource) firstMint(ctx context.Context) (issued, error) {
	sc := s.cfg.scopes
	all := sc.all()
	tok, err := s.exchange(ctx, all)
	if err == nil {
		s.request = all
		return tok, nil
	}
	if !isScopeRefusal(err) {
		return issued{}, s.explain(err)
	}
	refused := err

	// The required scopes: one request settles it when they are all granted.
	ok := false
	if len(sc.optional) > 0 {
		if ok, err = s.grantable(ctx, sc.required...); err != nil {
			return issued{}, err
		}
	}
	if !ok {
		var missing []string
		for _, r := range sc.required {
			granted, err := s.grantable(ctx, r)
			if err != nil {
				return issued{}, err
			}
			if !granted {
				missing = append(missing, r)
			}
		}
		if len(missing) == 0 {
			// Every scope is granted alone but not together: report the
			// org's own answer rather than guess.
			return issued{}, s.explain(refused)
		}
		return issued{}, missingScopesError(s.cfg.clientID, missing)
	}

	// The optional scopes, one by one, each falling back to its read scope.
	request := append([]string{}, sc.required...)
	for _, o := range sc.optional {
		candidates := []string{o}
		if fb, ok := sc.fallback[o]; ok {
			candidates = append(candidates, fb)
		}
		for _, c := range candidates {
			granted, err := s.grantable(ctx, c)
			if err != nil {
				return issued{}, err
			}
			if granted {
				request = append(request, c)
				break
			}
		}
	}
	s.request = request
	if tok, err = s.exchange(ctx, request); err != nil {
		return issued{}, s.explain(err)
	}
	return tok, nil
}

// grantable reports whether the app may hold scopes together, by asking for a
// token and dropping it unused. Only a refusal of the scopes means false; any
// other failure is returned, explained.
func (s *tokenSource) grantable(ctx context.Context, scopes ...string) (bool, error) {
	tok, err := s.exchange(ctx, scopes)
	switch {
	case err == nil:
		tok.value.Wipe()
		return true, nil
	case isScopeRefusal(err):
		return false, nil
	}
	return false, s.explain(err)
}

// issued is one minted access token.
type issued struct {
	value    secret.Value
	scopes   []string
	lifetime time.Duration
	issued   time.Time
}

// tokenResponse is the token endpoint's success body (RFC 6749 section 5.1).
type tokenResponse struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

// exchange runs the client credentials grant for scopes, authenticating with
// a fresh client assertion. An org refusal comes back as *oauthError.
func (s *tokenSource) exchange(ctx context.Context, scopes []string) (issued, error) {
	scopes = scopeSet(scopes...)
	start := s.cfg.clk.Now()
	var resp tokenResponse
	err := s.post(ctx, tokenPath, func() (url.Values, error) {
		a, err := s.assertion(tokenPath)
		if err != nil {
			return nil, err
		}
		return url.Values{
			"grant_type":            {"client_credentials"},
			"scope":                 {strings.Join(scopes, " ")},
			"client_assertion_type": {clientAssertionType},
			"client_assertion":      {a},
		}, nil
	}, &resp)
	value := secret.New(resp.AccessToken)
	resp.AccessToken = ""
	if err != nil {
		value.Wipe()
		return issued{}, err
	}
	switch {
	case strings.EqualFold(resp.TokenType, "DPoP"):
		value.Wipe()
		return issued{}, &oauthError{Status: http.StatusOK, Code: "invalid_dpop_proof",
			Description: "the org issued a DPoP-bound token, not a Bearer token"}
	case !strings.EqualFold(resp.TokenType, "Bearer") || value.Empty():
		value.Wipe()
		return issued{}, &authError{fmt.Sprintf("okta: the org's token response carried no usable Bearer token (token_type %q); "+
			"check that the tenant is the Okta org URL and that nothing between here and the org rewrites its responses", resp.TokenType)}
	}
	lifetime := time.Duration(resp.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = refreshMargin // unknown: assume short and refresh early
	}
	got := scopeSet(strings.Fields(resp.Scope)...)
	if len(got) == 0 {
		got = scopes
	}
	return issued{value: value, scopes: got, lifetime: lifetime, issued: start}, nil
}

// introspection is the subset of an RFC 7662 introspection response Whoami
// uses: the org's own statement of which client the token belongs to and
// what it may do.
type introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"iss"`
}

// introspect asks the org about this session's token, authenticating as the
// app with a fresh client assertion.
func (s *tokenSource) introspect(ctx context.Context) (introspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureLocked(ctx); err != nil {
		return introspection{}, err
	}
	var in introspection
	err := s.post(ctx, introspectPath, func() (url.Values, error) {
		a, err := s.assertion(introspectPath)
		if err != nil {
			return nil, err
		}
		return url.Values{
			"token":                 {s.token.Reveal()},
			"token_type_hint":       {"access_token"},
			"client_assertion_type": {clientAssertionType},
			"client_assertion":      {a},
		}, nil
	}, &in)
	if err != nil {
		return introspection{}, s.explain(err)
	}
	return in, nil
}

// post sends one form-encoded request to an OAuth endpoint and decodes a 200
// answer into out. form is called per attempt, so every attempt carries its
// own single-use assertion. It backs off on 429 like the API client and maps
// any other non-200 answer to *oauthError. The body it read is cleared.
func (s *tokenSource) post(ctx context.Context, path string, form func() (url.Values, error), out any) error {
	endpoint := s.cfg.base.String() + path
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		v, err := form()
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(v.Encode()))
		if err != nil {
			return fmt.Errorf("okta: build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", provider.UserAgent(ctx))
		start := s.cfg.clk.Now()
		resp, err := s.http.Do(req)
		if err != nil {
			return &authError{fmt.Sprintf("okta: POST %s: %v", path, unwrapURLError(err))}
		}
		if s.cfg.trace != nil {
			s.cfg.trace(provider.Request{Method: http.MethodPost, Path: path, Status: resp.StatusCode, Duration: s.cfg.clk.Now().Sub(start)})
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitRetries {
			wait := rateLimitWait(resp, s.cfg.clk.Now())
			_ = drainClose(resp.Body)
			if err := s.cfg.clk.Sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return decodeOAuth(resp, path, out)
	}
}

// decodeOAuth reads and closes an OAuth endpoint response, decoding a 200
// into out and anything else into *oauthError. The bytes read, which may hold
// a token, are cleared before it returns.
func decodeOAuth(resp *http.Response, path string, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthBody))
	_ = drainClose(resp.Body)
	defer clear(body)
	if err != nil {
		return fmt.Errorf("okta: read %s response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		oe := &oauthError{Status: resp.StatusCode}
		var e struct {
			Error        string `json:"error"`
			Description  string `json:"error_description"`
			ErrorCode    string `json:"errorCode"`
			ErrorSummary string `json:"errorSummary"`
		}
		if json.Unmarshal(body, &e) == nil {
			oe.Code, oe.Description = e.Error, e.Description
			if oe.Code == "" && oe.Description == "" {
				// Not an RFC 6749 error: Okta's own envelope, as a rate
				// limit or a wrong path answers with.
				oe.Description = strings.TrimSpace(e.ErrorCode + " " + e.ErrorSummary)
			}
		}
		return oe
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &authError{"okta: malformed response from " + path}
	}
	return nil
}

// explain maps an org refusal to the operator-facing error; any other error
// passes through.
func (s *tokenSource) explain(err error) error {
	var oe *oauthError
	if errors.As(err, &oe) {
		return explain(oe, s.cfg.clientID, s.kid)
	}
	return err
}

func (e *oauthError) Error() string {
	return fmt.Sprintf("okta: OAuth endpoint answered %d (%s): %s", e.Status, e.Code, sanitize(e.Description))
}

// isScopeRefusal reports whether the org refused the requested scopes.
func isScopeRefusal(err error) bool {
	var oe *oauthError
	return errors.As(err, &oe) && oe.Code == "invalid_scope"
}

// unwrapURLError drops net/http's "Post <url>:" prefix, which repeats the
// endpoint, and keeps the cause.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// noRedirects stops a client following a redirect: Okta's API and OAuth
// endpoints never redirect, and following one could carry a request, or the
// credential the transport adds to every hop, somewhere else.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// authTransport sets the session's bearer token on every request to the org.
type authTransport struct {
	base http.RoundTripper
	src  *tokenSource
}

func newAuthTransport(base http.RoundTripper, src *tokenSource) *authTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &authTransport{base: base, src: src}
}

// RoundTrip adds the Authorization header to a clone of the request, so the
// caller's request is never mutated. A request for any host but the org's is
// refused outright: the token never leaves the tenant it was minted for.
func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	org := t.src.cfg.base
	if r.URL.Scheme != org.Scheme || r.URL.Host != org.Host {
		closeBody(r)
		return nil, fmt.Errorf("okta: refusing to send the org's credential to %s://%s", r.URL.Scheme, r.URL.Host)
	}
	h, err := t.src.authorization(r.Context())
	if err != nil {
		closeBody(r)
		return nil, err
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", h)
	return t.base.RoundTrip(r2)
}

// closeBody honours the RoundTripper contract on a request not sent.
func closeBody(r *http.Request) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
}

// wipe scrubs the token and the key from memory.
func (t *authTransport) wipe() { t.src.wipe() }
