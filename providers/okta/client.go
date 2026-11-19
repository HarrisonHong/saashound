// Package okta is the Okta provider: a hand-written client over net/http (no
// vendor SDK) plus the provider boundary (ops, the System Log audit source,
// Whoami, the ownership marker and Sweep) for one Okta org.
//
// The client is deliberately small and uniform: every request carries the
// run's User-Agent marker, authenticates with the operator's SSWS token
// through transport.go (the only place the raw token is read), backs off on
// Okta's 429 rate limiting, follows Link-header pagination, and never logs or
// returns a credential or a response body. Only the method, path, status and
// latency of a call are ever traced.
package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// maxRateLimitRetries bounds how many times a 429 is retried before giving up.
const maxRateLimitRetries = 4

// maxPages bounds pagination so a misbehaving (or malicious) Link chain cannot
// loop forever.
const maxPages = 1000

// maxBodyBytes bounds how much of a response the client will read, so a huge
// body cannot exhaust memory.
const maxBodyBytes = 16 << 20

// client is the hand-written Okta REST client.
type client struct {
	base  *url.URL
	http  *http.Client
	auth  *authTransport
	clk   clock.Clock
	trace func(provider.Request)
}

// apiError is a non-2xx Okta response. A 404 wraps provider.ErrNotFound so the
// cleaner treats an already-gone object as success.
type apiError struct {
	Status  int
	Code    string
	Summary string
}

func (e *apiError) Error() string {
	if e.Summary != "" {
		return fmt.Sprintf("okta API %d (%s): %s", e.Status, e.Code, e.Summary)
	}
	return fmt.Sprintf("okta API %d", e.Status)
}

func (e *apiError) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return provider.ErrNotFound
	}
	return nil
}

// parseBase validates and canonicalises a tenant's org URL. It accepts only an
// absolute https URL with a bare host (no path, query or fragment); plain http
// is allowed solely for a loopback host, so tests can point the client at a
// local mock without TLS, while a real tenant is always reached over https.
func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("okta: tenant %q is not a URL: %w", raw, err)
	}
	if u.Host == "" || !u.IsAbs() {
		return nil, fmt.Errorf("okta: tenant must be the org URL, e.g. https://your-org.okta.com, got %q", raw)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("okta: tenant must be a bare org URL with no path or trailing slash, e.g. https://your-org.okta.com, got %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("okta: tenant %q must use https", raw)
		}
	default:
		return nil, fmt.Errorf("okta: tenant %q must use https", raw)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
}

// newClient builds a client for base, authenticating with token through the
// auth transport. It makes no network call.
func newClient(base *url.URL, auth *authTransport, clk clock.Clock, trace func(provider.Request)) *client {
	return &client{
		base:  base,
		http:  &http.Client{Transport: auth, Timeout: 60 * time.Second},
		auth:  auth,
		clk:   clk,
		trace: trace,
	}
}

// close releases the client and scrubs the token.
func (c *client) close() { c.auth.wipe() }

// get, post, put and del are the verb-shaped conveniences ops call.
func (c *client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}
func (c *client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}
func (c *client) put(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}
func (c *client) del(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// exists reports whether a GET of path returns an object: a 404 is "no", any
// other error is a real failure.
func (c *client) exists(ctx context.Context, path string) (bool, error) {
	err := c.get(ctx, path, nil)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, err
}

// isNotFound reports whether err is (or wraps) a 404.
func isNotFound(err error) bool { return errors.Is(err, provider.ErrNotFound) }

// do performs one request against path (which may carry a query string),
// encoding body as JSON if non-nil and decoding a JSON response into out if
// non-nil. It retries Okta's 429 rate limiting, honouring X-Rate-Limit-Reset.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	return c.doURL(ctx, method, c.base.String()+path, body, out)
}

func (c *client) doURL(ctx context.Context, method, rawURL string, body, out any) error {
	var encoded []byte
	if body != nil {
		var err error
		if encoded, err = json.Marshal(body); err != nil {
			return fmt.Errorf("okta: encode request: %w", err)
		}
	}
	resp, err := c.send(ctx, method, rawURL, encoded)
	if err != nil {
		return err
	}
	return c.finish(resp, out)
}

// send performs one request, retrying Okta's 429 rate limiting at most
// maxRateLimitRetries times. It is the single place a request is issued, so
// every caller shares the same bound: a 429 that outlasts the retries is
// returned as the response for the caller to finish into an apiError.
func (c *client) send(ctx context.Context, method, rawURL string, encoded []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		start := c.clk.Now()
		var reader io.Reader
		if encoded != nil {
			reader = bytes.NewReader(encoded)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
		if err != nil {
			return nil, fmt.Errorf("okta: build request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if encoded != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		// Every request is attributable: the run's User-Agent marker.
		req.Header.Set("User-Agent", provider.UserAgent(ctx))

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("okta: %s %s: %w", method, redactPath(rawURL), err)
		}
		c.traceReq(method, rawURL, resp.StatusCode, c.clk.Now().Sub(start))

		if resp.StatusCode != http.StatusTooManyRequests || attempt >= maxRateLimitRetries {
			return resp, nil
		}
		wait := rateLimitWait(resp, c.clk.Now())
		_ = drainClose(resp.Body)
		if err := c.clk.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// finish reads and closes the response, mapping a non-2xx status to an
// apiError (with its Okta error code) and decoding a success body into out.
func (c *client) finish(resp *http.Response, out any) error {
	defer drainClose(resp.Body)
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("okta: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		ae := &apiError{Status: resp.StatusCode}
		var oe struct {
			ErrorCode    string `json:"errorCode"`
			ErrorSummary string `json:"errorSummary"`
		}
		if json.Unmarshal(data, &oe) == nil {
			ae.Code, ae.Summary = oe.ErrorCode, oe.ErrorSummary
		}
		return ae
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("okta: decode response: %w", err)
		}
	}
	return nil
}

// list follows Link-header pagination from path, accumulating every element of
// each JSON-array page. It never leaves the org's own host.
func (c *client) list(ctx context.Context, path string) ([]json.RawMessage, error) {
	return c.listUpTo(ctx, path, math.MaxInt)
}

// listUpTo follows pagination from path but stops once it has max elements, so
// counting against a very large org cannot page without bound.
func (c *client) listUpTo(ctx context.Context, path string, max int) ([]json.RawMessage, error) {
	next := c.base.String() + path
	var out []json.RawMessage
	for page := 0; next != "" && page < maxPages && len(out) < max; page++ {
		resp, err := c.send(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if err := c.finish(resp, &items); err != nil {
			return nil, err
		}
		out = append(out, items...)
		following, err := c.nextLink(resp)
		if err != nil {
			return nil, err
		}
		next = following
	}
	return out, nil
}

// nextLink returns the rel="next" URL, but only when it points at the org's
// own host: a pagination link to anywhere else is refused.
func (c *client) nextLink(resp *http.Response) (string, error) {
	for _, h := range resp.Header.Values("Link") {
		for _, part := range strings.Split(h, ",") {
			part = strings.TrimSpace(part)
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			lt, gt := strings.Index(part, "<"), strings.Index(part, ">")
			if lt < 0 || gt < lt {
				continue
			}
			raw := part[lt+1 : gt]
			u, err := url.Parse(raw)
			if err != nil {
				return "", fmt.Errorf("okta: malformed pagination link %q", raw)
			}
			if u.Host != "" && u.Host != c.base.Host {
				return "", fmt.Errorf("okta: pagination link points off-tenant to %q", u.Host)
			}
			if u.Host == "" { // relative
				raw = c.base.String() + "/" + strings.TrimPrefix(raw, "/")
			}
			return raw, nil
		}
	}
	return "", nil
}

func (c *client) traceReq(method, rawURL string, status int, d time.Duration) {
	if c.trace == nil {
		return
	}
	c.trace(provider.Request{Method: method, Path: redactPath(rawURL), Status: status, Duration: d})
}

// redactPath strips the host (which is never secret but is noise) and any
// query string from a URL, leaving the method-path shape that -v shows. It
// never includes a header or body, so a token cannot reach the trace.
func redactPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.RawQuery != "" {
		return u.Path + "?" + redactQuery(u.RawQuery)
	}
	return u.Path
}

// redactQuery keeps query keys but blanks values, so a value can never leak.
func redactQuery(raw string) string {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	// Stable order for readable traces.
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"=…")
	}
	return strings.Join(parts, "&")
}

// rateLimitWait computes how long to wait after a 429, from X-Rate-Limit-Reset
// (an epoch second), clamped to a sane range.
func rateLimitWait(resp *http.Response, now time.Time) time.Duration {
	wait := time.Second
	if v := resp.Header.Get("X-Rate-Limit-Reset"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Unix(sec, 0).Sub(now); d > 0 {
				wait = d + 500*time.Millisecond
			}
		}
	}
	if wait < 100*time.Millisecond {
		wait = 100 * time.Millisecond
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	return wait
}

func drainClose(rc io.ReadCloser) error {
	if rc == nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxBodyBytes))
	return rc.Close()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
