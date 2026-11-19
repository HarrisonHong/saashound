package mockokta

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
)

// Server is a running mock Okta org.
type Server struct {
	http      *httptest.Server
	g         *guarded
	token     string
	principal string
	now       func() time.Time
	lag       time.Duration
	lagByType map[string]time.Duration
	drop      map[string]bool

	// fail429 makes the next n API calls answer 429, to exercise the client's
	// rate-limit backoff. Guarded by g.mu.
	fail429 int
}

// Option configures a Server.
type Option func(*Server)

// WithToken sets the SSWS token the org accepts. The default is "mock-token".
func WithToken(tok string) Option { return func(s *Server) { s.token = tok } }

// WithPrincipal sets the login of the token's user (what /users/me returns and
// the guardrail matches against the target's principal).
func WithPrincipal(login string) Option { return func(s *Server) { s.principal = login } }

// WithClock makes event timestamps and log visibility follow now, so tests on
// a fake clock see events inside their query window.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithLag delays every event's visibility to the /logs API.
func WithLag(d time.Duration) Option { return func(s *Server) { s.lag = d } }

// WithLagByType delays one event type's visibility.
func WithLagByType(eventType string, d time.Duration) Option {
	return func(s *Server) { s.lagByType[eventType] = d }
}

// WithDrop makes the org never log an event type (a platform coverage gap).
func WithDrop(eventType string) Option {
	return func(s *Server) { s.drop[eventType] = true }
}

// New starts a mock org seeded with the token's user (so /users/me and the
// guardrail work) and nothing else. Close it when done.
func New(opts ...Option) *Server {
	s := &Server{
		g:         &guarded{s: newState()},
		token:     "mock-token",
		principal: "okta-bot@example.com",
		now:       time.Now,
		lagByType: map[string]time.Duration{},
		drop:      map[string]bool{},
	}
	for _, o := range opts {
		o(s)
	}
	st := s.g.s
	st.Org = Org{ID: st.newID("00o"), Subdomain: "dev-mock", CompanyName: "Mock Org", Status: statusActive}
	me := &User{ID: st.newID("00u"), Status: statusActive, Created: s.now().UTC(),
		Profile: UserProfile{Login: s.principal, Email: s.principal, FirstName: "Mock", LastName: "Bot"}}
	st.Users[me.ID] = me
	st.Roles[st.newID("ra")] = &RoleAssignment{ID: "sysadmin", Type: "SUPER_ADMIN", Status: statusActive, userID: me.ID}
	s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// URL is the org base URL (what a target's tenant field holds in tests).
func (s *Server) URL() string { return s.http.URL }

// Close stops the server.
func (s *Server) Close() { s.http.Close() }

// Snapshot returns the tenant's objects without its System Log.
func (s *Server) Snapshot() json.RawMessage {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	return s.g.s.snapshot()
}

// State runs fn with the locked state, for test setup and assertions.
func (s *Server) State(fn func(*State)) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	fn(s.g.s)
}

// InjectRateLimit makes the next n API calls answer 429.
func (s *Server) InjectRateLimit(n int) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	s.fail429 = n
}

// PlaceMarker plays a tenant admin creating the ownership group in the admin
// console (so it carries a browser User-Agent, never the tool's).
func (s *Server) PlaceMarker(name, value string) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	st := s.g.s
	for _, g := range st.Groups {
		if g.Profile.Name == name {
			g.Profile.Description = value
			return
		}
	}
	g := &Group{ID: st.newID("00g"), Type: "OKTA_GROUP", Profile: GroupProfile{Name: name, Description: value}}
	st.Groups[g.ID] = g
	s.emit(st, "Mozilla/5.0 (X11; Linux x86_64)", "group.lifecycle.create", "Add group",
		target{ID: g.ID, Type: "UserGroup", DisplayName: name})
}

// oktaError is Okta's error envelope.
type oktaError struct {
	ErrorCode    string `json:"errorCode"`
	ErrorSummary string `json:"errorSummary"`
	ErrorID      string `json:"errorId"`
}

func writeErr(w http.ResponseWriter, status int, code, summary string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oktaError{ErrorCode: code, ErrorSummary: summary})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// serve routes one request. Every mutating handler runs under g.mu and records
// its System Log event with the request's User-Agent.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.g.mu.Lock()
	if s.fail429 > 0 {
		s.fail429--
		reset := s.now().Add(time.Second).Unix()
		s.g.mu.Unlock()
		w.Header().Set("X-Rate-Limit-Limit", "600")
		w.Header().Set("X-Rate-Limit-Remaining", "0")
		w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(reset, 10))
		writeErr(w, http.StatusTooManyRequests, "E0000047", "API call exceeded rate limit")
		return
	}
	s.g.mu.Unlock()

	// SSWS token auth: the one credential check, as a real org's does.
	auth := r.Header.Get("Authorization")
	if auth != "SSWS "+s.token {
		writeErr(w, http.StatusUnauthorized, "E0000011", "Invalid token provided")
		return
	}
	ua := r.Header.Get("User-Agent")

	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	st := s.g.s
	seg := splitPath(r.URL.Path)
	s.route(w, r, st, ua, seg)
}

// splitPath returns the non-empty path segments after /api/v1.
func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/api/v1")
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	// seg[0] selects the resource family.
	switch {
	case len(seg) == 1 && seg[0] == "org":
		writeJSON(w, 200, st.Org)
	case seg[0] == "users":
		s.routeUsers(w, r, st, ua, seg[1:])
	case seg[0] == "groups":
		s.routeGroups(w, r, st, ua, seg[1:])
	case seg[0] == "iam":
		s.routeIam(w, r, st, ua, seg[1:])
	case seg[0] == "zones":
		s.routeZones(w, r, st, ua, seg[1:])
	case seg[0] == "idps":
		s.routeIdps(w, r, st, ua, seg[1:])
	case seg[0] == "apps":
		s.routeApps(w, r, st, ua, seg[1:])
	case seg[0] == "policies":
		s.routePolicies(w, r, st, ua, seg[1:])
	case len(seg) == 1 && seg[0] == "logs":
		s.routeLogs(w, r, st)
	default:
		writeErr(w, 404, "E0000007", "Not found: "+r.URL.Path)
	}
}

// ---- helpers shared across handlers -----------------------------------

func decodeBody(r *http.Request, v any) bool {
	if r.Body == nil {
		return false
	}
	return json.NewDecoder(r.Body).Decode(v) == nil
}

func queryParam(r *http.Request, k string) string { return r.URL.Query().Get(k) }

// paginate writes items as a JSON array, emitting a Link: rel="next" header
// (the real Okta pagination contract) when more than pageSize remain, so the
// client's Link-following is exercised.
func (s *Server) paginate(w http.ResponseWriter, r *http.Request, items []json.RawMessage) {
	const pageSize = 2
	start := 0
	if a := queryParam(r, "after"); a != "" {
		start, _ = strconv.Atoi(a)
	}
	limit := pageSize
	if l := queryParam(r, "limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n < pageSize {
			limit = n
		}
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	if end < len(items) {
		next := *r.URL
		q := next.Query()
		q.Set("after", strconv.Itoa(end))
		next.RawQuery = q.Encode()
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		// Okta returns an absolute next URL; mirror that so the client's
		// Link-following (and its same-host guard) is exercised.
		w.Header().Set("Link", fmt.Sprintf(`<%s://%s%s>; rel="next"`, scheme, r.Host, next.RequestURI()))
	}
	page := items[start:end]
	if page == nil {
		page = []json.RawMessage{}
	}
	writeJSON(w, 200, page)
}
