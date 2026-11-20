package mockgithub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
)

// Server is a running mock GitHub organization.
type Server struct {
	http      *httptest.Server
	g         *guarded
	token     string
	principal string
	org       string
	now       func() time.Time
	// clockOffset is how far the org's clock runs ahead of now.
	clockOffset time.Duration
	lag         time.Duration
	lagByType   map[string]time.Duration
	drop        map[string]bool
	seed        []string // extra member logins to create at New
	// recordUA is what the audit log records for a request's User-Agent.
	recordUA func(string) string
	// hashToken records hashed_token on every event, as GitHub does for
	// requests made with a token.
	hashToken bool

	// fail403 makes the next n API calls answer a primary rate-limit 403, to
	// exercise the client's back-off. Guarded by g.mu.
	fail403 int
}

// Option configures a Server.
type Option func(*Server)

// WithToken sets the bearer token the org accepts. The default is "mock-token".
func WithToken(tok string) Option { return func(s *Server) { s.token = tok } }

// WithPrincipal sets the login of the token's user (what /user returns and the
// guardrail matches against the target's principal).
func WithPrincipal(login string) Option { return func(s *Server) { s.principal = login } }

// WithOrg sets the organization login the server serves.
func WithOrg(slug string) Option { return func(s *Server) { s.org = slug } }

// WithClock makes event timestamps and log visibility follow now, so tests on
// a fake clock see events inside their query window.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithClockOffset makes the org's clock run d ahead of the clock (behind it
// when d is negative): events are stamped with the offset, while when they
// become readable still follows the clock.
func WithClockOffset(d time.Duration) Option { return func(s *Server) { s.clockOffset = d } }

// WithLag delays every event's visibility to the audit-log API.
func WithLag(d time.Duration) Option { return func(s *Server) { s.lag = d } }

// WithLagByType delays one action's visibility.
func WithLagByType(action string, d time.Duration) Option {
	return func(s *Server) { s.lagByType[action] = d }
}

// WithDrop makes the org never log an action (a platform coverage gap).
func WithDrop(action string) Option { return func(s *Server) { s.drop[action] = true } }

// WithRecordedUserAgent makes the audit log record record(ua) as an event's
// user_agent instead of the request's User-Agent, to model an org that drops
// it (return "") or truncates it.
func WithRecordedUserAgent(record func(ua string) string) Option {
	return func(s *Server) { s.recordUA = record }
}

// WithoutHashedToken makes the audit log record no hashed_token, to model an
// event shape that does not identify the credential.
func WithoutHashedToken() Option { return func(s *Server) { s.hashToken = false } }

// HashedToken is the hashed_token GitHub records for a request made with
// token: the base64-encoded SHA-256 of the token.
func HashedToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// WithMember seeds an extra organization member with role "member".
func WithMember(login string) Option {
	return func(s *Server) { s.seed = append(s.seed, login) }
}

// seed holds extra member logins to create after the base org is built.
// (Stored on the server so options can append before New seeds them.)
func (s *Server) seedMembers() {
	st := s.g.s
	for _, login := range s.seed {
		if login != "" {
			st.addMember(login, roleMember)
		}
	}
}

// New starts a mock org seeded with the token's user (an owner, so /user and
// the guardrail work) and any extra members, and nothing else. Close it when
// done.
func New(opts ...Option) *Server {
	s := &Server{
		g:         &guarded{s: newState()},
		token:     "mock-token",
		principal: "github-bot",
		org:       "acme-labs",
		now:       time.Now,
		lagByType: map[string]time.Duration{},
		drop:      map[string]bool{},
		recordUA:  func(ua string) string { return ua },
		hashToken: true,
	}
	for _, o := range opts {
		o(s)
	}
	st := s.g.s
	st.Org = Org{Login: s.org, ID: st.newID(), Name: "Acme Labs"}
	st.addMember(s.principal, roleAdmin)
	s.seedMembers()
	s.http = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// URL is the API base URL (what a target's api_url option holds in tests).
func (s *Server) URL() string { return s.http.URL }

// Org returns the organization login the server serves.
func (s *Server) OrgLogin() string { return s.org }

// Close stops the server.
func (s *Server) Close() { s.http.Close() }

// Snapshot returns the org's objects without its audit log.
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

// InjectRateLimit makes the next n API calls answer a primary rate-limit 403.
func (s *Server) InjectRateLimit(n int) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	s.fail403 = n
}

// PlaceMarker plays a tenant admin creating the ownership-marker repo and file
// in the admin UI (so the write carries a browser User-Agent, never the
// tool's). repo is the marker repository name, file the marker file path, and
// value its contents.
func (s *Server) PlaceMarker(repo, file, value string) {
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	st := s.g.s
	r := st.Repos[repo]
	if r == nil {
		r = newRepo(st, repo, true)
		st.Repos[repo] = r
	}
	r.Contents[file] = value
}

// newRepo builds an empty repository with its default security posture.
func newRepo(st *State, name string, private bool) *Repo {
	return &Repo{
		ID:             st.newID(),
		Name:           name,
		Private:        private,
		SecretScanning: statusEnabled,
		PushProtection: statusEnabled,
		Keys:           map[int64]*Key{},
		Hooks:          map[int64]*Hook{},
		Collaborators:  map[string]bool{},
		Invitations:    map[int64]string{},
		Contents:       map[string]string{},
	}
}

// githubError is GitHub's error envelope.
type githubError struct {
	Message string `json:"message"`
}

func writeErr(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(githubError{Message: message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeNoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// serve routes one request. Every mutating handler runs under g.mu and records
// its audit event with the request's User-Agent.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.g.mu.Lock()
	if s.fail403 > 0 {
		s.fail403--
		reset := s.now().Add(time.Second).Unix()
		s.g.mu.Unlock()
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
		writeErr(w, http.StatusForbidden, "API rate limit exceeded")
		return
	}
	s.g.mu.Unlock()

	// Bearer token auth: the one credential check, as a real org's does.
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		writeErr(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	ua := r.Header.Get("User-Agent")

	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	s.route(w, r, s.g.s, ua, splitPath(r.URL.Path))
}

// splitPath returns the non-empty path segments.
func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 1 && seg[0] == "user":
		s.handleUser(w, r, st)
	case len(seg) == 4 && seg[0] == "user" && seg[1] == "memberships" && seg[2] == "orgs":
		s.handleSelfMembership(w, r, st, seg[3])
	case seg[0] == "orgs":
		s.routeOrgs(w, r, st, ua, seg[1:])
	case seg[0] == "repos":
		s.routeRepos(w, r, st, ua, seg[1:])
	default:
		writeErr(w, http.StatusNotFound, "Not Found: "+r.URL.Path)
	}
}

// routeOrgs handles /orgs/{org}/... The org must be the one this mock serves.
func (s *Server) routeOrgs(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	if len(seg) == 0 || seg[0] != s.org {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	rest := seg[1:]
	switch {
	case len(rest) == 0:
		writeJSON(w, 200, st.Org)
	case len(rest) == 1 && rest[0] == "members":
		s.handleMembers(w, r, st)
	case len(rest) == 2 && rest[0] == "memberships":
		s.handleMembership(w, r, st, ua, rest[1])
	case len(rest) == 1 && rest[0] == "repos":
		s.handleOrgRepos(w, r, st, ua)
	case len(rest) == 1 && rest[0] == "audit-log":
		s.handleAuditLog(w, r, st)
	default:
		writeErr(w, http.StatusNotFound, "Not Found")
	}
}

// routeRepos handles /repos/{org}/{repo}/... The org must be this mock's.
func (s *Server) routeRepos(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	if len(seg) < 2 || seg[0] != s.org {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	repoName := seg[1]
	rest := seg[2:]
	switch {
	case len(rest) == 0:
		s.handleRepo(w, r, st, ua, repoName)
	case rest[0] == "keys":
		s.handleKeys(w, r, st, ua, repoName, rest[1:])
	case rest[0] == "hooks":
		s.handleHooks(w, r, st, ua, repoName, rest[1:])
	case rest[0] == "collaborators" && len(rest) == 2:
		s.handleCollaborator(w, r, st, ua, repoName, rest[1])
	case rest[0] == "invitations":
		s.handleInvitations(w, r, st, ua, repoName, rest[1:])
	case rest[0] == "branches" && len(rest) == 3 && rest[2] == "protection":
		s.handleProtection(w, r, st, ua, repoName, rest[1])
	case rest[0] == "contents" && len(rest) >= 2:
		s.handleContents(w, r, st, repoName, strings.Join(rest[1:], "/"))
	default:
		writeErr(w, http.StatusNotFound, "Not Found")
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
// (the real GitHub pagination contract) when more than pageSize remain, so the
// client's Link-following is exercised.
func (s *Server) paginate(w http.ResponseWriter, r *http.Request, items []json.RawMessage) {
	const pageSize = 2
	start := 0
	if a := queryParam(r, "after"); a != "" {
		start, _ = strconv.Atoi(a)
	}
	end := start + pageSize
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
		w.Header().Set("Link", fmt.Sprintf(`<%s://%s%s>; rel="next"`, scheme, r.Host, next.RequestURI()))
	}
	page := items[start:end]
	if page == nil {
		page = []json.RawMessage{}
	}
	writeJSON(w, 200, page)
}
