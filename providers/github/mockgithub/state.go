// Package mockgithub is an in-process stand-in for a GitHub organization: an
// httptest server that speaks the subset of the GitHub REST API and the org
// audit-log API that the github provider uses, backed by a small in-memory
// model of an org.
//
// It exists only for tests. The org audit-log REST API is GHEC-only, so CI
// cannot reach a real one; the op- and technique-conformance suites, the
// crash-injection tests and the full-loop CLI tests run the real github
// provider against this mock over real TCP, which is why it is a regular
// package (the cli crash test, in another package, runs the mock in the parent
// process while a child saashound process connects to it and is killed
// mid-run). Nothing in the production binary imports it, so the linker drops
// it from cmd/saashound.
package mockgithub

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// State is the whole mock org: its identity, its members, its repositories
// and its audit log. Every field mirrors the shape of the GitHub JSON the
// provider reads back, so the provider's own decoders are exercised end to end.
type State struct {
	Org     Org
	nextID  int64
	nextDoc int64

	Members map[string]*Member // keyed by login
	Repos   map[string]*Repo   // keyed by repo name

	// Log holds the audit log, with the time each event becomes visible to the
	// audit-log API (to model near-real-time ingestion lag in tests).
	Log []LogEntry
}

// Org is the subset of GET /orgs/{org} the provider reads.
type Org struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

// Member is an organization member.
type Member struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Role  string `json:"-"` // "admin" (owner) or "member"
}

// Repo is a repository and everything the provider attaches to it.
type Repo struct {
	ID                 int64             `json:"id"`
	Name               string            `json:"name"`
	Private            bool              `json:"private"`
	SecretScanning     string            `json:"-"` // "enabled"/"disabled"
	PushProtection     string            `json:"-"`
	Protected          bool              `json:"-"`
	ProtectionContexts []string          `json:"-"`
	Keys               map[int64]*Key    `json:"keys"`
	Hooks              map[int64]*Hook   `json:"hooks"`
	Collaborators      map[string]bool   `json:"collaborators"`
	Invitations        map[int64]string  `json:"-"` // invitation id -> invitee login (pending)
	Contents           map[string]string `json:"-"` // path -> raw file content (marker repo)
}

// Key is a repository deploy key.
type Key struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	Key   string `json:"key"`
}

// Hook is a repository webhook.
type Hook struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"-"`
	Active bool   `json:"-"`
}

// LogEntry is one audit-log event plus when it becomes visible to the API.
type LogEntry struct {
	VisibleAt time.Time
	Event     json.RawMessage
}

const (
	statusEnabled  = "enabled"
	statusDisabled = "disabled"
	roleAdmin      = "admin"
	roleMember     = "member"
)

func newState() *State {
	return &State{
		Members: map[string]*Member{},
		Repos:   map[string]*Repo{},
	}
}

// newID returns a fresh numeric identifier.
func (s *State) newID() int64 {
	s.nextID++
	return 100000 + s.nextID
}

// newDocID returns a fresh audit-log document id.
func (s *State) newDocID() string {
	s.nextDoc++
	return "doc-" + padID(s.nextDoc)
}

func padID(n int64) string {
	d := []byte("0000000000")
	var s []byte
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	if len(s) >= len(d) {
		return string(s)
	}
	return string(d[:len(d)-len(s)]) + string(s)
}

// addMember seeds an org member, for setup. It emits no event.
func (s *State) addMember(login, role string) *Member {
	m := &Member{Login: login, ID: s.newID(), Role: role}
	s.Members[login] = m
	return m
}

// AddRepo seeds a private repository, for test setup. It emits no event.
func (s *State) AddRepo(name string) *Repo {
	r := newRepo(s, name, true)
	s.Repos[name] = r
	return r
}

// snapshot returns the org's objects, without the audit log and the id
// counters, as stable JSON: the conformance suite proves an op leaves the org
// byte-identical to how it found it.
func (s *State) snapshot() json.RawMessage {
	repos := make(map[string]any, len(s.Repos))
	for name, r := range s.Repos {
		repos[name] = map[string]any{
			"id": r.ID, "name": r.Name, "private": r.Private,
			"secret_scanning": r.SecretScanning, "push_protection": r.PushProtection,
			"protected": r.Protected, "protection_contexts": r.ProtectionContexts,
			"keys": r.Keys, "hooks": viewHooks(r.Hooks), "collaborators": sortedKeys(r.Collaborators),
			"invitations": sortedValues(r.Invitations), "contents": r.Contents,
		}
	}
	members := make(map[string]any, len(s.Members))
	for login, m := range s.Members {
		members[login] = map[string]any{"login": m.Login, "id": m.ID, "role": m.Role}
	}
	b, err := json.Marshal(map[string]any{"org": s.Org, "members": members, "repos": repos})
	if err != nil {
		panic(err) // only plain data
	}
	return b
}

// viewHooks renders hooks including the unexported URL so the snapshot
// reflects a hook's payload target.
func viewHooks(hooks map[int64]*Hook) map[string]any {
	out := make(map[string]any, len(hooks))
	for id, h := range hooks {
		out[padID(id)] = map[string]any{"id": h.ID, "name": h.Name, "url": h.URL, "active": h.Active}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedValues(m map[int64]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// mu guards every State mutation and read. httptest serves each request on its
// own goroutine, and the crash test reads the state from the parent while a
// child process drives it, so all access is serialised.
type guarded struct {
	mu sync.Mutex
	s  *State
}
