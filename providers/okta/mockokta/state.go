// Package mockokta is an in-process stand-in for an Okta org: an httptest
// server that speaks the subset of the Okta Management API and the System Log
// that the okta provider uses, backed by a small in-memory model of a tenant.
//
// It exists only for tests. CI cannot reach a real Okta org, so the op- and
// technique-conformance suites, the crash-injection tests and the full-loop
// CLI tests run the real okta provider against this mock over real TCP, which
// is why it is a regular package (the cli crash test, in another package, runs
// the mock in the parent process while a child saashound process connects to
// it and is killed mid-run). Nothing in the production binary imports it, so
// the linker drops it from cmd/saashound.
package mockokta

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// State is the whole mock tenant: its org identity, its objects and its
// System Log. Every field mirrors the shape of the Okta JSON the provider
// reads back, so the provider's own decoders are exercised end to end.
type State struct {
	Org    Org
	nextID int

	Users        map[string]*User
	Factors      map[string]*Factor
	Roles        map[string]*RoleAssignment
	Groups       map[string]*Group
	Zones        map[string]*Zone
	IdPs         map[string]*IdP
	Apps         map[string]*App
	Grants       map[string]*AppGrant
	Policies     map[string]*Policy
	Rules        map[string]*PolicyRule
	CustomRoles  map[string]*CustomRole
	ResourceSets map[string]*ResourceSet
	Bindings     map[string]*Binding

	// Log holds the System Log, with the time each event becomes visible to
	// the /logs API (to model near-real-time ingestion lag in tests).
	Log []LogEntry
}

// Org is the subset of GET /api/v1/org the provider reads.
type Org struct {
	ID          string `json:"id"`
	Subdomain   string `json:"subdomain"`
	CompanyName string `json:"companyName"`
	Status      string `json:"status"`
}

// User is a tenant user.
type User struct {
	ID      string      `json:"id"`
	Status  string      `json:"status"`
	Created time.Time   `json:"created"`
	Profile UserProfile `json:"profile"`
	// factorsReset records that reset_factors has run on this user. It is the
	// restorable surrogate the reset op tracks; it is never serialised to the
	// API (the API has no such field), only used by the mock and the snapshot.
	factorsReset bool
}

// UserProfile is the Okta user profile subset.
type UserProfile struct {
	Login     string `json:"login"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// Factor is an enrolled MFA factor. For a software TOTP factor the object
// name is carried in profile.credentialId, a real settable Okta field.
type Factor struct {
	ID         string        `json:"id"`
	FactorType string        `json:"factorType"`
	Provider   string        `json:"provider"`
	Status     string        `json:"status"`
	Profile    FactorProfile `json:"profile"`
	userID     string
}

// FactorProfile carries the TOTP credential id.
type FactorProfile struct {
	CredentialID string `json:"credentialId"`
}

// RoleAssignment is an admin role granted to a user.
type RoleAssignment struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
	userID string
}

// Group is a tenant group. The ownership marker is a group.
type Group struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Profile GroupProfile `json:"profile"`
}

// GroupProfile is the group name and description.
type GroupProfile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Zone is a network zone.
type Zone struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Status   string        `json:"status"`
	Type     string        `json:"type"`
	Gateways []ZoneAddress `json:"gateways"`
}

// ZoneAddress is one gateway entry.
type ZoneAddress struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// IdP is an inbound identity provider.
type IdP struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// App is an OAuth service application.
type App struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	SignOnMode string `json:"signOnMode"`
}

// AppGrant is an API scope granted to an app.
type AppGrant struct {
	ID      string `json:"id"`
	Scopeid string `json:"scopeId"`
	Status  string `json:"status"`
	appID   string
}

// Policy is an access policy.
type Policy struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// PolicyRule is a rule within a policy.
type PolicyRule struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// RequireFactor is true when the rule requires MFA. Weakening the rule
	// sets it false; the prior value is restored on cleanup.
	RequireFactor bool `json:"-"`
	policyID      string
}

// CustomRole is a custom admin role.
type CustomRole struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// ResourceSet is a set of resources a custom role can be bound over.
type ResourceSet struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// Binding binds a custom role to a resource set for a member.
type Binding struct {
	ID            string `json:"id"`
	Role          string `json:"role"`
	ResourceSetID string `json:"-"`
	MemberID      string `json:"-"`
}

// LogEntry is one System Log event plus when it becomes visible to the API.
type LogEntry struct {
	VisibleAt time.Time
	Event     json.RawMessage
}

const (
	statusActive   = "ACTIVE"
	statusInactive = "INACTIVE"
)

func newState() *State {
	return &State{
		Users:        map[string]*User{},
		Factors:      map[string]*Factor{},
		Roles:        map[string]*RoleAssignment{},
		Groups:       map[string]*Group{},
		Zones:        map[string]*Zone{},
		IdPs:         map[string]*IdP{},
		Apps:         map[string]*App{},
		Grants:       map[string]*AppGrant{},
		Policies:     map[string]*Policy{},
		Rules:        map[string]*PolicyRule{},
		CustomRoles:  map[string]*CustomRole{},
		ResourceSets: map[string]*ResourceSet{},
		Bindings:     map[string]*Binding{},
	}
}

// AddUser seeds an active user with the given login, for test setup. It emits
// no event.
func (s *State) AddUser(login string) *User {
	u := &User{ID: s.newID("00u"), Status: statusActive, Profile: UserProfile{Login: login, Email: login}}
	s.Users[u.ID] = u
	return u
}

// newID returns a fresh Okta-style identifier with the given prefix.
func (s *State) newID(prefix string) string {
	s.nextID++
	return prefix + padID(s.nextID)
}

func padID(n int) string {
	d := []byte("0000000000")
	s := []byte{}
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	if len(s) >= len(d) {
		return string(s)
	}
	return string(d[:len(d)-len(s)]) + string(s)
}

// snapshot returns the tenant's objects, without the System Log and without
// the id counter, as stable JSON: the conformance suite proves an op leaves
// the tenant byte-identical to how it found it.
func (s *State) snapshot() json.RawMessage {
	m := map[string]any{
		"org":           s.Org,
		"users":         viewUsers(s.Users),
		"factors":       s.Factors,
		"roles":         s.Roles,
		"groups":        s.Groups,
		"zones":         s.Zones,
		"idps":          s.IdPs,
		"apps":          s.Apps,
		"grants":        s.Grants,
		"policies":      s.Policies,
		"rules":         s.Rules,
		"custom_roles":  s.CustomRoles,
		"resource_sets": s.ResourceSets,
		"bindings":      s.Bindings,
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // only plain data
	}
	return b
}

// viewUsers renders users including the unexported factorsReset flag so the
// snapshot reflects a reset-then-restored user as unchanged.
func viewUsers(users map[string]*User) map[string]any {
	out := make(map[string]any, len(users))
	for id, u := range users {
		out[id] = map[string]any{
			"id": u.ID, "status": u.Status, "created": u.Created,
			"profile": u.Profile, "factors_reset": u.factorsReset,
		}
	}
	return out
}

// sortedUsers returns users ordered by id, for deterministic listing.
func sortedUsers(m map[string]*User) []*User {
	out := make([]*User, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func hasPrefix(s, p string) bool { return strings.HasPrefix(s, p) }

// mu guards every State mutation and read. httptest serves each request on its
// own goroutine, and the crash test reads the state from the parent while a
// child process drives it, so all access is serialised.
type guarded struct {
	mu sync.Mutex
	s  *State
}
