// Package provider defines the boundary between the platform-agnostic core
// and one SaaS or identity platform.
//
// A provider is one Go package that implements Provider and registers itself
// from init() with Register; one blank import in providers/all.go adds it to
// the binary. Nothing in the core switches on platform names.
//
// A provider contributes three things:
//
//   - a closed vocabulary of operations (Op), each with a mandatory inverse
//     (Undo), a proof that the inverse worked (Gone), and a way to recover
//     after a crash (Locate for ops that create, Prior for ops that modify);
//   - an AuditSource that reads the platform's own audit log;
//   - a Tenant: an authenticated connection that can say which tenant and
//     principal it is (Whoami), read the human-placed ownership marker, and
//     find run-created objects whose journal was lost (Sweep).
//
// Every request a provider makes must carry the User-Agent from
// UserAgent(ctx). The conformance suite in internal/conformance checks all of
// the above for every registered provider.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/secret"
)

// Provider is one platform.
type Provider interface {
	// Name is the platform name and the namespace of its ops and technique
	// IDs, for example "okta".
	Name() string
	// Ops returns the provider's closed vocabulary of operations. It must
	// return the same set on every call.
	Ops() []Op
	// Audit describes the platform's audit source statically, so techniques
	// can be validated and planned without a tenant.
	Audit() AuditInfo
	// Open builds an authenticated connection to one tenant. It must not
	// mutate anything.
	Open(ctx context.Context, cfg Config) (Tenant, error)
}

// Config is what a provider gets to open a tenant.
type Config struct {
	Target TargetInfo
	// Credential is the target's credential reference; resolve it with
	// Secrets only when needed. It is zero when the target declares none.
	Credential secret.Ref
	Secrets    secret.Source
	// Scopes are the permissions this connection's work needs, as the ops it
	// may run and the audit source declare them (Spec.Scopes, AuditInfo.Scopes).
	// The caller derives them from what it is about to do: the plan's scopes
	// for plan and apply, the journalled ops' for cleanup. A provider whose
	// credential can be narrowed per
	// session (an OAuth client that mints a token per run) must request
	// exactly these, plus whatever its own identity and marker reads need,
	// and fail before any call if it cannot obtain one of them. A provider
	// whose credential has fixed privileges may ignore them.
	Scopes []string
	// OptionalScopes are requested only if the credential can obtain them,
	// and silently left out otherwise; Whoami's Identity.Scopes then says
	// which were obtained. auth uses them to report, in one read-only session,
	// which scopes the corpus needs that the credential cannot get; sweep asks
	// for the whole op vocabulary's this way. A provider that then cannot see
	// some kind of object it would sweep must refuse rather than report the
	// tenant clean.
	OptionalScopes []string
	// ReadOnly says the connection will make only read calls (sweep without
	// --delete). A provider that narrows its credential per session should
	// then ask for the read-only counterparts of the scopes, where its
	// platform has them.
	ReadOnly bool
	// StateDir is a private directory the provider may use for local state.
	// Real platforms should not need it; the simulated provider keeps its
	// tenant there.
	StateDir string
	Clock    clock.Clock
	// Trace, if set, receives one record per API call. It carries method,
	// path, status and latency only: never headers or bodies, so verbose
	// output cannot leak a credential.
	Trace func(Request)
}

// Request describes one API call for verbose output.
type Request struct {
	Method   string
	Path     string
	Status   int
	Duration time.Duration
}

// TraceRequest reports r to cfg.Trace, if set.
func (cfg Config) TraceRequest(r Request) {
	if cfg.Trace != nil {
		cfg.Trace(r)
	}
}

// TargetInfo is the non-secret part of a targets.yaml entry.
type TargetInfo struct {
	Name        string
	Platform    string
	Tenant      string // declared tenant identifier (org URL, org slug, ...)
	Principal   string // declared principal (service app client ID, app ID, ...)
	Environment string // "lab" or "production"
	TestDomain  string
	// Options are provider-specific, non-secret settings.
	Options map[string]string
}

// Tenant is an authenticated connection to one tenant.
type Tenant interface {
	// Whoami asks the platform which tenant and principal the credential
	// belongs to. The guardrail compares the answer to the declared target.
	Whoami(ctx context.Context) (Identity, error)
	// ReadMarker reads the human-placed ownership marker. It never creates
	// one: a token alone must not be able to self-authorise.
	ReadMarker(ctx context.Context) (value string, found bool, err error)
	// Capabilities reports what this tenant's tier can verify.
	Capabilities(ctx context.Context) (Caps, error)
	// AuditSource returns the tenant's audit log reader.
	AuditSource() AuditSource
	// Sweep lists every object whose name starts with prefix, as orphans the
	// cleaner can remove with the op that created them. Children must come
	// before their parents.
	Sweep(ctx context.Context, prefix string) ([]Orphan, error)
	// Close releases the connection.
	Close() error
}

// Identity is what the platform says about the credential in use.
type Identity struct {
	Tenant      string   `json:"tenant"`
	Principal   string   `json:"principal"`
	DisplayName string   `json:"display_name"`
	Domain      string   `json:"domain"`
	ShortName   string   `json:"short_name"` // what the operator types to confirm
	Roles       []string `json:"roles,omitempty"`
	// Scopes are the scopes the credential carries in this session.
	Scopes []string `json:"scopes,omitempty"`
	// Credential describes, for display, how the credential authenticates,
	// for example "OAuth 2.0 service app (private_key_jwt)". It never holds
	// any part of the credential itself.
	Credential string `json:"credential,omitempty"`
	// ActiveUsers is the tenant's active user count, or -1 if unknown.
	ActiveUsers int `json:"active_users"`
}

// Caps describes what a tenant's tier supports.
type Caps struct {
	// Audit reports whether the audit log API is available on this tier.
	Audit bool   `json:"audit"`
	Tier  string `json:"tier"`
	// Note explains a missing capability, for example "audit API needs GHEC".
	Note string `json:"note,omitempty"`
}

// AuditInfo statically describes a platform's audit source.
type AuditInfo struct {
	// Name is the source name techniques reference in expect[].source,
	// for example "okta.system_log".
	Name string
	// TypeField is the event field holding the event type, for example
	// "eventType" (Okta) or "action" (GitHub). Every expectation must match it.
	TypeField string
	// Deadline is the default time to wait for an expected event, from the
	// platform's documented lag.
	Deadline time.Duration
	// PollInterval is how often to poll.
	PollInterval time.Duration
	// Scopes are the permissions reading the audit log needs.
	Scopes []string
}

// AuditQuery selects events in a window.
type AuditQuery struct {
	Since time.Time
	Until time.Time
	// Run lets a provider filter server-side where the platform allows it.
	// The collector filters exactly on the User-Agent regardless.
	Run string
}

// AuditSource reads the platform's own audit log.
type AuditSource interface {
	Poll(ctx context.Context, q AuditQuery) ([]Event, error)
}

// Event is one raw audit event.
type Event struct {
	ID string
	// Time is the platform's own event timestamp.
	Time time.Time
	Type string
	// UserAgent is the User-Agent the platform recorded for the request.
	UserAgent string
	// Raw is the event exactly as the platform returned it.
	Raw json.RawMessage
}

// Orphan is a run-created object found by Sweep.
type Orphan struct {
	// Op is the registered op that creates this kind of object; its Undo and
	// Gone remove it and prove it is gone.
	Op       string            `json:"op"`
	Name     string            `json:"name"`
	Resource string            `json:"resource"`
	Params   map[string]string `json:"params,omitempty"`
	Record   Record            `json:"record"`
}

// ErrNotFound reports that an object does not exist. Undo returning it counts
// as success: the object is already gone.
var ErrNotFound = errors.New("not found")

// ErrAlreadyExists is returned by Simulator.Provision for a tenant that is
// already provisioned.
var ErrAlreadyExists = errors.New("already exists")

// Simulator is implemented by simulated providers, which have no real admin
// console: it stands up the tenant locally and plays the tenant admin's part
// in placing the ownership marker. Real providers do not implement it.
type Simulator interface {
	Provision(ctx context.Context, cfg Config) error
	PlaceMarker(ctx context.Context, cfg Config, value string) error
}

// Onboarder is implemented by providers that can tell an operator where a
// tenant admin places the ownership marker, for `saashound init`.
type Onboarder interface {
	MarkerInstructions(t TargetInfo, value string) []string
}
