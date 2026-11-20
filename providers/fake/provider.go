// Package fake is a simulated SaaS platform. It implements the full provider
// boundary (ops with inverses, an audit source, Whoami, the ownership marker
// and sweep) against a local simulated tenant, with no network and no real
// credentials. It exists to prove the core loop and to give the test suites
// a platform; it is also what `--target <a fake target>` runs against.
//
// Its shape is deliberately the shape a real provider such as Okta will
// have: ops call a small "API" on the tenant that records an Okta-style
// System Log event carrying the request's User-Agent, exactly what a real
// platform's audit log does.
package fake

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Name is the platform name.
const Name = "fake"

// AuditSourceName is the name techniques use in expect[].source.
const AuditSourceName = "fake.audit"

func init() { provider.Register(New()) }

// Provider is the simulated platform.
type Provider struct {
	store Store
}

// Option configures a Provider.
type Option func(*Provider)

// WithStore makes the provider keep its tenants in s instead of in files
// under the run state directory.
func WithStore(s Store) Option { return func(p *Provider) { p.store = s } }

// New returns a provider. By default tenants live in files under
// Config.StateDir, so they survive across CLI invocations.
func New(opts ...Option) *Provider {
	p := &Provider{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name implements provider.Provider.
func (*Provider) Name() string { return Name }

// Audit implements provider.Provider.
func (*Provider) Audit() provider.AuditInfo {
	return provider.AuditInfo{
		Name:         AuditSourceName,
		TypeField:    "eventType",
		Deadline:     30 * time.Second,
		PollInterval: 250 * time.Millisecond,
		Scopes:       []string{"fake.logs.read"},
	}
}

// Ops implements provider.Provider.
func (*Provider) Ops() []provider.Op {
	return []provider.Op{
		userCreate{},
		factorEnroll{},
		roleAssign{},
		zoneCreate{},
		zoneDeactivate{},
		orgSettingSet{},
	}
}

func (p *Provider) storeFor(cfg provider.Config) (Store, error) {
	if p.store != nil {
		return p.store, nil
	}
	if cfg.StateDir == "" {
		return nil, fmt.Errorf("fake: no state directory for the simulated tenant")
	}
	return FileStore{Dir: filepath.Join(cfg.StateDir, "tenants")}, nil
}

// Options a fake target accepts.
const (
	// OptAuditLag delays every event's visibility, e.g. "2s".
	OptAuditLag = "audit_lag"
	// OptAuditLagPrefix + "<eventType>" delays one event type.
	OptAuditLagPrefix = "audit_lag/"
	// OptAuditDrop lists event types the platform never logs, comma-separated.
	OptAuditDrop = "audit_drop"
	// OptAudit set to "unsupported" simulates a tier without an audit API.
	OptAudit = "audit"
	// OptAPILatency delays every response after the platform has applied
	// the request, e.g. "2s". An interrupt during that delay leaves an
	// object the client never learned the ID of, as a dropped HTTP response
	// would.
	OptAPILatency = "api_latency"
	// OptAuditUserAgent says what the log records for a request's
	// User-Agent: "recorded" (the default) as sent, "dropped" nothing, or
	// "truncated" only its first TruncatedUserAgentLen bytes, so the run
	// marker does not survive whole.
	OptAuditUserAgent = "audit_user_agent"
)

// TruncatedUserAgentLen is how much of a User-Agent a log with
// audit_user_agent: truncated keeps.
const TruncatedUserAgentLen = 24

type auditSim struct {
	latency   time.Duration
	lag       time.Duration
	lagByType map[string]time.Duration
	drop      map[string]bool
	supported bool
	// userAgent is what the log records for a request's User-Agent.
	userAgent func(string) string
}

func parseOptions(opts map[string]string) (auditSim, error) {
	a := auditSim{lagByType: map[string]time.Duration{}, drop: map[string]bool{}, supported: true, userAgent: func(ua string) string { return ua }}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := opts[k]
		switch {
		case k == OptAuditLag:
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				return a, fmt.Errorf("fake: option %s: invalid duration %q", k, v)
			}
			a.lag = d
		case strings.HasPrefix(k, OptAuditLagPrefix):
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				return a, fmt.Errorf("fake: option %s: invalid duration %q", k, v)
			}
			a.lagByType[strings.TrimPrefix(k, OptAuditLagPrefix)] = d
		case k == OptAPILatency:
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				return a, fmt.Errorf("fake: option %s: invalid duration %q", k, v)
			}
			a.latency = d
		case k == OptAuditDrop:
			for _, t := range strings.Split(v, ",") {
				if t = strings.TrimSpace(t); t != "" {
					a.drop[t] = true
				}
			}
		case k == OptAuditUserAgent:
			switch v {
			case "recorded":
			case "dropped":
				a.userAgent = func(string) string { return "" }
			case "truncated":
				a.userAgent = func(ua string) string { return ua[:min(len(ua), TruncatedUserAgentLen)] }
			default:
				return a, fmt.Errorf("fake: option %s must be recorded, dropped or truncated", k)
			}
		case k == OptAudit:
			switch v {
			case "supported":
			case "unsupported":
				a.supported = false
			default:
				return a, fmt.Errorf("fake: option audit must be supported or unsupported")
			}
		default:
			return a, fmt.Errorf("fake: unknown option %q", k)
		}
	}
	return a, nil
}

// Open implements provider.Provider.
func (p *Provider) Open(ctx context.Context, cfg provider.Config) (provider.Tenant, error) {
	sim, err := parseOptions(cfg.Target.Options)
	if err != nil {
		return nil, err
	}
	store, err := p.storeFor(cfg)
	if err != nil {
		return nil, err
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	t := &Tenant{cfg: cfg, store: store, id: cfg.Target.Tenant, clk: clk, audit: sim}
	if err := t.authenticate(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// Provision implements provider.Simulator: it stands up a simulated tenant
// with a couple of human users, so a lab target looks like a small lab org.
func (p *Provider) Provision(ctx context.Context, cfg provider.Config) error {
	store, err := p.storeFor(cfg)
	if err != nil {
		return err
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	id := cfg.Target.Tenant
	s := &State{
		Version:     StateVersion,
		ID:          id,
		Principal:   cfg.Target.Principal,
		DisplayName: "Simulated tenant " + id,
		Domain:      id + ".fake.invalid",
		ShortName:   id,
		Tier:        "simulated",
	}
	s.init()
	if s.TokenSHA256, err = credentialDigest(ctx, cfg); err != nil {
		return err
	}
	now := clk.Now().UTC()
	for _, h := range []string{"admin", "analyst"} {
		u := &User{ID: s.newID("00u"), Name: h, Login: h + "@" + s.Domain, DisplayName: h, Status: statusActive, PasswordSet: true, Created: now}
		s.Users[u.ID] = u
	}
	g := &Group{ID: s.newID("00g"), Name: "Everyone", Description: "All users"}
	s.Groups[g.ID] = g
	z := &Zone{ID: s.newID("nzo"), Name: "LegacyIpZone", Gateway: "198.51.100.0/24", Status: statusActive}
	s.Zones[z.ID] = z
	for _, set := range orgSettings {
		s.Settings[set] = "on"
	}
	// Background noise from people, not the tool: the collector must ignore it.
	appendEvent(s, now, now, humanActor(s), "Mozilla/5.0 (X11; Linux x86_64)", "user.session.start", "User login to Okta",
		eventTarget{ID: firstUser(s), Type: "User"})
	return store.Create(id, s)
}

// PlaceMarker implements provider.Simulator. It plays the tenant admin
// creating the ownership group in the admin console, so it carries a
// browser's User-Agent, not the tool's.
func (p *Provider) PlaceMarker(_ context.Context, cfg provider.Config, value string) error {
	store, err := p.storeFor(cfg)
	if err != nil {
		return err
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return store.Update(cfg.Target.Tenant, func(s *State) error {
		now := clk.Now().UTC()
		for _, g := range s.Groups {
			if g.Name == marker.AuthorizationName {
				g.Description = value
				appendEvent(s, now, now, humanActor(s), "Mozilla/5.0 (X11; Linux x86_64)", "group.profile.update", "Update group profile",
					eventTarget{ID: g.ID, Type: "UserGroup", DisplayName: g.Name})
				return nil
			}
		}
		g := &Group{ID: s.newID("00g"), Name: marker.AuthorizationName, Description: value}
		s.Groups[g.ID] = g
		appendEvent(s, now, now, humanActor(s), "Mozilla/5.0 (X11; Linux x86_64)", "group.lifecycle.create", "Create okta group",
			eventTarget{ID: g.ID, Type: "UserGroup", DisplayName: g.Name})
		return nil
	})
}

// MarkerInstructions implements provider.Onboarder.
func (*Provider) MarkerInstructions(t provider.TargetInfo, value string) []string {
	return []string{
		fmt.Sprintf("In the tenant's admin console, create a group named  %s", marker.AuthorizationName),
		fmt.Sprintf("with description  %s", value),
		fmt.Sprintf("(The simulated tenant has no console: `saashound init %s --platform fake --place-marker` plays the admin.)", t.Name),
	}
}

func humanActor(s *State) actor {
	return actor{ID: firstUser(s), Type: "User", AlternateID: "admin@" + s.Domain, DisplayName: "admin"}
}

func firstUser(s *State) string {
	ids := make([]string, 0, len(s.Users))
	for id := range s.Users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// Snapshot returns the tenant's objects without its audit log, for tests that
// prove a run left the tenant exactly as it found it.
func Snapshot(store Store, tenant string) (json.RawMessage, error) {
	var out json.RawMessage
	err := store.View(tenant, func(s *State) error {
		cp := *s
		cp.Log = nil
		cp.NextID = 0
		b, err := json.Marshal(cp)
		out = b
		return err
	})
	return out, err
}
