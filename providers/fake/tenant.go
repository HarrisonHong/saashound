package fake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

const (
	statusActive   = "ACTIVE"
	statusInactive = "INACTIVE"
)

// Tenant is an open connection to one simulated tenant.
type Tenant struct {
	cfg   provider.Config
	store Store
	id    string
	clk   clock.Clock
	audit auditSim
}

var _ provider.Tenant = (*Tenant)(nil)

// apiError is a simulated HTTP error.
type apiError struct {
	status int
	msg    string
	err    error
}

func (e *apiError) Error() string { return fmt.Sprintf("fake API %d: %s", e.status, e.msg) }
func (e *apiError) Unwrap() error { return e.err }

func notFound(what string) error {
	return &apiError{status: 404, msg: what + " not found", err: provider.ErrNotFound}
}

func badRequest(format string, a ...any) error {
	return &apiError{status: 400, msg: fmt.Sprintf(format, a...)}
}

// call runs one simulated API request: it applies fn to the tenant state,
// appends the audit events fn emitted (stamped with the request's
// User-Agent), persists the result and traces method, path and status.
func (t *Tenant) call(ctx context.Context, method, path string, fn func(s *State, e *emitter) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	start := t.clk.Now()
	mutating := method != "GET"
	var err error
	run := func(s *State) error {
		em := &emitter{s: s, t: t, ua: provider.UserAgent(ctx), now: t.clk.Now().UTC()}
		if ferr := fn(s, em); ferr != nil {
			return ferr
		}
		em.flush()
		return nil
	}
	if mutating {
		err = t.store.Update(t.id, run)
	} else {
		err = t.store.View(t.id, run)
	}
	if err == nil && t.audit.latency > 0 {
		// The platform has applied the request; the response is in flight.
		if serr := t.clk.Sleep(ctx, t.audit.latency); serr != nil {
			err = &apiError{status: 499, msg: "client closed request before the response arrived", err: serr}
		}
	}
	status := 200
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		status = ae.status
	case err != nil:
		status = 500
	}
	t.cfg.TraceRequest(provider.Request{Method: method, Path: path, Status: status, Duration: t.clk.Now().Sub(start)})
	return err
}

// Whoami implements provider.Tenant.
func (t *Tenant) Whoami(ctx context.Context) (provider.Identity, error) {
	var id provider.Identity
	err := t.call(ctx, "GET", "/api/v1/org", func(s *State, _ *emitter) error {
		active := 0
		for _, u := range s.Users {
			if u.Status == statusActive {
				active++
			}
		}
		id = provider.Identity{
			Tenant:      s.ID,
			Principal:   s.Principal,
			DisplayName: s.DisplayName,
			Domain:      s.Domain,
			ShortName:   s.ShortName,
			Roles:       []string{"SUPER_ADMIN"},
			Scopes:      allScopes(),
			ActiveUsers: active,
		}
		return nil
	})
	return id, err
}

// ReadMarker implements provider.Tenant.
func (t *Tenant) ReadMarker(ctx context.Context) (string, bool, error) {
	var (
		value string
		found bool
	)
	err := t.call(ctx, "GET", "/api/v1/groups?q="+marker.AuthorizationName, func(s *State, _ *emitter) error {
		for _, g := range s.Groups {
			if g.Name == marker.AuthorizationName {
				value, found = g.Description, true
			}
		}
		return nil
	})
	return value, found, err
}

// Capabilities implements provider.Tenant.
func (t *Tenant) Capabilities(ctx context.Context) (provider.Caps, error) {
	var caps provider.Caps
	err := t.call(ctx, "GET", "/api/v1/org/capabilities", func(s *State, _ *emitter) error {
		caps = provider.Caps{Audit: t.audit.supported, Tier: s.Tier}
		if !t.audit.supported {
			caps.Note = "this simulated tier has no audit API"
		}
		return nil
	})
	return caps, err
}

// AuditSource implements provider.Tenant.
func (t *Tenant) AuditSource() provider.AuditSource { return auditSource{t} }

// Close implements provider.Tenant.
func (t *Tenant) Close() error { return nil }

type auditSource struct{ t *Tenant }

// wireEvent is the subset of an event the provider reads back. Fields are
// decoded defensively: a missing or oddly typed field yields a zero value,
// never a panic.
type wireEvent struct {
	UUID      string    `json:"uuid"`
	Published time.Time `json:"published"`
	EventType string    `json:"eventType"`
	Client    struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
	} `json:"client"`
}

// Poll implements provider.AuditSource.
func (a auditSource) Poll(ctx context.Context, q provider.AuditQuery) ([]provider.Event, error) {
	if !a.t.audit.supported {
		return nil, errors.New("fake: audit API not available on this tier")
	}
	var out []provider.Event
	path := fmt.Sprintf("/api/v1/logs?since=%s&until=%s", q.Since.UTC().Format(time.RFC3339), q.Until.UTC().Format(time.RFC3339))
	err := a.t.call(ctx, "GET", path, func(s *State, _ *emitter) error {
		now := a.t.clk.Now()
		for _, le := range s.Log {
			if le.VisibleAt.After(now) {
				continue // not ingested yet
			}
			var w wireEvent
			if err := json.Unmarshal(le.Event, &w); err != nil {
				continue
			}
			if w.Published.Before(q.Since) || (!q.Until.IsZero() && w.Published.After(q.Until)) {
				continue
			}
			out = append(out, provider.Event{
				ID:        w.UUID,
				Time:      w.Published,
				Type:      w.EventType,
				UserAgent: w.Client.UserAgent.RawUserAgent,
				Raw:       append(json.RawMessage(nil), le.Event...),
			})
		}
		return nil
	})
	return out, err
}

// Sweep implements provider.Tenant.
func (t *Tenant) Sweep(ctx context.Context, prefix string) ([]provider.Orphan, error) {
	var out []provider.Orphan
	err := t.call(ctx, "GET", "/api/v1/search?prefix="+prefix, func(s *State, _ *emitter) error {
		match := func(name string) bool { return strings.HasPrefix(name, prefix) }
		// Children first, so each removal leaves no dangling child.
		for _, g := range sortedValues(s.Grants) {
			if match(g.Name) {
				out = append(out, provider.Orphan{Op: opRoleAssign, Name: g.Name, Resource: resRoleGrant,
					Params: map[string]string{"user": g.UserID, "role": g.Role}, Record: provider.Record{ID: g.ID}})
			}
		}
		for _, f := range sortedValues(s.Factors) {
			if match(f.Name) {
				out = append(out, provider.Orphan{Op: opFactorEnroll, Name: f.Name, Resource: resFactor,
					Params: map[string]string{"user": f.UserID}, Record: provider.Record{ID: f.ID}})
			}
		}
		for _, z := range sortedValues(s.Zones) {
			if match(z.Name) {
				out = append(out, provider.Orphan{Op: opZoneCreate, Name: z.Name, Resource: resZone,
					Params: map[string]string{"gateway": z.Gateway}, Record: provider.Record{ID: z.ID}})
			}
		}
		for _, u := range sortedValues(s.Users) {
			if match(u.Name) {
				out = append(out, provider.Orphan{Op: opUserCreate, Name: u.Name, Resource: resUser,
					Params: map[string]string{}, Record: provider.Record{ID: u.ID, Outputs: map[string]string{"login": u.Login}}})
			}
		}
		return nil
	})
	return out, err
}

type named interface{ comparableID() string }

func (u *User) comparableID() string      { return u.ID }
func (f *Factor) comparableID() string    { return f.ID }
func (g *RoleGrant) comparableID() string { return g.ID }
func (z *Zone) comparableID() string      { return z.ID }

func sortedValues[T named](m map[string]T) []T {
	out := make([]T, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].comparableID() < out[j].comparableID() })
	return out
}

// emitter collects the audit events one API call produces.
type emitter struct {
	s       *State
	t       *Tenant
	ua      string
	now     time.Time
	pending []pendingEvent
}

type pendingEvent struct {
	typ, msg string
	targets  []eventTarget
}

type eventTarget struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type actor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

func (e *emitter) emit(typ, msg string, targets ...eventTarget) {
	e.pending = append(e.pending, pendingEvent{typ: typ, msg: msg, targets: targets})
}

func (e *emitter) flush() {
	a := actor{ID: e.s.Principal, Type: "PublicClientApp", AlternateID: e.s.Principal, DisplayName: e.s.Principal}
	for _, p := range e.pending {
		if e.t.audit.drop[p.typ] {
			continue // this platform does not log it
		}
		lag := e.t.audit.lag
		if d, ok := e.t.audit.lagByType[p.typ]; ok {
			lag = d
		}
		appendEvent(e.s, e.now, e.now.Add(lag), a, e.ua, p.typ, p.msg, p.targets...)
	}
}

// appendEvent records one System Log-style event.
func appendEvent(s *State, published, visible time.Time, a actor, ua, typ, msg string, targets ...eventTarget) {
	if targets == nil {
		targets = []eventTarget{}
	}
	ev := map[string]any{
		"uuid":           s.newID("evt"),
		"published":      published.UTC().Format(time.RFC3339Nano),
		"eventType":      typ,
		"displayMessage": msg,
		"severity":       "INFO",
		"actor":          a,
		"client":         map[string]any{"userAgent": map[string]string{"rawUserAgent": ua}},
		"outcome":        map[string]string{"result": "SUCCESS"},
		"target":         targets,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err) // only plain maps and strings; cannot fail
	}
	s.Log = append(s.Log, LogEntry{VisibleAt: visible.UTC(), Event: b})
}
