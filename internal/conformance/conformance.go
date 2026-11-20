// Package conformance is the suite every provider must pass. A provider's
// own test calls Run with a harness that hands out fresh tenants; the suite
// then proves, op by op, the properties the core relies on:
//
//   - the provider registers: every op has Undo and Gone, and Locate (create)
//     or Prior (modify);
//   - Do creates or changes something Gone can see, and returns a resource ID
//     and only declared outputs;
//   - every audit event Do and Undo emit carries the run's User-Agent with
//     the right phase, and every declared event type is really emitted;
//   - every such event can be attributed to the run even when the platform
//     does not record the User-Agent: it names one of the run's objects, or
//     carries the run's credential where the platform records one;
//   - Locate finds a created object by its exact name and nothing else;
//   - Sweep finds what the op created;
//   - Undo then Gone proves the object gone (or the prior value restored);
//   - Undo on an already-undone object succeeds;
//   - the tenant ends exactly as it started;
//   - for a provider whose credential is scoped per session, the scopes an
//     op declares are enough to run it, undo it and prove it gone.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Harness supplies tenants to the suite.
type Harness struct {
	Provider provider.Provider
	// NewTenant returns a fresh, empty tenant whose audit events are visible
	// immediately.
	NewTenant func(t *testing.T) (provider.Tenant, provider.TargetInfo)
	// Snapshot returns the tenant's objects (not its audit log), so the
	// suite can prove an op leaves the tenant exactly as it found it.
	Snapshot func(t *testing.T) json.RawMessage
	// Version is the tool version used in User-Agents.
	Version string
	// Scoped, if set, opens another connection to the tenant NewTenant last
	// returned, whose credential carries only the given scopes (see
	// provider.Config.Scopes). The suite then runs each op, its setup, Do,
	// Prior, Locate, Undo and Gone, and reads its audit events, through a
	// connection limited to the scopes the op and its setup declare plus the
	// audit source's: the declared scopes are what the core will ask for, so
	// they must be enough. Sweep still runs on the NewTenant connection.
	Scoped func(t *testing.T, scopes []string) provider.Tenant
}

// Run runs the whole suite.
func Run(t *testing.T, h Harness) {
	t.Helper()
	reg := provider.NewRegistry()
	if err := reg.Register(h.Provider); err != nil {
		t.Fatalf("provider does not register: %v", err)
	}
	for _, e := range reg.Ops(h.Provider.Name()) {
		t.Run(e.Spec.Name, func(t *testing.T) { runOp(t, h, reg, e) })
	}
}

type created struct {
	entry *provider.Entry
	call  *provider.Call
	rec   provider.Record
}

func runOp(t *testing.T, h Harness, reg *provider.Registry, e *provider.Entry) {
	tenant, info := h.NewTenant(t)
	before := h.Snapshot(t)
	// sweeper lists the tenant; tenant runs the op. They differ only when the
	// harness can narrow a connection to the op's declared scopes.
	sweeper := tenant
	if h.Scoped != nil {
		tenant = h.Scoped(t, declaredScopes(reg, h.Provider, e))
	}
	run, err := marker.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start := time.Now().Add(-time.Minute)
	dctx := provider.WithUserAgent(ctx, marker.UserAgent(h.Version, run, marker.PhaseDetonate))
	cctx := provider.WithUserAgent(ctx, marker.UserAgent(h.Version, run, marker.PhaseCleanup))

	// Build whatever the op's ref parameters point at.
	var deps []created
	n := 0
	var build func(entry *provider.Entry) map[string]string
	build = func(entry *provider.Entry) map[string]string {
		params := map[string]string{}
		for _, p := range entry.Spec.Params {
			switch p.Type {
			case provider.ParamRef:
				dep := producer(reg, p.Ref)
				if dep == nil {
					t.Fatalf("param %s: no create op produces %s", p.Name, p.Ref)
				}
				dparams := build(dep)
				n++
				step := fmt.Sprintf("dep%d", n)
				call := &provider.Call{Run: run, Step: step, Name: marker.ObjectName(run, step), Params: dparams, Target: info, Tenant: tenant}
				res, err := dep.Op.Do(dctx, call)
				if err != nil {
					t.Fatalf("setup %s: %v", dep.Spec.Name, err)
				}
				deps = append(deps, created{entry: dep, call: call, rec: provider.Record{ID: res.ID, Outputs: res.Outputs}})
				params[p.Name] = res.ID
			case provider.ParamEnum:
				params[p.Name] = p.Example
				if params[p.Name] == "" {
					params[p.Name] = p.Enum[0]
				}
			case provider.ParamString:
				params[p.Name] = p.Example
			}
		}
		return params
	}
	params := build(e)
	call := &provider.Call{Run: run, Step: "subject", Name: marker.ObjectName(run, "subject"), Params: params, Target: info, Tenant: tenant}

	rec := provider.Record{}
	if e.Spec.Kind == provider.KindModify {
		prior, err := e.Prior.Prior(dctx, call)
		if err != nil || len(prior) == 0 {
			t.Fatalf("Prior: %v (len %d): a modify op must read the value it changes", err, len(prior))
		}
		rec.Prior = prior
	}
	res, err := e.Op.Do(dctx, call)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.ID == "" {
		t.Fatalf("Do returned no resource ID")
	}
	for k := range res.Outputs {
		if !e.Spec.HasOutput(k) {
			t.Errorf("Do returned undeclared output %q", k)
		}
	}
	rec.ID, rec.Outputs = res.ID, res.Outputs

	if gone, err := e.Gone.Gone(cctx, call, rec); err != nil || gone {
		t.Errorf("Gone right after Do = %v, %v; want false: Gone must see what Do did", gone, err)
	}

	if e.Spec.Kind == provider.KindCreate {
		found, ok, err := e.Locate.Locate(cctx, call)
		if err != nil || !ok || found.ID != res.ID {
			t.Errorf("Locate(%q) = %+v, %v, %v; want the created object %s", call.Name, found, ok, err, res.ID)
		}
		for _, near := range []string{call.Name + "x", call.Name[:len(call.Name)-1], marker.RunPrefix(run)} {
			other := *call
			other.Name = near
			if _, ok, err := e.Locate.Locate(cctx, &other); err != nil || ok {
				t.Errorf("Locate(%q) = found=%v err=%v; Locate must match the exact name only", near, ok, err)
			}
		}
		orphans, err := sweeper.Sweep(cctx, marker.RunPrefix(run)+"-")
		if err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if !hasOrphan(orphans, e.Spec.Name, call.Name, res.ID) {
			t.Errorf("Sweep did not report the object %s (%s) as an orphan of op %s: %+v", call.Name, res.ID, e.Spec.Name, orphans)
		}
	}

	checkEvents(t, ctx, tenant, run, start, marker.PhaseDetonate, e.Spec.Events, "Do")
	touchesRunObject := e.Spec.Kind == provider.KindCreate || len(deps) > 0
	checkCorrelatable(t, ctx, tenant, run, start, marker.PhaseDetonate, touchesRunObject, "Do")

	if err := e.Undo.Undo(cctx, call, rec); err != nil {
		t.Fatalf("Undo: %v", err)
	}
	if gone, err := e.Gone.Gone(cctx, call, rec); err != nil || !gone {
		t.Fatalf("Gone after Undo = %v, %v; want true", gone, err)
	}
	if err := e.Undo.Undo(cctx, call, rec); err != nil && !errors.Is(err, provider.ErrNotFound) {
		t.Errorf("second Undo = %v; Undo on an undone object must succeed or wrap ErrNotFound", err)
	}
	if gone, err := e.Gone.Gone(cctx, call, rec); err != nil || !gone {
		t.Errorf("Gone after a second Undo = %v, %v; want true", gone, err)
	}
	if e.Spec.Kind == provider.KindCreate {
		if _, ok, err := e.Locate.Locate(cctx, call); err != nil || ok {
			t.Errorf("Locate after Undo = found=%v err=%v; want not found", ok, err)
		}
	}
	checkEvents(t, ctx, tenant, run, start, marker.PhaseCleanup, e.Spec.UndoEvents, "Undo")
	checkCorrelatable(t, ctx, tenant, run, start, marker.PhaseCleanup, touchesRunObject, "Undo")

	for i := len(deps) - 1; i >= 0; i-- {
		d := deps[i]
		if err := d.entry.Undo.Undo(cctx, d.call, d.rec); err != nil && !errors.Is(err, provider.ErrNotFound) {
			t.Fatalf("teardown %s: %v", d.entry.Spec.Name, err)
		}
		if gone, err := d.entry.Gone.Gone(cctx, d.call, d.rec); err != nil || !gone {
			t.Fatalf("teardown %s: gone = %v, %v", d.entry.Spec.Name, gone, err)
		}
	}
	if left, err := sweeper.Sweep(cctx, marker.RunPrefix(run)+"-"); err != nil || len(left) != 0 {
		t.Errorf("after teardown Sweep = %+v, %v; want nothing left", left, err)
	}
	if after := h.Snapshot(t); string(after) != string(before) {
		t.Errorf("the tenant is not as the op found it:\nbefore %s\nafter  %s", before, after)
	}
}

// declaredScopes is what running e needs by declaration: its own scopes, those
// of every op the suite runs to build its ref parameters, and the audit
// source's.
func declaredScopes(reg *provider.Registry, p provider.Provider, e *provider.Entry) []string {
	set := map[string]bool{}
	for _, s := range p.Audit().Scopes {
		set[s] = true
	}
	var walk func(entry *provider.Entry)
	walk = func(entry *provider.Entry) {
		for _, s := range entry.Spec.Scopes {
			set[s] = true
		}
		for _, prm := range entry.Spec.Params {
			if prm.Type == provider.ParamRef {
				if dep := producer(reg, prm.Ref); dep != nil {
					walk(dep)
				}
			}
		}
	}
	walk(e)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// producer returns the first create op (by name) producing resource.
func producer(reg *provider.Registry, resource string) *provider.Entry {
	for _, e := range reg.Ops() {
		if e.Spec.Kind == provider.KindCreate && e.Spec.Resource == resource {
			return e
		}
	}
	return nil
}

func hasOrphan(os []provider.Orphan, op, name, id string) bool {
	for _, o := range os {
		if o.Op == op && o.Name == name && o.Record.ID == id {
			return true
		}
	}
	return false
}

// checkEvents requires every declared event type to have been emitted under
// the run's marker in the given phase.
func checkEvents(t *testing.T, ctx context.Context, tenant provider.Tenant, run string, since time.Time, phase marker.Phase, want []string, what string) {
	t.Helper()
	evs, err := tenant.AuditSource().Poll(ctx, provider.AuditQuery{Since: since, Until: time.Now().Add(time.Minute), Run: run})
	if err != nil {
		t.Fatalf("audit poll: %v", err)
	}
	got := map[string]bool{}
	for _, ev := range evs {
		ua, ok := marker.ParseUserAgent(ev.UserAgent)
		if !ok || ua.Run != run {
			continue
		}
		if ua.Phase == phase {
			got[ev.Type] = true
		}
	}
	var missing []string
	for _, w := range want {
		if !got[w] {
			missing = append(missing, w)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%s: declared events %v were not logged with User-Agent run=%s phase=%s (logged: %v)", what, missing, run, phase, keys(got))
	}
}

// checkCorrelatable requires every event the run caused in phase to carry a
// correlation signal besides its User-Agent, so the collector can still
// attribute it to the run on a platform that does not record the User-Agent:
// one of the run's object names in Event.Objects, or the run's credential in
// Event.Credential. An op that touches nothing the run created can only be
// recognised by its credential; on a platform that records none, its events
// are attributable by the User-Agent alone and the check does not apply.
func checkCorrelatable(t *testing.T, ctx context.Context, tenant provider.Tenant, run string, since time.Time, phase marker.Phase, touchesRunObject bool, what string) {
	t.Helper()
	src := tenant.AuditSource()
	cred := ""
	if cr, ok := src.(provider.CredentialRecorder); ok {
		cred = cr.RecordedCredential()
	}
	if !touchesRunObject && cred == "" {
		return
	}
	evs, err := src.Poll(ctx, provider.AuditQuery{Since: since, Until: time.Now().Add(time.Minute), Run: run})
	if err != nil {
		t.Fatalf("audit poll: %v", err)
	}
	for _, ev := range evs {
		ua, ok := marker.ParseUserAgent(ev.UserAgent)
		if !ok || ua.Run != run || ua.Phase != phase {
			continue
		}
		if cred != "" && ev.Credential == cred {
			continue
		}
		named := false
		for _, v := range ev.Objects {
			for _, name := range marker.FindObjectNames(v) {
				if r, _, _ := marker.ParseObjectName(name); r == run {
					named = true
				}
			}
		}
		if !named {
			t.Errorf("%s: event %s %s names none of run %s's objects (Objects %q) and carries no credential the platform records for this run, so without its User-Agent it could not be attributed to the run", what, ev.ID, ev.Type, run, ev.Objects)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
