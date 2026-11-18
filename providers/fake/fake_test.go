package fake_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/conformance"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/providers/fake"
)

func newConfig(tenant string, opts map[string]string) provider.Config {
	return provider.Config{
		Target: provider.TargetInfo{
			Name: "t", Platform: fake.Name, Tenant: tenant, Principal: "saashound-operator",
			Environment: "lab", TestDomain: "lab.example.com", Options: opts,
		},
		Secrets: secret.DefaultSource{},
	}
}

func TestConformance(t *testing.T) {
	store := fake.NewMemoryStore()
	p := fake.New(fake.WithStore(store))
	n := 0
	var current string
	conformance.Run(t, conformance.Harness{
		Provider: p,
		Version:  "test",
		NewTenant: func(t *testing.T) (provider.Tenant, provider.TargetInfo) {
			n++
			current = fmt.Sprintf("conf-%d", n)
			cfg := newConfig(current, nil)
			if err := p.Provision(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			ten, err := p.Open(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			return ten, cfg.Target
		},
		Snapshot: func(t *testing.T) json.RawMessage {
			s, err := fake.Snapshot(store, current)
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
}

func TestRegisteredInDefaultRegistry(t *testing.T) {
	if _, ok := provider.Default.Provider(fake.Name); !ok {
		t.Fatal("the fake provider must register itself in init()")
	}
}

func open(t *testing.T, p *fake.Provider, cfg provider.Config) provider.Tenant {
	t.Helper()
	ten, err := p.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ten
}

func TestWhoamiAndMarker(t *testing.T) {
	p := fake.New(fake.WithStore(fake.NewMemoryStore()))
	cfg := newConfig("sim-a", nil)
	ctx := context.Background()
	if _, err := p.Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), "init") {
		t.Fatalf("opening an unprovisioned tenant = %v; want a hint to run init", err)
	}
	if err := p.Provision(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, cfg); err == nil {
		t.Fatal("provisioning twice must fail")
	}
	ten := open(t, p, cfg)
	id, err := ten.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tenant != "sim-a" || id.Principal != "saashound-operator" || id.ActiveUsers != 2 || id.ShortName != "sim-a" {
		t.Fatalf("Whoami = %+v", id)
	}
	if _, found, err := ten.ReadMarker(ctx); err != nil || found {
		t.Fatalf("marker before placement: found=%v err=%v", found, err)
	}
	if err := p.PlaceMarker(ctx, cfg, "saashound-authorized:abc"); err != nil {
		t.Fatal(err)
	}
	if v, found, err := ten.ReadMarker(ctx); err != nil || !found || v != "saashound-authorized:abc" {
		t.Fatalf("marker = %q %v %v", v, found, err)
	}
	// Re-placing updates the description rather than adding a second group.
	if err := p.PlaceMarker(ctx, cfg, "saashound-authorized:def"); err != nil {
		t.Fatal(err)
	}
	if v, _, _ := ten.ReadMarker(ctx); v != "saashound-authorized:def" {
		t.Fatalf("marker after update = %q", v)
	}
	// The marker group is never swept: its name is not a run object name.
	orphans, err := ten.Sweep(ctx, marker.Prefix+"-")
	if err != nil || len(orphans) != 0 {
		t.Fatalf("Sweep = %+v, %v; the marker must never be an orphan", orphans, err)
	}
}

func TestCredential(t *testing.T) {
	ctx := context.Background()
	store := fake.NewMemoryStore()
	p := fake.New(fake.WithStore(store))
	cfg := newConfig("sim-cred", nil)
	cfg.Credential = secret.Ref{Env: "FAKE_TOKEN"}
	env := map[string]string{"FAKE_TOKEN": "right-token"}
	cfg.Secrets = secret.DefaultSource{LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	if err := p.Provision(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Open(ctx, cfg); err != nil {
		t.Fatalf("right token rejected: %v", err)
	}
	env["FAKE_TOKEN"] = "wrong-token"
	if _, err := p.Open(ctx, cfg); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token = %v; want 401", err)
	}
	delete(env, "FAKE_TOKEN")
	if _, err := p.Open(ctx, cfg); err == nil {
		t.Fatal("missing token accepted")
	}
	anon := newConfig("sim-cred", nil)
	if _, err := p.Open(ctx, anon); err == nil {
		t.Fatal("a tenant provisioned with a credential must refuse an anonymous target")
	}
	// The tenant stores a digest, never the token.
	snap, err := fake.Snapshot(store, "sim-cred")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snap), "right-token") {
		t.Fatal("the simulated tenant stored the raw credential")
	}
}

func TestAuditLagDropAndUnsupported(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	p := fake.New(fake.WithStore(fake.NewMemoryStore()))
	cfg := newConfig("sim-lag", map[string]string{
		"audit_lag":                          "10s",
		"audit_lag/user.mfa.factor.activate": "1m",
		"audit_drop":                         "user.lifecycle.deactivate",
	})
	cfg.Clock = clk
	if err := p.Provision(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	ten := open(t, p, cfg)
	reg := provider.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatal(err)
	}
	run := "abcdef"
	dctx := provider.WithUserAgent(ctx, marker.UserAgent("t", run, marker.PhaseDetonate))
	user, _ := reg.Op("fake.user.create")
	ucall := &provider.Call{Run: run, Step: "u", Name: marker.ObjectName(run, "u"), Params: map[string]string{}, Target: cfg.Target, Tenant: ten}
	ures, err := user.Op.Do(dctx, ucall)
	if err != nil {
		t.Fatal(err)
	}
	factor, _ := reg.Op("fake.factor.enroll")
	fcall := &provider.Call{Run: run, Step: "f", Name: marker.ObjectName(run, "f"), Params: map[string]string{"user": ures.ID}, Target: cfg.Target, Tenant: ten}
	if _, err := factor.Op.Do(dctx, fcall); err != nil {
		t.Fatal(err)
	}
	types := func() []string {
		evs, err := ten.AuditSource().Poll(ctx, provider.AuditQuery{Since: clk.Now().Add(-time.Hour), Until: clk.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range evs {
			if ua, ok := marker.ParseUserAgent(e.UserAgent); ok && ua.Run == run {
				out = append(out, e.Type)
			}
		}
		return out
	}
	if got := types(); len(got) != 0 {
		t.Fatalf("events visible before the lag: %v", got)
	}
	clk.Advance(11 * time.Second)
	if got := strings.Join(types(), ","); got != "user.lifecycle.create" {
		t.Fatalf("after 11s: %s", got)
	}
	clk.Advance(time.Minute)
	if got := strings.Join(types(), ","); got != "user.lifecycle.create,user.mfa.factor.activate" {
		t.Fatalf("after 71s: %s", got)
	}
	cctx := provider.WithUserAgent(ctx, marker.UserAgent("t", run, marker.PhaseCleanup))
	if err := user.Undo.Undo(cctx, ucall, provider.Record{ID: ures.ID}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if got := strings.Join(types(), ","); strings.Contains(got, "user.lifecycle.deactivate") || !strings.Contains(got, "user.lifecycle.delete") {
		t.Fatalf("dropped event logged or delete missing: %s", got)
	}

	un := newConfig("sim-lag", map[string]string{"audit": "unsupported"})
	ut := open(t, p, un)
	caps, err := ut.Capabilities(ctx)
	if err != nil || caps.Audit {
		t.Fatalf("caps = %+v %v; want audit unsupported", caps, err)
	}
	if _, err := ut.AuditSource().Poll(ctx, provider.AuditQuery{}); err == nil {
		t.Fatal("poll on an unsupported tier must fail")
	}
}

func TestOptionsAreStrict(t *testing.T) {
	p := fake.New(fake.WithStore(fake.NewMemoryStore()))
	for _, opts := range []map[string]string{
		{"nope": "1"},
		{"audit_lag": "soon"},
		{"audit": "maybe"},
		{"api_latency": "-1s"},
	} {
		if _, err := p.Open(context.Background(), newConfig("x", opts)); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

func TestFileStoreSurvivesProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	cfg := newConfig("sim-file", nil)
	cfg.StateDir = dir
	p := fake.New()
	if err := p.Provision(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tenants", "sim-file.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("tenant file mode %v, want 0600", fi.Mode().Perm())
	}
	ten := open(t, p, cfg)
	reg := provider.NewRegistry()
	if err := reg.Register(fake.New()); err != nil {
		t.Fatal(err)
	}
	user, _ := reg.Op("fake.user.create")
	run := "abcdef"
	call := &provider.Call{Run: run, Step: "u", Name: marker.ObjectName(run, "u"), Params: map[string]string{}, Target: cfg.Target, Tenant: ten}
	if _, err := user.Op.Do(provider.WithUserAgent(ctx, marker.UserAgent("t", run, marker.PhaseDetonate)), call); err != nil {
		t.Fatal(err)
	}
	// A second, independent provider instance (as a later process would
	// be) sees the object.
	ten2 := open(t, fake.New(), cfg)
	res, found, err := user.Locate.Locate(ctx, &provider.Call{Run: run, Step: "u", Name: call.Name, Target: cfg.Target, Tenant: ten2})
	if err != nil || !found || res.ID == "" {
		t.Fatalf("Locate from a fresh instance = %+v %v %v", res, found, err)
	}
	if _, err := fake.New().Open(ctx, func() provider.Config { c := cfg; c.Target.Tenant = "../escape"; return c }()); err == nil {
		t.Fatal("a tenant id with path separators must be refused")
	}
}
