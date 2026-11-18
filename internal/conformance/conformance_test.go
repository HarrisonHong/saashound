package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/HarrisonHong/saashound/internal/conformance"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/providers/fake"
)

const breakEnv = "SAASHOUND_CONFORMANCE_BREAK"

// broken wraps the fake provider with one deliberate defect.
type broken struct {
	*fake.Provider
	kind string
}

func (b broken) Ops() []provider.Op {
	var out []provider.Op
	for _, op := range b.Provider.Ops() {
		out = append(out, &brokenOp{Op: op, kind: b.kind, undone: map[string]bool{}})
	}
	return out
}

type brokenOp struct {
	provider.Op
	kind   string
	mu     sync.Mutex
	undone map[string]bool
}

func (o *brokenOp) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	if o.kind == "no-user-agent" {
		ctx = context.Background() // forgets the run's User-Agent
	}
	return o.Op.Do(ctx, c)
}

func (o *brokenOp) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	o.mu.Lock()
	again := o.undone[r.ID]
	o.undone[r.ID] = true
	o.mu.Unlock()
	if o.kind == "undo-not-idempotent" && again {
		return errors.New("404 page not found") // does not wrap ErrNotFound
	}
	return o.Op.(provider.Inverter).Undo(ctx, c, r)
}

func (o *brokenOp) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	if o.kind == "gone-always-true" {
		return true, nil
	}
	return o.Op.(provider.GoneProver).Gone(ctx, c, r)
}

func (o *brokenOp) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	l := o.Op.(provider.Locator)
	res, found, err := l.Locate(ctx, c)
	if o.kind != "locate-by-prefix" || found || err != nil {
		return res, found, err
	}
	// Stratus-style revert-by-search: settle for any name sharing a prefix.
	for n := len(c.Name) - 1; n > len(c.Name)-4 && n > 0; n-- {
		cc := *c
		cc.Name = c.Name[:n]
		if res, found, err := l.Locate(ctx, &cc); found || err != nil {
			return res, found, err
		}
	}
	return res, found, err
}

func (o *brokenOp) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	return o.Op.(provider.PriorReader).Prior(ctx, c)
}

func harness(p provider.Provider, store *fake.MemoryStore, sim *fake.Provider) conformance.Harness {
	n := 0
	var current string
	return conformance.Harness{
		Provider: p,
		Version:  "test",
		NewTenant: func(t *testing.T) (provider.Tenant, provider.TargetInfo) {
			n++
			current = fmt.Sprintf("conf-%d", n)
			cfg := provider.Config{Target: provider.TargetInfo{Name: "t", Platform: fake.Name, Tenant: current, Principal: "op", Environment: "lab", TestDomain: "lab.example.com"}}
			if err := sim.Provision(context.Background(), cfg); err != nil {
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
	}
}

// TestBrokenProviderHelper runs the suite against a broken provider. It only
// runs as the child of TestSuiteCatchesBrokenProviders, which expects it to
// fail.
func TestBrokenProviderHelper(t *testing.T) {
	kind := os.Getenv(breakEnv)
	if kind == "" {
		t.Skip("helper for TestSuiteCatchesBrokenProviders")
	}
	store := fake.NewMemoryStore()
	sim := fake.New(fake.WithStore(store))
	conformance.Run(t, harness(broken{Provider: sim, kind: kind}, store, sim))
}

func TestSuiteCatchesBrokenProviders(t *testing.T) {
	cases := map[string]string{
		"gone-always-true":    "want false: Gone must see what Do did",
		"locate-by-prefix":    "Locate must match the exact name only",
		"undo-not-idempotent": "Undo on an undone object must succeed or wrap ErrNotFound",
		"no-user-agent":       "were not logged with User-Agent",
	}
	for kind, want := range cases {
		t.Run(kind, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenProviderHelper$", "-test.v")
			cmd.Env = append(os.Environ(), breakEnv+"="+kind)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("the conformance suite passed a provider with defect %q:\n%s", kind, out)
			}
			if !strings.Contains(string(out), want) {
				t.Fatalf("defect %q was not reported as %q:\n%s", kind, want, out)
			}
		})
	}
}

func TestSuitePassesTheFakeProvider(t *testing.T) {
	store := fake.NewMemoryStore()
	sim := fake.New(fake.WithStore(store))
	conformance.Run(t, harness(sim, store, sim))
}
