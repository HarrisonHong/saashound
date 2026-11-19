package okta_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/conformance"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/providers/okta"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

const (
	testToken     = "ssws-test-token-9f8e7d"
	testPrincipal = "okta-bot@example.com"
	testDomain    = "lab.example.com"
)

// newMock starts a mock org and returns it plus a Config that opens the okta
// provider against it.
func newMock(t *testing.T, opts ...mockokta.Option) (*mockokta.Server, provider.Config) {
	t.Helper()
	opts = append([]mockokta.Option{mockokta.WithToken(testToken), mockokta.WithPrincipal(testPrincipal)}, opts...)
	srv := mockokta.New(opts...)
	t.Cleanup(srv.Close)
	cfg := provider.Config{
		Target: provider.TargetInfo{
			Name: "lab", Platform: okta.Name, Tenant: srv.URL(), Principal: testPrincipal,
			Environment: "lab", TestDomain: testDomain,
		},
		Credential: secret.Ref{Env: "OKTA_TOKEN"},
		Secrets:    secret.DefaultSource{LookupEnv: func(k string) (string, bool) { return testToken, k == "OKTA_TOKEN" }},
	}
	return srv, cfg
}

func open(t *testing.T, cfg provider.Config) provider.Tenant {
	t.Helper()
	ten, err := okta.New().Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = ten.Close() })
	return ten
}

// TestConformance runs the full op-conformance suite against the mock org.
// The suite builds one tenant then snapshots it within the same (sequential)
// subtest, so the last server handed out is the one Snapshot reads.
func TestConformance(t *testing.T) {
	var current *mockokta.Server
	conformance.Run(t, conformance.Harness{
		Provider: okta.New(),
		Version:  "test",
		NewTenant: func(t *testing.T) (provider.Tenant, provider.TargetInfo) {
			srv, cfg := newMock(t)
			current = srv
			return open(t, cfg), cfg.Target
		},
		Snapshot: func(t *testing.T) json.RawMessage {
			if current == nil {
				t.Fatal("no mock server for snapshot")
			}
			return current.Snapshot()
		},
	})
}

func TestRegisteredInDefaultRegistry(t *testing.T) {
	if _, ok := provider.Default.Provider(okta.Name); !ok {
		t.Fatal("the okta provider must register itself in init()")
	}
}

func TestWhoamiAndMarker(t *testing.T) {
	srv, cfg := newMock(t)
	ten := open(t, cfg)
	ctx := context.Background()

	id, err := ten.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id.Tenant != srv.URL() {
		t.Fatalf("tenant = %q, want %q", id.Tenant, srv.URL())
	}
	if id.Principal != testPrincipal {
		t.Fatalf("principal = %q", id.Principal)
	}
	if id.ActiveUsers != 1 {
		t.Fatalf("active users = %d, want 1 (the token user)", id.ActiveUsers)
	}

	if _, found, err := ten.ReadMarker(ctx); err != nil || found {
		t.Fatalf("marker before placement: found=%v err=%v", found, err)
	}
	srv.PlaceMarker("saashound-authorized", "saashound-authorized:abc123")
	v, found, err := ten.ReadMarker(ctx)
	if err != nil || !found || v != "saashound-authorized:abc123" {
		t.Fatalf("marker = %q %v %v", v, found, err)
	}

	caps, err := ten.Capabilities(ctx)
	if err != nil || !caps.Audit {
		t.Fatalf("caps = %+v %v; want audit reachable", caps, err)
	}
}

func TestOpenRejectsBadConfig(t *testing.T) {
	ctx := context.Background()
	// No credential.
	bad := provider.Config{Target: provider.TargetInfo{Tenant: "https://x.okta.com"}, Secrets: secret.DefaultSource{}}
	if _, err := okta.New().Open(ctx, bad); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing token accepted: %v", err)
	}
	// Non-https, non-loopback tenant.
	cred := secret.Ref{Env: "T"}
	src := secret.DefaultSource{LookupEnv: func(string) (string, bool) { return "x", true }}
	for _, tenant := range []string{"http://evil.example.com", "ftp://x", "https://x.okta.com/path", "not-a-url"} {
		c := provider.Config{Target: provider.TargetInfo{Tenant: tenant}, Credential: cred, Secrets: src}
		if _, err := okta.New().Open(ctx, c); err == nil {
			t.Errorf("tenant %q accepted", tenant)
		}
	}
}

func TestWrongTokenIsRejected(t *testing.T) {
	_, cfg := newMock(t)
	cfg.Secrets = secret.DefaultSource{LookupEnv: func(string) (string, bool) { return "wrong-token", true }}
	ten := open(t, cfg)
	if _, err := ten.Whoami(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token = %v; want 401", err)
	}
}
