package okta_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/conformance"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/providers/okta"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

const (
	keyEnv     = "OKTA_KEY"
	testDomain = "lab.example.com"
)

// keySource serves pemOrJWK as the OKTA_KEY environment variable.
func keySource(pemOrJWK string) secret.Source {
	return secret.DefaultSource{LookupEnv: func(k string) (string, bool) { return pemOrJWK, k == keyEnv }}
}

// allOpScopes is every scope the provider's ops and audit source declare:
// what a session that may run any op asks for.
func allOpScopes() []string {
	p := okta.New()
	set := map[string]bool{}
	for _, s := range p.Audit().Scopes {
		set[s] = true
	}
	for _, op := range p.Ops() {
		for _, s := range op.Spec().Scopes {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// newMock starts a mock org and returns it plus a Config that opens the okta
// provider against it as its service app, with the default key (as the JWK
// the Admin Console generates, which carries its kid) and the scopes of every
// op.
func newMock(t *testing.T, opts ...mockokta.Option) (*mockokta.Server, provider.Config) {
	t.Helper()
	srv := mockokta.New(opts...)
	t.Cleanup(srv.Close)
	cfg := provider.Config{
		Target: provider.TargetInfo{
			Name: "lab", Platform: okta.Name, Tenant: srv.URL(), Principal: srv.ClientID(),
			Environment: "lab", TestDomain: testDomain,
		},
		Credential: secret.Ref{Env: keyEnv},
		Secrets:    keySource(mockokta.DefaultKey().JWK()),
		Scopes:     allOpScopes(),
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
// Each op runs through a connection whose token carries only the scopes the
// op and its setup declare (the mock org enforces every endpoint's scope), so
// a declared scope list that is not enough fails here. The suite builds one
// tenant then snapshots it within the same (sequential) subtest, so the last
// server handed out is the one Snapshot and Scoped use.
func TestConformance(t *testing.T) {
	var (
		current *mockokta.Server
		baseCfg provider.Config
	)
	conformance.Run(t, conformance.Harness{
		Provider: okta.New(),
		Version:  "test",
		NewTenant: func(t *testing.T) (provider.Tenant, provider.TargetInfo) {
			srv, cfg := newMock(t)
			current, baseCfg = srv, cfg
			return open(t, cfg), cfg.Target
		},
		Scoped: func(t *testing.T, scopes []string) provider.Tenant {
			cfg := baseCfg
			cfg.Scopes = scopes
			return open(t, cfg)
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
	if id.Principal != srv.ClientID() {
		t.Fatalf("principal = %q, want the service app's client ID %q", id.Principal, srv.ClientID())
	}
	if id.ActiveUsers != 1 {
		t.Fatalf("active users = %d, want 1 (the org's admin)", id.ActiveUsers)
	}
	if !slices.Equal(id.Roles, []string{"SUPER_ADMIN"}) {
		t.Fatalf("roles = %v, want the service app's SUPER_ADMIN", id.Roles)
	}
	for _, want := range []string{"okta.logs.read", "okta.users.manage", "okta.groups.read", "okta.orgs.read"} {
		if !slices.Contains(id.Scopes, want) {
			t.Errorf("identity scopes %v lack %s", id.Scopes, want)
		}
	}
	if !strings.Contains(id.Credential, "private_key_jwt") || !strings.Contains(id.Credential, "valid 1h") {
		t.Fatalf("credential = %q; want the OAuth service app and its token lifetime", id.Credential)
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
	src := keySource(mockokta.DefaultKey().PEM())
	cred := secret.Ref{Env: keyEnv}
	good := provider.TargetInfo{Tenant: "https://x.okta.com", Principal: mockokta.DefaultClientID}
	cases := map[string]struct {
		cfg  provider.Config
		want string
	}{
		"no credential": {provider.Config{Target: good, Secrets: src}, "private key"},
		"login principal": {provider.Config{Target: provider.TargetInfo{Tenant: good.Tenant, Principal: "bot@example.com"},
			Credential: cred, Secrets: src}, "client ID"},
		"no principal": {provider.Config{Target: provider.TargetInfo{Tenant: good.Tenant}, Credential: cred, Secrets: src}, "client ID"},
		"unknown option": {provider.Config{Target: provider.TargetInfo{Tenant: good.Tenant, Principal: good.Principal,
			Options: map[string]string{"api_token": "x"}}, Credential: cred, Secrets: src}, "unknown target option"},
		"not a key": {provider.Config{Target: good, Credential: cred, Secrets: keySource("00abcSSWS-token")}, "not usable"},
	}
	for name, c := range cases {
		if _, err := okta.New().Open(ctx, c.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Open = %v; want an error mentioning %q", name, err, c.want)
		}
	}
	// Non-https, non-loopback or malformed tenants.
	for _, tenant := range []string{"http://evil.example.com", "ftp://x", "https://x.okta.com/path", "not-a-url"} {
		c := provider.Config{Target: provider.TargetInfo{Tenant: tenant, Principal: good.Principal}, Credential: cred, Secrets: src}
		if _, err := okta.New().Open(ctx, c); err == nil {
			t.Errorf("tenant %q accepted", tenant)
		}
	}
}

// TestWrongKeyIsRejected proves a key the app does not hold cannot get a token,
// and that the refusal explains what to check without quoting any credential.
func TestWrongKeyIsRejected(t *testing.T) {
	srv, cfg := newMock(t)
	other, err := mockokta.NewRSAKey(mockokta.DefaultKeyID, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Secrets = keySource(other.PEM())
	ten := open(t, cfg)
	_, err = ten.Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not accept principal (client ID) "+srv.ClientID()) ||
		!strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("wrong key = %v; want the org's invalid_client refusal, explained", err)
	}
	assertNoCredential(t, err.Error(), srv, other.PEM())
	if srv.Mints() != 0 {
		t.Fatalf("a token was minted for a key the app does not hold")
	}
}

// TestWrongClientIsRejected proves a target whose principal is not the app the
// key belongs to cannot authenticate: the principal check is live.
func TestWrongClientIsRejected(t *testing.T) {
	_, cfg := newMock(t)
	cfg.Target.Principal = "0oaSomeOtherApp9"
	ten := open(t, cfg)
	if _, err := ten.Whoami(context.Background()); err == nil || !strings.Contains(err.Error(), "principal (client ID) 0oaSomeOtherApp9") {
		t.Fatalf("wrong client = %v; want a refusal naming the principal", err)
	}
}
