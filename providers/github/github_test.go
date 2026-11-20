package github_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/conformance"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/providers/github"
	"github.com/HarrisonHong/saashound/providers/github/mockgithub"
)

const (
	testToken     = "ghp-test-token-9f8e7d"
	testPrincipal = "github-bot"
	testOrg       = "acme-labs"
	testDomain    = "lab.example.com"
	secondAccount = "octo-second"
)

// newMock starts a mock org and returns it plus a Config that opens the github
// provider against it. The org is seeded with an operator-owned second account
// (the synthetic outside collaborator / owner-promotion subject).
func newMock(t *testing.T, opts ...mockgithub.Option) (*mockgithub.Server, provider.Config) {
	t.Helper()
	opts = append([]mockgithub.Option{
		mockgithub.WithToken(testToken), mockgithub.WithPrincipal(testPrincipal),
		mockgithub.WithOrg(testOrg), mockgithub.WithMember(secondAccount),
	}, opts...)
	srv := mockgithub.New(opts...)
	t.Cleanup(srv.Close)
	cfg := provider.Config{
		Target: provider.TargetInfo{
			Name: "lab", Platform: github.Name, Tenant: srv.OrgLogin(), Principal: testPrincipal,
			Environment: "lab", TestDomain: testDomain,
			Options: map[string]string{"api_url": srv.URL(), "second_account": secondAccount},
		},
		Credential: secret.Ref{Env: "GITHUB_TOKEN"},
		Secrets:    secret.DefaultSource{LookupEnv: func(k string) (string, bool) { return testToken, k == "GITHUB_TOKEN" }},
	}
	return srv, cfg
}

func open(t *testing.T, cfg provider.Config) provider.Tenant {
	t.Helper()
	ten, err := github.New().Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = ten.Close() })
	return ten
}

// TestConformance runs the full op-conformance suite against the mock org.
func TestConformance(t *testing.T) {
	var current *mockgithub.Server
	conformance.Run(t, conformance.Harness{
		Provider: github.New(),
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
	if _, ok := provider.Default.Provider(github.Name); !ok {
		t.Fatal("the github provider must register itself in init()")
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
	if id.Tenant != testOrg {
		t.Fatalf("tenant = %q, want %q", id.Tenant, testOrg)
	}
	if id.Principal != testPrincipal {
		t.Fatalf("principal = %q", id.Principal)
	}
	if id.ActiveUsers != 2 { // the token owner plus the seeded second account
		t.Fatalf("active users = %d, want 2", id.ActiveUsers)
	}

	if _, found, err := ten.ReadMarker(ctx); err != nil || found {
		t.Fatalf("marker before placement: found=%v err=%v", found, err)
	}
	srv.PlaceMarker(github.MarkerRepo, github.MarkerFile, "saashound-authorized:abc123")
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
	cred := secret.Ref{Env: "T"}
	src := secret.DefaultSource{LookupEnv: func(string) (string, bool) { return "x", true }}

	// No credential.
	bad := provider.Config{Target: provider.TargetInfo{Tenant: testOrg}, Secrets: secret.DefaultSource{}}
	if _, err := github.New().Open(ctx, bad); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing token accepted: %v", err)
	}
	// Malformed org slugs.
	for _, org := range []string{"", "has/slash", "has space", "-leadinghyphen", "way-too-long-an-organization-login-exceeding-the-limit"} {
		c := provider.Config{Target: provider.TargetInfo{Tenant: org}, Credential: cred, Secrets: src}
		if _, err := github.New().Open(ctx, c); err == nil {
			t.Errorf("org slug %q accepted", org)
		}
	}
	// Non-https, non-loopback api_url.
	c := provider.Config{Target: provider.TargetInfo{Tenant: testOrg, Options: map[string]string{"api_url": "http://evil.example.com"}}, Credential: cred, Secrets: src}
	if _, err := github.New().Open(ctx, c); err == nil {
		t.Errorf("non-loopback http api_url accepted")
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

// TestAuditEventsCarryCorrelationSignals: the audit source reports each
// event's repository names and hashed_token, and its own credential as GitHub
// records it (the base64 SHA-256 of the token, which `echo -n $TOKEN |
// openssl dgst -sha256 -binary | base64` reproduces), so the collector can
// correlate an event whose User-Agent GitHub did not record.
func TestAuditEventsCarryCorrelationSignals(t *testing.T) {
	const wantHash = "IfvLP7DVl4iOKwChr3EZBXzz210x6WAiLsGsDRRS0Qc=" // of testToken
	ctx := context.Background()
	_, cfg := newMock(t, mockgithub.WithRecordedUserAgent(func(string) string { return "" }))
	ten := open(t, cfg)
	src := ten.AuditSource()
	cr, ok := src.(provider.CredentialRecorder)
	if !ok {
		t.Fatal("the github audit source does not report the credential it records")
	}
	if got := cr.RecordedCredential(); got != wantHash || got != mockgithub.HashedToken(testToken) {
		t.Fatalf("RecordedCredential() = %q, want %q", got, wantHash)
	}

	run := "k3v9q2"
	reg := provider.NewRegistry()
	if err := reg.Register(github.New()); err != nil {
		t.Fatal(err)
	}
	repo, _ := reg.Op("github.repo.create")
	call := &provider.Call{Run: run, Step: "repo", Name: marker.ObjectName(run, "repo"), Params: map[string]string{}, Target: cfg.Target, Tenant: ten}
	dctx := provider.WithUserAgent(ctx, marker.UserAgent("t", run, marker.PhaseDetonate))
	if _, err := repo.Op.Do(dctx, call); err != nil {
		t.Fatal(err)
	}
	evs, err := src.Poll(ctx, provider.AuditQuery{Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	if err != nil || len(evs) != 1 {
		t.Fatalf("poll = %d events, %v; want the repo.create event", len(evs), err)
	}
	ev := evs[0]
	if ev.Type != "repo.create" || ev.UserAgent != "" || ev.Credential != wantHash || ev.Time.IsZero() {
		t.Fatalf("event = %+v", ev)
	}
	if len(ev.Objects) != 1 || ev.Objects[0] != testOrg+"/"+call.Name {
		t.Fatalf("Objects = %q, want the run's repository", ev.Objects)
	}
	if err := ten.Close(); err != nil {
		t.Fatal(err)
	}
	if got := cr.RecordedCredential(); got != "" {
		t.Fatalf("RecordedCredential() after Close = %q; the token is gone, so nothing can match it", got)
	}
}
