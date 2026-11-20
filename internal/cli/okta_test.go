package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/cli"
	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// oktaKeyEnv holds the service app's private key, as the operator's
// environment would.
const oktaKeyEnv = "OKTA_KEY"

// oktaKey is the service app's private key: the JWK the Admin Console
// generates, which carries its key ID.
func oktaKey() string { return mockokta.DefaultKey().JWK() }

// oktaLab is a mock Okta org wired into the CLI through a targets.yaml that
// points at it, exactly as a real org would be.
type oktaLab struct {
	t     *testing.T
	dir   string
	srv   *mockokta.Server
	clk   *clock.Fake
	runID string
}

func newOktaLab(t *testing.T, place bool, opts ...mockokta.Option) *oktaLab {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(time.Date(2026, 11, 14, 15, 2, 11, 0, time.UTC))
	srv := mockokta.New(append([]mockokta.Option{mockokta.WithClock(clk.Now)}, opts...)...)
	t.Cleanup(srv.Close)
	lab := &oktaLab{t: t, dir: dir, srv: srv, clk: clk}
	// Declare the target in targets.yaml, as `init` does on a real org.
	lab.mustRun("init", "okta", "--platform", "okta", "--tenant", srv.URL(),
		"--principal", srv.ClientID(), "--test-domain", "lab.example.com", "--credential-env", oktaKeyEnv)
	if place {
		lab.placeMarker()
	}
	return lab
}

// placeMarker plays the tenant admin creating the ownership group.
func (l *oktaLab) placeMarker() {
	tgt := &target.Target{Name: "okta", Platform: "okta", Tenant: l.srv.URL(), Principal: l.srv.ClientID(), Environment: "lab"}
	l.srv.PlaceMarker(marker.AuthorizationName, tgt.MarkerValue())
}

func (l *oktaLab) run(args ...string) result {
	l.t.Helper()
	var out, errb bytes.Buffer
	zero := engine.Retry{Attempts: 1, GoneAttempts: 1}
	env := cli.Env{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
		Getenv: func(k string) string {
			if k == oktaKeyEnv {
				return oktaKey()
			}
			return ""
		},
		Registry: provider.Default,
		Clock:    l.clk,
		Retry:    &zero,
		Version:  "0.0.0-test",
	}
	if l.runID != "" {
		id := l.runID
		env.NewRunID = func() (string, error) { return id, nil }
	}
	full := append([]string{"--targets", filepath.Join(l.dir, "targets.yaml"), "--state-dir", filepath.Join(l.dir, "state")}, args...)
	code := cli.Main(context.Background(), full, env)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func (l *oktaLab) mustRun(args ...string) result {
	l.t.Helper()
	r := l.run(args...)
	if r.code != 0 {
		l.t.Fatalf("saashound %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

// oktaTechniques is every technique the okta provider ships.
var oktaTechniques = []string{
	"okta.persistence.mfa-factor-register",
	"okta.persistence.mfa-factor-reset",
	"okta.privilege-escalation.admin-role-assign",
	"okta.privilege-escalation.custom-admin-role",
	"okta.persistence.idp-create",
	"okta.persistence.service-app-api-access",
	"okta.defense-impairment.policy-rule-weaken",
	"okta.defense-impairment.network-zone-deactivate",
}

// TestOktaTechniqueConformance runs every okta technique through the whole
// loop against the mock org: guardrail, detonate, journalled cleanup proven
// verified, System Log collected, expectations matched, and the tenant left
// byte-identical to how it started.
func TestOktaTechniqueConformance(t *testing.T) {
	for _, id := range oktaTechniques {
		t.Run(id, func(t *testing.T) {
			lab := newOktaLab(t, true)
			before := lab.srv.Snapshot()
			r := lab.run("apply", id, "--target", "okta", "--yes", "-q")
			if r.code != report.ExitOK {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			recs := records(t, r.stdout)
			if len(recs) != 1 {
				t.Fatalf("want 1 record, got %d", len(recs))
			}
			rec := recs[0]
			if rec["verdict"] != "pass" {
				t.Fatalf("verdict %v (reason %v)\n%s", rec["verdict"], rec["reason"], r.stdout)
			}
			if rec["platform"] != "okta" || rec["corpus"] != "verified" {
				t.Fatalf("record %v", rec)
			}
			cleanup := rec["cleanup"].(map[string]any)
			if cleanup["status"] != "verified" {
				t.Fatalf("cleanup %v", cleanup)
			}
			tel := rec["telemetry"].(map[string]any)
			if tel["status"] != "observed" || tel["source"] != "okta.system_log" {
				t.Fatalf("telemetry %v", tel)
			}
			if tel["observed"].(float64) != tel["expected"].(float64) || tel["expected"].(float64) < 1 {
				t.Fatalf("telemetry counts %v", tel)
			}
			if after := lab.srv.Snapshot(); string(after) != string(before) {
				t.Fatalf("tenant changed:\nbefore %s\nafter  %s", before, after)
			}
			// A second sweep finds nothing left behind.
			sw := lab.run("sweep", "--target", "okta")
			if sw.code != report.ExitOK || !strings.Contains(sw.stdout, "no "+marker.Prefix+"- objects found") {
				t.Fatalf("sweep: exit %d\n%s", sw.code, sw.stdout)
			}
		})
	}
}

// TestOktaGuardrailRefusals proves the tenant-you-own guarantee against the
// real provider: a missing marker, a principal the key does not authenticate
// as, and a missing key each refuse with exit 2 and run nothing.
func TestOktaGuardrailRefusals(t *testing.T) {
	// Marker missing: the admin has not opted the org in.
	lab := newOktaLab(t, false)
	r := lab.run("apply", oktaTechniques[0], "--target", "okta", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "no ownership marker") {
		t.Fatalf("missing marker: exit %d\n%s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a refusal must print no records: %q", r.stdout)
	}

	// Principal mismatch: the key belongs to a different app than declared.
	lab.placeMarker()
	before := lab.srv.Snapshot()
	tp := filepath.Join(lab.dir, "targets.yaml")
	b, _ := os.ReadFile(tp)
	tampered := bytes.Replace(b, []byte("principal: "+lab.srv.ClientID()), []byte("principal: 0oaSomeOtherApp9"), 1)
	if err := os.WriteFile(tp, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	r = lab.run("apply", oktaTechniques[0], "--target", "okta", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "refused (identity)") || !strings.Contains(r.stderr, "principal (client ID) 0oaSomeOtherApp9") {
		t.Fatalf("principal mismatch: exit %d\n%s", r.code, r.stderr)
	}

	// A login as the principal, from an SSWS-era targets.yaml, is refused
	// with what to change.
	tampered = bytes.Replace(b, []byte("principal: "+lab.srv.ClientID()), []byte("principal: okta-bot@example.com"), 1)
	if err := os.WriteFile(tp, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	r = lab.run("auth", "okta")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "must be that app's client ID") {
		t.Fatalf("login principal: exit %d\n%s", r.code, r.stderr)
	}

	// Missing key: the credential env var is unset.
	if err := os.WriteFile(tp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	env := cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }, Registry: provider.Default, Clock: lab.clk}
	code := cli.Main(context.Background(), []string{"--targets", tp, "--state-dir", filepath.Join(lab.dir, "state3"), "apply", oktaTechniques[0], "--target", "okta", "--yes"}, env)
	if code != report.ExitRefused || !strings.Contains(errb.String(), oktaKeyEnv) {
		t.Fatalf("missing key: exit %d\n%s", code, errb.String())
	}
	if after := lab.srv.Snapshot(); string(after) != string(before) {
		t.Fatal("a refused run changed the org")
	}
}

// TestOktaCanarySecret drives every okta command at maximum verbosity and
// fails if any credential appears in any output or any file the tool wrote:
// the service app's private key (in either form it is stored), any client
// assertion signed with it, any access token the org issued, or the client
// secret the org generates for a service app a technique creates (which it
// returns in a response body). This is the Dorothy failure mode (a credential
// in plaintext on disk, a generated secret logged) checked against.
func TestOktaCanarySecret(t *testing.T) {
	lab := newOktaLab(t, true)
	var all strings.Builder
	rec := func(r result) { all.WriteString(r.stdout); all.WriteString(r.stderr) }
	rec(lab.mustRun("auth", "okta", "-vv"))
	rec(lab.mustRun("plan", "okta.persistence.service-app-api-access", "--target", "okta", "-vv"))
	rec(lab.mustRun("apply", "okta.persistence.service-app-api-access", "--target", "okta", "--yes", "-vv"))
	rec(lab.mustRun("apply", "okta.persistence.mfa-factor-register", "--target", "okta", "--yes", "-vv"))
	rec(lab.mustRun("status", "-vv"))
	rec(lab.mustRun("sweep", "--target", "okta", "-vv"))

	needles := oktaCredentials(t, lab.srv)
	if len(needles) < 10 {
		t.Fatalf("only %d credentials to look for; the canary is not exercising the token flow", len(needles))
	}
	output := all.String()
	for _, n := range needles {
		if strings.Contains(output, n) {
			t.Fatalf("a credential leaked into output (%.12q...):\n%s", n, output)
		}
	}
	for _, path := range []string{"/api/v1/", "/oauth2/v1/token", "/oauth2/v1/introspect"} {
		if !strings.Contains(output, path) {
			t.Fatalf("verbose output did not trace %s", path)
		}
	}

	files := 0
	err := filepath.WalkDir(lab.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(b, []byte(n)) {
				t.Fatalf("a credential leaked into %s (%.12q...)", p, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 6 {
		t.Fatalf("only %d files written; the canary is not exercising the run directories", files)
	}
	tp, _ := os.ReadFile(filepath.Join(lab.dir, "targets.yaml"))
	if !strings.Contains(string(tp), "env: "+oktaKeyEnv) {
		t.Fatalf("targets.yaml must hold the reference, not the key:\n%s", tp)
	}
}

// oktaCredentials is every secret a session against srv handled: each line of
// the private key's PEM form and each member of its JWK form long enough to
// be key material, every client assertion and access token the org saw, and
// the markers the mock puts in the client secrets it generates.
func oktaCredentials(t *testing.T, srv *mockokta.Server) []string {
	t.Helper()
	out := []string{"do-not-log", "sECReT", "BEGIN PRIVATE KEY"}
	k := mockokta.DefaultKey()
	for _, f := range strings.FieldsFunc(k.PEM()+k.JWK(), func(r rune) bool { return r == '\n' || r == '"' }) {
		if len(f) >= 32 && !strings.HasPrefix(f, "-----") {
			out = append(out, f)
		}
	}
	creds := srv.Credentials()
	if len(creds) == 0 {
		t.Fatal("the org saw no credentials")
	}
	return append(out, creds...)
}

// TestOktaAuthReportsOAuthState proves `auth`, the first command an operator
// runs, shows how it authenticated (the service app, private_key_jwt, the
// per-session token) and which of the scopes the corpus needs the app lacks,
// without failing on them: an operator may withhold scopes for techniques
// they never run.
func TestOktaAuthReportsOAuthState(t *testing.T) {
	lab := newOktaLab(t, true)
	r := lab.mustRun("auth", "okta")
	for _, want := range []string{
		"principal   " + lab.srv.ClientID(),
		"credential  OAuth 2.0 service app, private_key_jwt (RS256, key " + mockokta.DefaultKeyID + "); a per-session access token valid 1h",
		"roles       SUPER_ADMIN",
		"needed by the okta corpus\n",
		"marker ok",
		"telemetry   audit API reachable",
		"ready",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("auth output lacks %q:\n%s", want, r.stdout)
		}
	}

	lab = newOktaLab(t, true, mockokta.WithoutScopes("okta.idps.manage", "okta.idps.read", "okta.appGrants.manage"))
	r = lab.mustRun("auth", "okta")
	if !strings.Contains(r.stdout, "MISSING okta.appGrants.manage okta.idps.manage\n") || !strings.Contains(r.stdout, "ready") {
		t.Fatalf("auth with withheld scopes:\n%s", r.stdout)
	}
}

// TestOktaRunTokenCarriesOnlyPlanScopes proves an apply's token carries the
// plan's scopes plus the read-only guardrail scopes, and nothing else, even
// though the app is granted far more.
func TestOktaRunTokenCarriesOnlyPlanScopes(t *testing.T) {
	lab := newOktaLab(t, true)
	lab.mustRun("apply", "okta.persistence.mfa-factor-register", "--target", "okta", "--yes", "-q")
	want := []string{"okta.groups.read", "okta.logs.read", "okta.orgs.read", "okta.users.manage", "okta.users.read"}
	tokens := lab.srv.TokenScopes()
	if len(tokens) != 1 {
		t.Fatalf("apply minted %d tokens, want 1: %v", len(tokens), tokens)
	}
	if strings.Join(tokens[0], " ") != strings.Join(want, " ") {
		t.Fatalf("apply's token carries %v, want exactly %v", tokens[0], want)
	}
}

// TestOktaWithheldScope proves an operator can withhold a technique's scope:
// that technique is refused before it touches the org, naming the scope,
// while the others still run and sweep still works.
func TestOktaWithheldScope(t *testing.T) {
	lab := newOktaLab(t, true, mockokta.WithoutScopes("okta.idps.manage"))
	before := lab.srv.Snapshot()
	for _, cmd := range [][]string{
		{"plan", "okta.persistence.idp-create", "--target", "okta"},
		{"apply", "okta.persistence.idp-create", "--target", "okta", "--yes"},
	} {
		r := lab.run(cmd...)
		if r.code != report.ExitRefused || !strings.Contains(r.stderr, "is not granted okta.idps.manage,") {
			t.Fatalf("%s with okta.idps.manage withheld: exit %d\n%s", cmd[0], r.code, r.stderr)
		}
	}
	if after := lab.srv.Snapshot(); string(after) != string(before) {
		t.Fatal("a refused technique changed the org")
	}
	if r := lab.run("apply", "okta.persistence.mfa-factor-register", "--target", "okta", "--yes", "-q"); r.code != report.ExitOK {
		t.Fatalf("a technique whose scopes are granted: exit %d\n%s", r.code, r.stderr)
	}
	// Sweep lists identity providers with okta.idps.read.
	if r := lab.run("sweep", "--target", "okta"); r.code != report.ExitOK || !strings.Contains(r.stdout, "no "+marker.Prefix+"- objects found") {
		t.Fatalf("sweep: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}

	// Without even read access to a kind of object, sweep refuses rather
	// than report the org clean.
	lab = newOktaLab(t, true, mockokta.WithoutScopes("okta.idps.manage", "okta.idps.read"))
	if r := lab.run("sweep", "--target", "okta"); r.code != report.ExitRefused || !strings.Contains(r.stderr, "identity providers (grant okta.idps.read)") {
		t.Fatalf("blind sweep: exit %d\n%s", r.code, r.stderr)
	}
}

// TestOktaListingSweepNeedsReadScopes proves a service app granted the
// techniques' .manage scopes but not the .read scopes a listing sweep asks
// for is refused with advice that works: each kind of object it cannot list
// is named with its .read scope, and it is never told to grant a .manage
// scope it already holds. The same app's sweep --delete, which asks for the
// .manage scopes, still runs.
func TestOktaListingSweepNeedsReadScopes(t *testing.T) {
	manageOnly := mockokta.WithGrantedScopes(
		"okta.orgs.read", "okta.users.read", "okta.groups.read", "okta.logs.read",
		"okta.users.manage", "okta.roles.manage", "okta.apps.manage", "okta.appGrants.manage",
		"okta.idps.manage", "okta.policies.manage", "okta.networkZones.manage")
	lab := newOktaLab(t, true, manageOnly)
	before := lab.srv.Snapshot()
	r := lab.run("sweep", "--target", "okta")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "a listing sweep needs the .read scope of each kind") {
		t.Fatalf("listing sweep without the read scopes: exit %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"policies and their rules (grant okta.policies.read)",
		"apps (grant okta.apps.read)",
		"identity providers (grant okta.idps.read)",
		"network zones (grant okta.networkZones.read)",
		"custom admin roles and resource sets (grant okta.roles.read)",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("listing sweep refusal does not say %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, ".manage") {
		t.Fatalf("listing sweep refusal suggests a .manage scope:\n%s", r.stderr)
	}
	if after := lab.srv.Snapshot(); string(after) != string(before) {
		t.Fatal("a refused sweep changed the org")
	}

	lab = newOktaLab(t, true, manageOnly)
	if r := lab.run("sweep", "--target", "okta", "--delete", "--yes"); r.code != report.ExitOK || !strings.Contains(r.stdout, "no "+marker.Prefix+"- objects found") {
		t.Fatalf("sweep --delete with the .manage scopes: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// TestOktaSweepDeleteNeedsManageScope proves sweep --delete refuses before
// asking for confirmation when it finds an object of a kind the token may
// list but not delete, naming the .manage scope, and that no delete reaches
// the org.
func TestOktaSweepDeleteNeedsManageScope(t *testing.T) {
	lab := newOktaLab(t, true, mockokta.WithoutScopes("okta.idps.manage"))
	name := marker.ObjectName("q8wd3f", "idp")
	lab.srv.State(func(st *mockokta.State) {
		st.IdPs["0oaorphan1"] = &mockokta.IdP{ID: "0oaorphan1", Name: name, Type: "OIDC", Status: "ACTIVE"}
	})
	before := lab.srv.Snapshot()
	for _, args := range [][]string{
		{"sweep", "--target", "okta", "--delete"},
		{"sweep", "--target", "okta", "--delete", "--yes"},
	} {
		r := lab.run(args...)
		if r.code != report.ExitRefused || !strings.Contains(r.stderr, "sweep --delete found identity providers this token may list but not delete; "+
			"grant okta.idps.manage (or run sweep without --delete to list only)") {
			t.Fatalf("%s: exit %d\n%s%s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, "Type the tenant short name") || strings.Contains(r.stderr, "pass --yes to confirm deletion") {
			t.Fatalf("%s reached the confirmation step:\n%s%s", strings.Join(args, " "), r.stdout, r.stderr)
		}
	}
	if after := lab.srv.Snapshot(); string(after) != string(before) {
		t.Fatal("a refused sweep --delete changed the org")
	}
	lab.srv.State(func(st *mockokta.State) {
		if st.IdPs["0oaorphan1"] == nil {
			t.Fatal("the identity provider was deleted")
		}
	})

	// The listing sweep still shows it.
	if r := lab.run("sweep", "--target", "okta"); r.code != report.ExitCleanupUnverified || !strings.Contains(r.stdout, name) {
		t.Fatalf("listing sweep: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

// TestOktaSweepTokenScopes proves sweep asks only for what it does: listing
// alone gets read scopes, one per kind of object a run creates; --delete adds
// the write scopes of the ops that create them, and nothing a modify-only op
// needs.
func TestOktaSweepTokenScopes(t *testing.T) {
	lab := newOktaLab(t, true)
	lab.mustRun("sweep", "--target", "okta")
	reads := []string{"okta.apps.read", "okta.groups.read", "okta.idps.read", "okta.networkZones.read",
		"okta.orgs.read", "okta.policies.read", "okta.roles.read", "okta.users.read"}
	tokens := lab.srv.TokenScopes()
	if len(tokens) != 1 || strings.Join(tokens[0], " ") != strings.Join(reads, " ") {
		t.Fatalf("a listing sweep's token carries %v, want exactly %v", tokens, reads)
	}

	lab = newOktaLab(t, true)
	lab.mustRun("sweep", "--target", "okta", "--delete", "--yes")
	tokens = lab.srv.TokenScopes()
	want := []string{"okta.apps.manage", "okta.groups.read", "okta.idps.manage", "okta.networkZones.manage",
		"okta.orgs.read", "okta.policies.manage", "okta.roles.manage", "okta.users.manage", "okta.users.read"}
	if len(tokens) != 1 || strings.Join(tokens[0], " ") != strings.Join(want, " ") {
		t.Fatalf("a deleting sweep's token carries %v, want exactly %v", tokens, want)
	}
}
