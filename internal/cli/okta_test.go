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

const (
	oktaToken     = "ssws-okta-test-token"
	oktaPrincipal = "okta-bot@example.com"
)

// oktaLab is a mock Okta org wired into the CLI through a targets.yaml that
// points at it, exactly as a real org would be.
type oktaLab struct {
	t     *testing.T
	dir   string
	srv   *mockokta.Server
	clk   *clock.Fake
	runID string
}

func newOktaLab(t *testing.T, place bool) *oktaLab {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(time.Date(2026, 11, 14, 15, 2, 11, 0, time.UTC))
	srv := mockokta.New(mockokta.WithToken(oktaToken), mockokta.WithPrincipal(oktaPrincipal), mockokta.WithClock(clk.Now))
	t.Cleanup(srv.Close)
	lab := &oktaLab{t: t, dir: dir, srv: srv, clk: clk}
	// Declare the target in targets.yaml, as `init` does on a real org.
	lab.mustRun("init", "okta", "--platform", "okta", "--tenant", srv.URL(),
		"--principal", oktaPrincipal, "--test-domain", "lab.example.com", "--credential-env", "OKTA_TOKEN")
	if place {
		lab.placeMarker()
	}
	return lab
}

// placeMarker plays the tenant admin creating the ownership group.
func (l *oktaLab) placeMarker() {
	tgt := &target.Target{Name: "okta", Platform: "okta", Tenant: l.srv.URL(), Principal: oktaPrincipal, Environment: "lab"}
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
			if k == "OKTA_TOKEN" {
				return oktaToken
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
// real provider: a missing marker, a tenant/principal mismatch and a missing
// token each refuse with exit 2 and run nothing.
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

	// Principal mismatch: the token is for a different principal than declared.
	lab.placeMarker()
	tp := filepath.Join(lab.dir, "targets.yaml")
	b, _ := os.ReadFile(tp)
	tampered := bytes.Replace(b, []byte("principal: "+oktaPrincipal), []byte("principal: someone-else@example.com"), 1)
	if err := os.WriteFile(tp, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	r = lab.run("apply", oktaTechniques[0], "--target", "okta", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "principal") {
		t.Fatalf("principal mismatch: exit %d\n%s", r.code, r.stderr)
	}

	// Missing token: the credential env var is unset.
	if err := os.WriteFile(tp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	env := cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }, Registry: provider.Default, Clock: lab.clk}
	code := cli.Main(context.Background(), []string{"--targets", tp, "--state-dir", filepath.Join(lab.dir, "state3"), "apply", oktaTechniques[0], "--target", "okta", "--yes"}, env)
	if code != report.ExitRefused || !strings.Contains(errb.String(), "OKTA_TOKEN") {
		t.Fatalf("missing token: exit %d\n%s", code, errb.String())
	}
}

// TestOktaCanarySecret drives every okta command at maximum verbosity and
// fails if the SSWS token, or the service app's generated client secret (which
// the org returns in a response body), appears in any output or any file the
// tool wrote. This is the Dorothy failure mode (token in plaintext on disk, a
// generated secret logged) checked against.
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

	output := all.String()
	if strings.Contains(output, oktaToken) {
		t.Fatalf("the SSWS token leaked into output:\n%s", output)
	}
	// The mock app's client secret carries a recognisable marker.
	for _, needle := range []string{"do-not-log", "sECReT"} {
		if strings.Contains(output, needle) {
			t.Fatalf("a generated client secret leaked into output (%q)", needle)
		}
	}
	if !strings.Contains(output, "/api/v1/") {
		t.Fatal("verbose output did not include any API path trace")
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
		for _, needle := range []string{oktaToken, "do-not-log", "sECReT"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Fatalf("a secret leaked into %s (%q)", p, needle)
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
	if !strings.Contains(string(tp), "env: OKTA_TOKEN") {
		t.Fatalf("targets.yaml must hold the reference, not the token:\n%s", tp)
	}
}
