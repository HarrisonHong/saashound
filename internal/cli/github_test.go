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
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/providers/github"
	"github.com/HarrisonHong/saashound/providers/github/mockgithub"
)

const (
	ghToken     = "ghp-github-test-token"
	ghPrincipal = "github-bot"
	ghOrg       = "acme-labs"
	ghSecond    = "octo-second"
)

// githubLab is a mock GitHub org wired into the CLI through a targets.yaml that
// points at it, exactly as a real org would be.
type githubLab struct {
	t   *testing.T
	dir string
	srv *mockgithub.Server
	clk *clock.Fake
}

func newGithubLab(t *testing.T, place bool) *githubLab {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(time.Date(2026, 11, 14, 15, 2, 11, 0, time.UTC))
	srv := mockgithub.New(mockgithub.WithToken(ghToken), mockgithub.WithPrincipal(ghPrincipal),
		mockgithub.WithOrg(ghOrg), mockgithub.WithMember(ghSecond), mockgithub.WithClock(clk.Now))
	t.Cleanup(srv.Close)
	lab := &githubLab{t: t, dir: dir, srv: srv, clk: clk}
	lab.writeTargets()
	if place {
		lab.placeMarker()
	}
	return lab
}

// tgt builds the target entry, matching what the CLI will load.
func (l *githubLab) tgt() *target.Target {
	return &target.Target{
		Name: "github", Platform: github.Name, Tenant: ghOrg, Principal: ghPrincipal, Environment: "lab",
		TestDomain: "lab.example.com", Credential: secret.Ref{Env: "GITHUB_TOKEN"},
		Options: map[string]string{"api_url": l.srv.URL(), "second_account": ghSecond},
	}
}

// writeTargets writes targets.yaml with the mock's API URL and second account,
// the way an operator declares a GitHub org (init plus the two options).
func (l *githubLab) writeTargets() {
	l.t.Helper()
	f := &target.File{Version: target.FileVersion, Targets: map[string]*target.Target{}}
	if err := f.Add(l.tgt()); err != nil {
		l.t.Fatal(err)
	}
	if err := f.Save(filepath.Join(l.dir, "targets.yaml")); err != nil {
		l.t.Fatal(err)
	}
}

// placeMarker plays the tenant admin creating the ownership-marker repo.
func (l *githubLab) placeMarker() {
	l.srv.PlaceMarker(github.MarkerRepo, github.MarkerFile, l.tgt().MarkerValue())
}

func (l *githubLab) run(args ...string) result {
	l.t.Helper()
	var out, errb bytes.Buffer
	zero := engine.Retry{Attempts: 1, GoneAttempts: 1}
	env := cli.Env{
		Stdin:  strings.NewReader(""),
		Stdout: &out,
		Stderr: &errb,
		Getenv: func(k string) string {
			if k == "GITHUB_TOKEN" {
				return ghToken
			}
			return ""
		},
		Registry: provider.Default,
		Clock:    l.clk,
		Retry:    &zero,
		Version:  "0.0.0-test",
	}
	full := append([]string{"--targets", filepath.Join(l.dir, "targets.yaml"), "--state-dir", filepath.Join(l.dir, "state")}, args...)
	code := cli.Main(context.Background(), full, env)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

// githubTechniques is every technique the github provider ships.
var githubTechniques = []string{
	"github.persistence.deploy-key-add",
	"github.persistence.outside-collaborator-add",
	"github.persistence.repo-webhook-create",
	"github.privilege-escalation.org-owner-promote",
	"github.defense-impairment.secret-scanning-disable",
	"github.defense-impairment.branch-protection-remove",
	"github.exfiltration.repo-visibility-public",
}

// TestGithubTechniqueConformance runs every github technique through the whole
// loop against the mock org: guardrail, detonate, journalled cleanup proven
// verified, audit log collected, expectations matched, and the org left
// byte-identical to how it started.
func TestGithubTechniqueConformance(t *testing.T) {
	for _, id := range githubTechniques {
		t.Run(id, func(t *testing.T) {
			lab := newGithubLab(t, true)
			before := lab.srv.Snapshot()
			r := lab.run("apply", id, "--target", "github", "--yes", "-q")
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
			if rec["platform"] != "github" || rec["corpus"] != "verified" {
				t.Fatalf("record %v", rec)
			}
			if rec["schema"] != report.Schema || rec["version"] != float64(report.Version) {
				t.Fatalf("schema/version = %v/%v", rec["schema"], rec["version"])
			}
			// No shipped github technique references a Sigma rule, so the
			// detection checker apply always runs adds no entry.
			if dets := detections(t, rec); len(dets) != 0 {
				t.Fatalf("detections %v", dets)
			}
			cleanup := rec["cleanup"].(map[string]any)
			if cleanup["status"] != "verified" {
				t.Fatalf("cleanup %v", cleanup)
			}
			tel := rec["telemetry"].(map[string]any)
			if tel["status"] != "observed" || tel["source"] != "github.audit_log" {
				t.Fatalf("telemetry %v", tel)
			}
			if tel["observed"].(float64) != tel["expected"].(float64) || tel["expected"].(float64) < 1 {
				t.Fatalf("telemetry counts %v", tel)
			}
			if after := lab.srv.Snapshot(); string(after) != string(before) {
				t.Fatalf("org changed:\nbefore %s\nafter  %s", before, after)
			}
			sw := lab.run("sweep", "--target", "github")
			if sw.code != report.ExitOK || !strings.Contains(sw.stdout, "no "+marker.Prefix+"- objects found") {
				t.Fatalf("sweep: exit %d\n%s", sw.code, sw.stdout)
			}
		})
	}
}

// TestGithubSigmaDetection proves the Sigma detection checker evaluates the
// GitHub org audit log: a technique referencing an operator rule keyed on the
// audit event's raw `action` field (the shape SigmaHQ's GitHub audit rules
// use) reports the rule fired with its author, and the run passes.
func TestGithubSigmaDetection(t *testing.T) {
	lab := newGithubLab(t, true)
	corpus := t.TempDir()
	rules := t.TempDir()
	const ruleID = "deadbeef-0000-4000-8000-0000000000a1"
	writeFile(t, filepath.Join(rules, "deploy-key-added.yml"), `
title: GitHub deploy key added (example)
id: `+ruleID+`
author: SaaSHound tests
logsource: {product: github, service: audit}
detection:
  selection:
    action: public_key.create
  condition: selection
`)
	src, err := os.ReadFile(filepath.Join("..", "..", "techniques", "github", "persistence.deploy-key-add.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(src),
		"id: github.persistence.deploy-key-add",
		"id: github.persistence.deploy-key-add-sigma", 1)
	if strings.Contains(body, "detections:") {
		t.Fatal("source technique already has a detections block; update this test")
	}
	writeFile(t, filepath.Join(corpus, "sigma.yaml"), body+"detections:\n  - sigma: "+ruleID+"\n")

	r := lab.run("--corpus-dir", corpus, "apply", "github.persistence.deploy-key-add-sigma",
		"--target", "github", "--yes", "-q", "--sigma-rules", rules)
	if r.code != report.ExitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	rec := records(t, r.stdout)[0]
	if rec["verdict"] != "pass" {
		t.Fatalf("verdict %v (reason %v)", rec["verdict"], rec["reason"])
	}
	dets := detections(t, rec)
	if len(dets) != 1 {
		t.Fatalf("want 1 detection, got %d: %v", len(dets), dets)
	}
	d := dets[0].(map[string]any)
	if d["checker"] != "sigma" || d["id"] != ruleID || d["status"] != "fired" || d["fired"] != true {
		t.Fatalf("detection = %v", d)
	}
	if d["author"] != "SaaSHound tests" {
		t.Errorf("a reported match must carry the rule author, got %v", d["author"])
	}
}

// TestGithubGuardrailRefusals proves the tenant-you-own guarantee against the
// real github provider: a missing marker, a tenant mismatch and a missing
// token each refuse with exit 2 and run nothing.
func TestGithubGuardrailRefusals(t *testing.T) {
	// Marker missing: the admin has not opted the org in.
	lab := newGithubLab(t, false)
	r := lab.run("apply", githubTechniques[0], "--target", "github", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "ownership marker") {
		t.Fatalf("missing marker: exit %d\n%s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a refusal must print no records: %q", r.stdout)
	}

	// Tenant mismatch: targets.yaml declares a different org than the token sees.
	lab.placeMarker()
	tp := filepath.Join(lab.dir, "targets.yaml")
	b, _ := os.ReadFile(tp)
	tampered := bytes.Replace(b, []byte("tenant: "+ghOrg), []byte("tenant: some-other-org"), 1)
	if err := os.WriteFile(tp, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	r = lab.run("apply", githubTechniques[0], "--target", "github", "--yes")
	if r.code != report.ExitRefused {
		t.Fatalf("tenant mismatch: exit %d\n%s", r.code, r.stderr)
	}

	// Missing token: the credential env var is unset.
	if err := os.WriteFile(tp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	env := cli.Env{Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" }, Registry: provider.Default, Clock: lab.clk}
	code := cli.Main(context.Background(), []string{"--targets", tp, "--state-dir", filepath.Join(lab.dir, "state3"), "apply", githubTechniques[0], "--target", "github", "--yes"}, env)
	if code != report.ExitRefused || !strings.Contains(errb.String(), "GITHUB_TOKEN") {
		t.Fatalf("missing token: exit %d\n%s", code, errb.String())
	}
}

func (l *githubLab) mustRun(args ...string) result {
	l.t.Helper()
	r := l.run(args...)
	if r.code != 0 {
		l.t.Fatalf("saashound %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

// TestGithubCanarySecret drives every github command at maximum verbosity and
// fails if the API token appears in any output or any file the tool wrote.
// This is the Dorothy failure mode (token in plaintext on disk, a credential
// logged) checked against.
func TestGithubCanarySecret(t *testing.T) {
	lab := newGithubLab(t, true)
	var all strings.Builder
	rec := func(r result) { all.WriteString(r.stdout); all.WriteString(r.stderr) }
	rec(lab.mustRun("auth", "github", "-vv"))
	rec(lab.mustRun("plan", "github.persistence.deploy-key-add", "--target", "github", "-vv"))
	rec(lab.mustRun("apply", "github.persistence.deploy-key-add", "--target", "github", "--yes", "-vv"))
	rec(lab.mustRun("apply", "github.persistence.repo-webhook-create", "--target", "github", "--yes", "-vv"))
	rec(lab.mustRun("status", "-vv"))
	rec(lab.mustRun("sweep", "--target", "github", "-vv"))

	output := all.String()
	if strings.Contains(output, ghToken) {
		t.Fatalf("the API token leaked into output:\n%s", output)
	}
	if !strings.Contains(output, "/orgs/") && !strings.Contains(output, "/repos/") {
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
		if bytes.Contains(b, []byte(ghToken)) {
			t.Fatalf("the API token leaked into %s", p)
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
	if !strings.Contains(string(tp), "env: GITHUB_TOKEN") {
		t.Fatalf("targets.yaml must hold the reference, not the token:\n%s", tp)
	}
}
