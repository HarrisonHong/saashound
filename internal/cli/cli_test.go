package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/cli"
	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/providers/fake"
	"github.com/HarrisonHong/saashound/providers/github"
	"github.com/HarrisonHong/saashound/providers/okta"
)

var update = flag.Bool("update", false, "rewrite golden files")

// sandbox is an isolated config and state directory with a CLI env.
type sandbox struct {
	t       *testing.T
	dir     string
	env     map[string]string
	reg     *provider.Registry
	store   *outageStore
	clk     clock.Clock
	runIDs  []string
	hook    func(engine.Point, string)
	stdin   string
	tty     bool
	version string
	signals chan os.Signal
}

// outageStore lets a test take the simulated platform down.
type outageStore struct {
	*fake.MemoryStore
	down bool
}

func (o *outageStore) Update(id string, fn func(*fake.State) error) error {
	if o.down {
		return errors.New("503 service unavailable")
	}
	return o.MemoryStore.Update(id, fn)
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	dir := t.TempDir()
	store := &outageStore{MemoryStore: fake.NewMemoryStore()}
	reg := provider.NewRegistry()
	if err := reg.Register(fake.New(fake.WithStore(store))); err != nil {
		t.Fatal(err)
	}
	// Register okta and github too so the full embedded corpus (which includes
	// their techniques) validates; these fake-backed tests never open an okta
	// or github target.
	if err := reg.Register(okta.New()); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(github.New()); err != nil {
		t.Fatal(err)
	}
	return &sandbox{
		t: t, dir: dir, reg: reg, store: store,
		clk:     clock.NewFake(time.Date(2026, 11, 14, 15, 2, 11, 0, time.UTC)),
		env:     map[string]string{},
		version: "0.0.0-test",
	}
}

type result struct {
	stdout, stderr string
	code           int
}

func (s *sandbox) run(args ...string) result {
	s.t.Helper()
	var out, errb bytes.Buffer
	zero := engine.Retry{Attempts: 1, GoneAttempts: 1}
	env := cli.Env{
		Stdin: strings.NewReader(s.stdin), Stdout: &out, Stderr: &errb,
		Getenv:    func(k string) string { return s.env[k] },
		StdoutTTY: s.tty, StdinTTY: s.tty, StderrTTY: s.tty,
		Registry: s.reg, Clock: s.clk, Retry: &zero, Hook: s.hook, Version: s.version,
	}
	if s.signals != nil {
		env.Signals = s.signals
	}
	if len(s.runIDs) > 0 {
		ids := s.runIDs
		env.NewRunID = func() (string, error) {
			if len(ids) == 0 {
				return "", errors.New("test ran out of run ids")
			}
			id := ids[0]
			ids = ids[1:]
			return id, nil
		}
	}
	full := append([]string{"--targets", filepath.Join(s.dir, "config", "targets.yaml"), "--state-dir", filepath.Join(s.dir, "state")}, args...)
	code := cli.Main(context.Background(), full, env)
	return result{stdout: out.String(), stderr: errb.String(), code: code}
}

func (s *sandbox) mustRun(args ...string) result {
	s.t.Helper()
	r := s.run(args...)
	if r.code != 0 {
		s.t.Fatalf("saashound %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

func (s *sandbox) initLab(extra ...string) {
	s.t.Helper()
	s.mustRun(append([]string{"init", "lab", "--platform", "fake", "--test-domain", "lab.example.com", "--place-marker"}, extra...)...)
}

func records(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("stdout is not JSON lines: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestGuardrailExitCodes(t *testing.T) {
	s := newSandbox(t)
	tech := "fake.persistence.mfa-factor-register"

	r := s.run("apply", tech, "--target", "lab", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "not allowlisted") {
		t.Fatalf("non-allowlisted target: exit %d %s", r.code, r.stderr)
	}

	s.mustRun("init", "lab", "--platform", "fake")
	r = s.run("apply", tech, "--target", "lab", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "no ownership marker") {
		t.Fatalf("marker missing: exit %d %s", r.code, r.stderr)
	}
	if r.stdout != "" {
		t.Fatalf("a refusal must not print records: %q", r.stdout)
	}
	r = s.run("plan", tech, "--target", "lab")
	if r.code != report.ExitRefused || !strings.Contains(r.stdout, "MARKER MISSING") {
		t.Fatalf("plan with a missing marker: exit %d\n%s", r.code, r.stdout)
	}

	s.mustRun("init", "lab", "--platform", "fake", "--place-marker")
	r = s.run("apply", tech, "--target", "lab")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "--yes") {
		t.Fatalf("non-interactive without --yes: exit %d %s", r.code, r.stderr)
	}
	r = s.run("apply", tech, "--target", "lab", "--yes", "--production", "--ticket", "CHG-1")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "labelled lab") {
		t.Fatalf("--production on a lab: exit %d %s", r.code, r.stderr)
	}
	r = s.run("apply", "fake.persistence.nope", "--target", "lab", "--yes")
	if r.code != report.ExitRefused {
		t.Fatalf("unknown technique: exit %d", r.code)
	}
	r = s.run("apply", tech, "--target", "lab", "--bogus-flag")
	if r.code != report.ExitRefused {
		t.Fatalf("bad flag: exit %d", r.code)
	}

	// The credential belongs to a different principal than declared.
	tp := filepath.Join(s.dir, "config", "targets.yaml")
	b, _ := os.ReadFile(tp)
	if err := os.WriteFile(tp, bytes.Replace(b, []byte("principal: saashound-operator"), []byte("principal: someone-else"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	r = s.run("apply", tech, "--target", "lab", "--yes")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "principal") {
		t.Fatalf("principal mismatch: exit %d %s", r.code, r.stderr)
	}
}

func TestTypedConfirmation(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.tty = true
	s.stdin = "sim-prod\n"
	r := s.run("apply", "fake.persistence.mfa-factor-register", "--target", "lab")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, `Type the tenant short name "sim-lab"`) {
		t.Fatalf("wrong name: exit %d %s", r.code, r.stderr)
	}
	s.stdin = "sim-lab\n"
	r = s.run("apply", "fake.persistence.mfa-factor-register", "--target", "lab")
	if r.code != 0 || !strings.Contains(r.stdout, "TECHNIQUE") || !strings.Contains(r.stdout, "verified") {
		t.Fatalf("confirmed run on a TTY: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -run Golden -update)", err)
	}
	if got != string(want) {
		t.Fatalf("%s differs from the golden file; if the change is intended run with -update and document it in docs/result-schema.md\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestGoldenPass pins the exact JSON-lines record for a passing run of
// every embedded technique.
func TestGoldenPass(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.runIDs = []string{"k3v9q2", "p7m2xw", "x4b8nd"}
	r := s.run("apply", "fake.persistence.mfa-factor-register", "fake.privilege-escalation.admin-role-assign",
		"fake.defense-impairment.network-zone-deactivate", "--target", "lab", "--yes", "-q")
	if r.code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if r.stderr != "" {
		t.Fatalf("-q must silence progress, got %q", r.stderr)
	}
	golden(t, "apply-pass.jsonl", r.stdout)
}

// TestGoldenFailures pins the failing shapes: telemetry missing (exit 1),
// then cleanup unverified (exit 3) with the following technique skipped.
func TestGoldenFailures(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	tp := filepath.Join(s.dir, "config", "targets.yaml")
	b, _ := os.ReadFile(tp)
	withDrop := strings.Replace(string(b), "    test_domain: lab.example.com\n", "    test_domain: lab.example.com\n    options:\n      audit_drop: user.mfa.factor.activate\n", 1)
	if err := os.WriteFile(tp, []byte(withDrop), 0o600); err != nil {
		t.Fatal(err)
	}
	s.runIDs = []string{"m9nq4z"}
	r := s.run("apply", "fake.persistence.mfa-factor-register", "--target", "lab", "--yes", "-q")
	if r.code != report.ExitExpectationFailed {
		t.Fatalf("telemetry missing: exit %d\n%s", r.code, r.stdout)
	}
	out := r.stdout

	if err := os.WriteFile(tp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.runIDs = []string{"r5tw8c", "h2jk6e"}
	s.hook = func(p engine.Point, step string) {
		if p == engine.AfterResult && step == "grant" {
			s.store.down = true
		}
	}
	r = s.run("apply", "fake.privilege-escalation.admin-role-assign", "fake.persistence.mfa-factor-register", "--target", "lab", "--yes", "-q")
	if r.code != report.ExitCleanupUnverified {
		t.Fatalf("cleanup unverified: exit %d\n%s", r.code, r.stdout)
	}
	out += r.stdout
	golden(t, "apply-failures.jsonl", out)

	recs := records(t, r.stdout)
	if recs[0]["verdict"] != "cleanup-unverified" || recs[1]["verdict"] != "skipped" {
		t.Fatalf("verdicts %v, %v", recs[0]["verdict"], recs[1]["verdict"])
	}

	// Recovery: the platform is back; cleanup replays the journal.
	s.store.down = false
	s.hook = nil
	st := s.mustRun("status")
	if !strings.Contains(st.stdout, "r5tw8c") || !strings.Contains(st.stdout, "cleanup-unverified") {
		t.Fatalf("status:\n%s", st.stdout)
	}
	c := s.mustRun("cleanup", "r5tw8c")
	if !strings.Contains(c.stdout, "cleanup verified for run r5tw8c (2 objects)") {
		t.Fatalf("cleanup: %s %s", c.stdout, c.stderr)
	}
	sw := s.mustRun("sweep", "--target", "lab")
	if !strings.Contains(sw.stdout, "no saashound- objects found") {
		t.Fatalf("sweep: %s", sw.stdout)
	}
}

// TestGoldenDegraded pins the records of passing runs on a platform whose
// audit log does not keep the User-Agent whole: dropped for the first run,
// truncated for the second. Their events are matched by the run's object
// names inside the run window, and each expectation says so.
func TestGoldenDegraded(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	tp := filepath.Join(s.dir, "config", "targets.yaml")
	b, _ := os.ReadFile(tp)
	var out string
	for _, c := range []struct{ run, technique, recording string }{
		{"q8vz3k", "fake.persistence.mfa-factor-register", "dropped"},
		{"w2hn5c", "fake.privilege-escalation.admin-role-assign", "truncated"},
	} {
		with := strings.Replace(string(b), "    test_domain: lab.example.com\n", "    test_domain: lab.example.com\n    options:\n      audit_user_agent: "+c.recording+"\n", 1)
		if err := os.WriteFile(tp, []byte(with), 0o600); err != nil {
			t.Fatal(err)
		}
		s.runIDs = []string{c.run}
		r := s.run("apply", c.technique, "--target", "lab", "--yes", "-q")
		if r.code != report.ExitOK {
			t.Fatalf("%s with the User-Agent %s: exit %d\n%s", c.technique, c.recording, r.code, r.stdout)
		}
		out += r.stdout
	}
	golden(t, "apply-degraded.jsonl", out)
}

// TestResultSchemaIsDocumented requires every key of the result record to
// appear in docs/result-schema.md.
func TestResultSchemaIsDocumented(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "result-schema.md"))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, name := range []string{"apply-pass.jsonl", "apply-failures.jsonl", "apply-degraded.jsonl"} {
		b, err := os.ReadFile(filepath.Join("testdata", "golden", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range records(t, string(b)) {
			collectKeys("", rec, keys)
			if rec["schema"] != report.Schema || rec["version"] != float64(report.Version) {
				t.Fatalf("schema/version = %v/%v", rec["schema"], rec["version"])
			}
		}
	}
	var missing []string
	for k := range keys {
		if !strings.Contains(string(doc), "`"+k+"`") {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("docs/result-schema.md does not document: %v", missing)
	}
}

func collectKeys(prefix string, v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if prefix == "telemetry.expectations[].match" {
				continue // keys are the technique's field paths
			}
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out[p] = true
			collectKeys(p, child, out)
		}
	case []any:
		for _, child := range x {
			collectKeys(prefix+"[]", child, out)
		}
	}
}

func TestSavedPlan(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.runIDs = []string{"q8wd3f"}
	pp := filepath.Join(s.dir, "plan.json")
	s.mustRun("plan", "fake.persistence.mfa-factor-register", "--target", "lab", "-o", pp)
	b, err := os.ReadFile(pp)
	if err != nil {
		t.Fatal(err)
	}
	for _, tamper := range []struct{ old, new string }{
		{`"op": "fake.factor.enroll"`, `"op": "fake.role.assign"`},
		{`"name": "saashound-q8wd3f-victim"`, `"name": "admin"`},
		{`"run": "q8wd3f"`, `"run": "../../x"`},
	} {
		if !bytes.Contains(b, []byte(tamper.old)) {
			t.Fatalf("plan lacks %s", tamper.old)
		}
		if err := os.WriteFile(pp, bytes.Replace(b, []byte(tamper.old), []byte(tamper.new), 1), 0o600); err != nil {
			t.Fatal(err)
		}
		if r := s.run("apply", "--plan", pp, "--target", "lab", "--yes"); r.code != report.ExitRefused {
			t.Fatalf("tampered plan (%s) accepted: exit %d %s", tamper.new, r.code, r.stderr)
		}
	}
	if err := os.WriteFile(pp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// The plan records its target, so --target may be omitted; a
	// different --target is still refused.
	if r := s.run("apply", "--plan", pp, "--target", "other", "--yes"); r.code != report.ExitRefused {
		t.Fatalf("plan applied to another target: exit %d %s", r.code, r.stderr)
	}
	r := s.mustRun("apply", "--plan", pp, "--yes")
	if recs := records(t, r.stdout); recs[0]["run"] != "q8wd3f" || recs[0]["verdict"] != "pass" {
		t.Fatalf("saved plan run: %v", recs[0])
	}
}

func TestCommands(t *testing.T) {
	s := newSandbox(t)
	if r := s.mustRun("version"); !strings.Contains(r.stdout, "result schema saashound.result/v2") {
		t.Fatal(r.stdout)
	}
	r := s.mustRun("list")
	for _, id := range []string{"fake.persistence.mfa-factor-register", "fake.privilege-escalation.admin-role-assign", "fake.defense-impairment.network-zone-deactivate"} {
		if !strings.Contains(r.stdout, id) {
			t.Fatalf("list lacks %s:\n%s", id, r.stdout)
		}
	}
	r = s.mustRun("show", "fake.defense-impairment.network-zone-deactivate")
	if !strings.Contains(r.stdout, "restore the recorded zone status") || !strings.Contains(r.stdout, "cleanup     deactivate -> zone") {
		t.Fatalf("show:\n%s", r.stdout)
	}
	s.mustRun("validate")
	bad := filepath.Join(s.dir, "bad.yaml")
	_ = os.WriteFile(bad, []byte("id: fake.persistence.x\nname: x\nhost: evil.example.com\n"), 0o600)
	if r := s.run("validate", bad); r.code != report.ExitRefused || !strings.Contains(r.stderr, "host") {
		t.Fatalf("validate bad: exit %d %s", r.code, r.stderr)
	}
	if r := s.run("cleanup", "../../etc"); r.code != report.ExitRefused {
		t.Fatalf("cleanup with a path: exit %d", r.code)
	}
	s.initLab()
	r = s.mustRun("auth", "lab")
	if !strings.Contains(r.stdout, "ready") || !strings.Contains(r.stdout, "marker ok") {
		t.Fatalf("auth:\n%s", r.stdout)
	}
	r = s.mustRun("plan", "fake.persistence.mfa-factor-register", "--target", "lab", "--offline")
	if !strings.Contains(r.stdout, "not checked (--offline)") {
		t.Fatalf("plan --offline:\n%s", r.stdout)
	}
	if r := s.mustRun("status"); !strings.Contains(r.stdout, "no runs") {
		t.Fatalf("status: %s", r.stdout)
	}
	if r := s.mustRun("cleanup", "--all"); !strings.Contains(r.stdout, "no runs with pending cleanup") {
		t.Fatalf("cleanup --all: %s", r.stdout)
	}
}

func TestCorpusDirIsUnverified(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	dir := filepath.Join(s.dir, "extra")
	_ = os.MkdirAll(dir, 0o700)
	src, err := os.ReadFile(filepath.Join("..", "..", "techniques", "fake", "persistence.mfa-factor-register.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	custom := strings.Replace(string(src), "id: fake.persistence.mfa-factor-register", "id: fake.persistence.mfa-factor-register-custom", 1)
	_ = os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(custom), 0o600)
	r := s.mustRun("--corpus-dir", dir, "apply", "fake.persistence.mfa-factor-register-custom", "--target", "lab", "--yes")
	if recs := records(t, r.stdout); recs[0]["corpus"] != "unverified" || recs[0]["verdict"] != "pass" {
		t.Fatalf("custom technique record: %v", recs[0])
	}
}

// TestCanarySecret seeds a recognisable credential, drives every command
// with maximum verbosity, and fails if the credential appears in any output
// or any file the tool wrote.
func TestCanarySecret(t *testing.T) {
	const canary = "CANARY-tok-9f8e7d6c5b4a3"
	s := newSandbox(t)
	s.env["SAASHOUND_TEST_TOKEN"] = canary
	s.initLab("--credential-env", "SAASHOUND_TEST_TOKEN")
	var all strings.Builder
	record := func(r result) { all.WriteString(r.stdout); all.WriteString(r.stderr) }
	record(s.mustRun("auth", "lab", "-vv"))
	record(s.mustRun("plan", "fake.persistence.mfa-factor-register", "--target", "lab", "-vv", "-o", filepath.Join(s.dir, "plan.json")))
	record(s.mustRun("apply", "fake.persistence.mfa-factor-register", "fake.privilege-escalation.admin-role-assign", "--target", "lab", "--yes", "-vv"))
	s.hook = func(p engine.Point, step string) {
		if p == engine.AfterResult && step == "zone" {
			s.store.down = true
		}
	}
	record(s.run("apply", "fake.defense-impairment.network-zone-deactivate", "--target", "lab", "--yes", "-vv"))
	s.store.down, s.hook = false, nil
	record(s.run("status", "-vv"))
	record(s.run("cleanup", "--all", "-vv"))
	record(s.run("sweep", "--target", "lab", "-vv"))
	// A wrong token is rejected without echoing it.
	s.env["SAASHOUND_TEST_TOKEN"] = canary + "-wrong"
	record(s.run("auth", "lab", "-vv"))
	s.env["SAASHOUND_TEST_TOKEN"] = canary

	if strings.Contains(all.String(), canary) {
		t.Fatalf("the credential leaked into CLI output:\n%s", all.String())
	}
	if !strings.Contains(all.String(), "401") {
		t.Fatal("the wrong-token check did not run")
	}
	files := 0
	err := filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(canary)) {
			return fmt.Errorf("the credential leaked into %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 8 {
		t.Fatalf("only %d files written; the canary test is not exercising the run directories", files)
	}
	tp, _ := os.ReadFile(filepath.Join(s.dir, "config", "targets.yaml"))
	if !strings.Contains(string(tp), "env: SAASHOUND_TEST_TOKEN") {
		t.Fatalf("targets.yaml must hold the reference:\n%s", tp)
	}
}

// pendingRun applies a technique while the platform goes down mid-run, so
// its cleanup is left unverified, then brings the platform back.
func (s *sandbox) pendingRun(run, tgt string) {
	s.t.Helper()
	s.runIDs = []string{run}
	s.hook = func(p engine.Point, step string) {
		if p == engine.AfterResult && step == "factor" {
			s.store.down = true
		}
	}
	if r := s.run("apply", "fake.persistence.mfa-factor-register", "--target", tgt, "--yes", "-q"); r.code != report.ExitCleanupUnverified {
		s.t.Fatalf("apply for a pending run: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	s.store.down, s.hook, s.runIDs = false, nil, nil
}

// TestApplyReportsEarlierRecordsWhenALaterRunCannotStart: a run that cannot
// be started stops the apply (exit 2), but the techniques that already ran
// are still reported, on a terminal too.
func TestApplyReportsEarlierRecordsWhenALaterRunCannotStart(t *testing.T) {
	for _, tty := range []bool{false, true} {
		s := newSandbox(t)
		s.initLab()
		s.tty = tty
		// The same run id twice: the second run directory cannot be created.
		s.runIDs = []string{"q8wd3f", "q8wd3f"}
		r := s.run("apply", "fake.persistence.mfa-factor-register", "fake.privilege-escalation.admin-role-assign", "--target", "lab", "--yes", "-q")
		if r.code != report.ExitRefused {
			t.Fatalf("tty=%v: exit %d, want %d\n%s", tty, r.code, report.ExitRefused, r.stderr)
		}
		if !strings.Contains(r.stderr, "fake.privilege-escalation.admin-role-assign (run q8wd3f) was not started") || !strings.Contains(r.stderr, "already exists") {
			t.Fatalf("tty=%v: stderr does not name the run that could not start:\n%s", tty, r.stderr)
		}
		if !strings.Contains(r.stdout, "fake.persistence.mfa-factor-register") || !strings.Contains(r.stdout, "pass") {
			t.Fatalf("tty=%v: the technique that already ran was not reported:\n%s", tty, r.stdout)
		}
		if strings.Contains(r.stdout, "admin-role-assign") {
			t.Fatalf("tty=%v: a record was written for a run that never started:\n%s", tty, r.stdout)
		}
		if !tty {
			if recs := records(t, r.stdout); len(recs) != 1 || recs[0]["verdict"] != "pass" {
				t.Fatalf("records %v", recs)
			}
		}
	}
}

func TestSavedPlanRejectsDuplicateRunIDs(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.runIDs = []string{"q8wd3f", "q8wd3f"}
	pp := filepath.Join(s.dir, "plan.json")
	s.mustRun("plan", "fake.persistence.mfa-factor-register", "fake.privilege-escalation.admin-role-assign", "--target", "lab", "-o", pp)
	r := s.run("apply", "--plan", pp, "--target", "lab", "--yes", "-q")
	if r.code != report.ExitRefused || !strings.Contains(r.stderr, "lists run q8wd3f more than once") {
		t.Fatalf("duplicate run ids: exit %d %s", r.code, r.stderr)
	}
	if st := s.mustRun("status"); !strings.Contains(st.stdout, "no runs") {
		t.Fatalf("a refused plan must not start anything:\n%s", st.stdout)
	}
}

// TestCleanupContinuesPastARefusedRun: one run that cannot be cleaned up
// must not stop the ones after it.
func TestCleanupContinuesPastARefusedRun(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	tp := filepath.Join(s.dir, "config", "targets.yaml")
	labOnly, err := os.ReadFile(tp)
	if err != nil {
		t.Fatal(err)
	}
	s.mustRun("init", "old", "--platform", "fake", "--test-domain", "lab.example.com", "--place-marker")
	s.pendingRun("aaaaa2", "old")
	s.pendingRun("bbbbb2", "lab")
	// The first run's target is no longer declared.
	if err := os.WriteFile(tp, labOnly, 0o600); err != nil {
		t.Fatal(err)
	}

	r := s.run("cleanup", "--all")
	if r.code != report.ExitRefused {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, report.ExitRefused, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "saashound: run aaaaa2: ") || !strings.Contains(r.stderr, "old") {
		t.Fatalf("the refusal must name its run:\n%s", r.stderr)
	}
	if !strings.Contains(r.stdout, "cleanup verified for run bbbbb2 (2 objects)") {
		t.Fatalf("the run after the refused one was not cleaned up:\nstdout: %s\nstderr: %s", r.stdout, r.stderr)
	}
	st := s.mustRun("status")
	for _, line := range strings.Split(st.stdout, "\n") {
		if strings.Contains(line, "aaaaa2") && !strings.Contains(line, "cleanup-unverified") {
			t.Fatalf("the refused run must stay pending: %s", line)
		}
		if strings.Contains(line, "bbbbb2") && strings.Contains(line, "cleanup-unverified") {
			t.Fatalf("the cleaned run is still pending: %s", line)
		}
	}

	// Named runs behave the same, in the order given, and an unverified
	// cleanup outranks a refusal.
	s.pendingRun("ccccc2", "lab")
	s.store.down = true
	r = s.run("cleanup", "zzzzz9", "ccccc2")
	s.store.down = false
	if r.code != report.ExitCleanupUnverified || !strings.Contains(r.stderr, "saashound: run zzzzz9: ") || !strings.Contains(r.stdout, "cleanup NOT verified for run ccccc2") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if r := s.run("cleanup", "ccccc2", "zzzzz9"); r.code != report.ExitRefused || !strings.Contains(r.stdout, "cleanup verified for run ccccc2") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

// TestCleanupFirstInterruptMessage: in `cleanup` the first Ctrl-C stops
// nothing, and must say so.
func TestCleanupFirstInterruptMessage(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.pendingRun("aaaaa2", "lab")
	s.signals = make(chan os.Signal)
	sent := false
	s.hook = func(p engine.Point, _ string) {
		if p == engine.AfterUndo && !sent {
			sent = true
			s.signals <- os.Interrupt
		}
	}
	r := s.run("cleanup", "aaaaa2")
	if !sent {
		t.Fatal("the interrupt was never sent")
	}
	if r.code != report.ExitOK || !strings.Contains(r.stdout, "cleanup verified for run aaaaa2") {
		t.Fatalf("one Ctrl-C must not stop cleanup: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "cleanup of run aaaaa2 continues") || !strings.Contains(r.stderr, "Ctrl-C again to abandon") {
		t.Fatalf("first Ctrl-C message:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "detonation") {
		t.Fatalf("cleanup does not detonate anything:\n%s", r.stderr)
	}
}

// TestAbandonedCleanupStopsTheRemainingRuns: giving up on one run's cleanup
// gives up on the command. The runs after it are not started.
func TestAbandonedCleanupStopsTheRemainingRuns(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	s.pendingRun("aaaaa2", "lab")
	s.pendingRun("bbbbb2", "lab")
	jp := filepath.Join(s.dir, "state", "runs", "bbbbb2", "journal.jsonl")
	before, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}

	s.signals = make(chan os.Signal)
	sent := false
	s.hook = func(p engine.Point, _ string) {
		if p == engine.AfterUndo && !sent {
			sent = true
			// Two interrupts abandon; the third only returns once the
			// second has been acted on.
			for i := 0; i < 3; i++ {
				s.signals <- os.Interrupt
			}
		}
	}
	r := s.run("cleanup", "aaaaa2", "bbbbb2")
	s.hook, s.signals = nil, nil
	if !sent {
		t.Fatal("the interrupts were never sent")
	}
	if r.code != report.ExitCleanupUnverified {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, report.ExitCleanupUnverified, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "cleanup NOT verified for run aaaaa2") {
		t.Fatalf("the abandoned run was not reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "cleanup not attempted for run bbbbb2") || !strings.Contains(r.stdout, "saashound cleanup bbbbb2") {
		t.Fatalf("the remaining run must be named as not attempted, with its retry command:\n%s", r.stdout)
	}
	if strings.Contains(r.stderr, "[bbbbb2]") {
		t.Fatalf("cleanup of the remaining run was started:\n%s", r.stderr)
	}
	after, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the journal of a run that was not attempted changed:\n%s", after)
	}
	sw := s.run("sweep", "--target", "lab")
	if sw.code != report.ExitCleanupUnverified || !strings.Contains(sw.stdout, "saashound-bbbbb2-") {
		t.Fatalf("the remaining run's objects must still be there: exit %d\n%s", sw.code, sw.stdout)
	}

	// Nothing was lost: both runs are still recoverable.
	r = s.mustRun("cleanup", "--all")
	if !strings.Contains(r.stdout, "cleanup verified for run aaaaa2") || !strings.Contains(r.stdout, "cleanup verified for run bbbbb2") {
		t.Fatalf("recovery after an abandoned cleanup:\n%s\n%s", r.stdout, r.stderr)
	}
}
