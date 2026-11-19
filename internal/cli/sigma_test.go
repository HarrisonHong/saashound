package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/report"
)

// detections returns the record's detections array.
func detections(t *testing.T, rec map[string]any) []any {
	t.Helper()
	d, ok := rec["detections"].([]any)
	if !ok {
		t.Fatalf("record has no detections array: %v", rec["detections"])
	}
	return d
}

// TestSigmaDetectionFires runs the shipped fake technique that references the
// bundled example rule and proves the whole loop: the rule is evaluated on the
// run's own events, reported as fired with its author (DRL-1.1), and the run
// passes with exit 0.
func TestSigmaDetectionFires(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	r := s.run("apply", "fake.privilege-escalation.admin-role-assign", "--target", "lab", "--yes", "-q")
	if r.code != report.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
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
	if d["checker"] != "sigma" || d["fired"] != true || d["status"] != "fired" {
		t.Fatalf("detection = %v", d)
	}
	if d["id"] != "5aa5c0de-face-4d00-8b00-0000feedface" {
		t.Errorf("rule id = %v", d["id"])
	}
	if a, _ := d["author"].(string); a == "" {
		t.Error("a reported match must carry the rule author")
	}
}

// TestSigmaDetectionMissing proves the failure half of the verdict: a rule the
// operator supplies with --sigma-rules that does not fire on the events makes
// the run a detection-missing failure with exit 1.
func TestSigmaDetectionMissing(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	corpus := t.TempDir()
	rules := t.TempDir()
	// A rule that only fires on a FAILED grant; the fake platform logs SUCCESS.
	writeFile(t, filepath.Join(rules, "failed-grant.yml"), `
title: Failed admin grant (example)
id: deadbeef-0000-4000-8000-000000000001
logsource: {product: fake}
detection:
  selection:
    eventType: user.account.privilege.grant
    outcome.result: FAILURE
  condition: selection
`)
	customTechnique(t, corpus, "notfire", "deadbeef-0000-4000-8000-000000000001")

	r := s.run("--corpus-dir", corpus, "apply", "fake.privilege-escalation.admin-role-assign-notfire",
		"--target", "lab", "--yes", "-q", "--sigma-rules", rules)
	if r.code != report.ExitExpectationFailed {
		t.Fatalf("want exit 1 (detection missing), got %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	rec := records(t, r.stdout)[0]
	if rec["verdict"] != "detection-missing" {
		t.Fatalf("verdict %v (reason %v)", rec["verdict"], rec["reason"])
	}
	d := detections(t, rec)[0].(map[string]any)
	if d["fired"] != false || d["status"] != "not-fired" {
		t.Fatalf("detection = %v", d)
	}
}

// TestSigmaUnknownRule proves that a referenced rule that cannot be found is
// reported as unknown and never silently treated as a pass of the detection:
// the detection entry carries status unknown with an explanation and does not
// decide fired. Telemetry still passes, so the run does not fail on an
// undecided detection, but the gap is visible in the record.
func TestSigmaUnknownRule(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	corpus := t.TempDir()
	customTechnique(t, corpus, "unknown", "deadbeef-0000-4000-8000-0000000000ff")

	r := s.run("--corpus-dir", corpus, "apply", "fake.privilege-escalation.admin-role-assign-unknown",
		"--target", "lab", "--yes", "-q")
	if r.code != report.ExitOK {
		t.Fatalf("an undecided detection must not fail the run on its own: exit %d\n%s", r.code, r.stdout)
	}
	rec := records(t, r.stdout)[0]
	d := detections(t, rec)[0].(map[string]any)
	if d["status"] != "unknown" {
		t.Fatalf("want status unknown, got %v", d["status"])
	}
	if d["fired"] != nil {
		t.Fatalf("unknown must not decide fired, got %v", d["fired"])
	}
	if e, _ := d["error"].(string); e == "" {
		t.Fatal("an unknown rule must explain itself, never be a silent pass")
	}
}

// TestSigmaUnparseableRule proves that a referenced rule the evaluator cannot
// parse is reported as unsupported with the parse error in the record (so it
// survives -q), and that load problems are one summary line by default with
// the per-file detail only at -v.
func TestSigmaUnparseableRule(t *testing.T) {
	s := newSandbox(t)
	s.initLab()
	corpus := t.TempDir()
	rules := t.TempDir()
	const bad = `
title: Unparseable %s (example)
id: deadbeef-0000-4000-8000-00000000000%s
logsource: {product: fake}
detection:
  selection:
    eventType|nosuchmodifier: user.account.privilege.grant
  condition: selection
`
	writeFile(t, filepath.Join(rules, "bad-a.yml"), strings.ReplaceAll(bad, "%s", "a"))
	writeFile(t, filepath.Join(rules, "bad-b.yml"), strings.ReplaceAll(bad, "%s", "b"))
	customTechnique(t, corpus, "unparseable", "deadbeef-0000-4000-8000-00000000000a")
	args := []string{"--corpus-dir", corpus, "apply", "fake.privilege-escalation.admin-role-assign-unparseable",
		"--target", "lab", "--yes", "--sigma-rules", rules}

	r := s.run(append(args, "-q")...)
	if r.code != report.ExitOK {
		t.Fatalf("an undecided detection must not fail the run on its own: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	d := detections(t, records(t, r.stdout)[0])[0].(map[string]any)
	if d["status"] != "unsupported" || d["fired"] != nil {
		t.Fatalf("detection = %v", d)
	}
	if e, _ := d["error"].(string); !strings.Contains(e, "nosuchmodifier") {
		t.Fatalf("the record must carry the parse error, got %q", e)
	}

	r = s.run(args...)
	if !strings.Contains(r.stderr, "2 Sigma rule(s) could not be loaded; run with -v for details") {
		t.Errorf("want one summary line on stderr, got:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "rule not loaded:") {
		t.Errorf("per-file detail must need -v, got:\n%s", r.stderr)
	}

	r = s.run(append(args, "-v")...)
	if n := strings.Count(r.stderr, "rule not loaded:"); n != 2 {
		t.Errorf("want 2 per-file detail lines at -v, got %d:\n%s", n, r.stderr)
	}
}

// customTechnique writes a copy of the shipped fake admin-role-assign technique
// into dir with a distinct id suffix and a single sigma detection reference.
func customTechnique(t *testing.T, dir, suffix, ruleRef string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "techniques", "fake", "privilege-escalation.admin-role-assign.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	body = strings.Replace(body,
		"id: fake.privilege-escalation.admin-role-assign",
		"id: fake.privilege-escalation.admin-role-assign-"+suffix, 1)
	// Replace the whole detections block with one that references ruleRef.
	idx := strings.Index(body, "detections:")
	if idx < 0 {
		t.Fatal("source technique has no detections block")
	}
	body = body[:idx] + "detections:\n  - sigma: " + ruleRef + "\n"
	writeFile(t, filepath.Join(dir, suffix+".yaml"), body)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
