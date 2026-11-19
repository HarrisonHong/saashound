package sigma

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

// exampleRuleID is the bundled example rule's Sigma id.
const exampleRuleID = "5aa5c0de-face-4d00-8b00-0000feedface"

// grantEvent is a fake-platform privilege-grant event, shaped like the Okta
// System Log: it carries two targets, so target.displayName fans out.
const grantEvent = `{
  "uuid": "evt1", "published": "2026-11-14T15:02:11Z",
  "eventType": "user.account.privilege.grant",
  "displayMessage": "Grant user privilege", "severity": "INFO",
  "actor": {"id": "svc", "type": "PublicClientApp", "alternateId": "bot@lab", "displayName": "bot"},
  "client": {"userAgent": {"rawUserAgent": "saashound/0 (run=abc123; phase=detonate)"}},
  "outcome": {"result": "SUCCESS"},
  "target": [
    {"id": "00u1", "type": "User", "alternateId": "victim@lab", "displayName": "saashound-abc123-victim"},
    {"id": "ra1", "type": "RoleAssignment", "displayName": "READ_ONLY_ADMIN"}
  ]
}`

// createEvent is an unrelated user-create event the grant rule must not fire on.
const createEvent = `{
  "uuid": "evt0", "eventType": "user.lifecycle.create",
  "displayMessage": "Create okta user", "outcome": {"result": "SUCCESS"},
  "target": [{"id": "00u1", "type": "User", "displayName": "saashound-abc123-victim"}]
}`

func seen(phase marker.Phase, raw string) telemetry.Seen {
	return telemetry.Seen{Event: provider.Event{Raw: json.RawMessage(raw)}, Phase: phase}
}

func check(t *testing.T, c *Checker, mappings []mapping, events ...telemetry.Seen) []detect.Result {
	t.Helper()
	in := detect.Input{Run: "abc123", Technique: "fake.t", Platform: "fake", Events: events}
	for _, m := range mappings {
		in.Mappings = append(in.Mappings, plan.Detection{Checker: m.checker, Rule: m.rule})
	}
	res, err := c.Check(context.Background(), in)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return res
}

// mapping is a tiny stand-in for a technique's detection reference so the
// tests read clearly.
type mapping struct {
	checker string
	rule    string
}

func TestCheckerFires(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"sigma", exampleRuleID}}, seen(marker.PhaseDetonate, grantEvent))
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	r := res[0]
	if r.Status != detect.StatusFired || r.Fired == nil || !*r.Fired {
		t.Fatalf("want fired, got status=%q fired=%v", r.Status, r.Fired)
	}
	if r.ID != exampleRuleID {
		t.Errorf("id = %q", r.ID)
	}
	if r.Author == "" {
		t.Error("a reported match must carry the rule author (DRL-1.1)")
	}
	if r.Rule == "" {
		t.Error("a reported match must carry the rule title")
	}
}

func TestCheckerDoesNotFire(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Only a user-create event: the admin-grant rule must not fire on it.
	res := check(t, c, []mapping{{"sigma", exampleRuleID}}, seen(marker.PhaseDetonate, createEvent))
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Status != detect.StatusNotFired || res[0].Fired == nil || *res[0].Fired {
		t.Fatalf("want not-fired/false, got status=%q fired=%v", res[0].Status, res[0].Fired)
	}
}

func TestCheckerIgnoresCleanupPhase(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// The grant event, but tagged as a cleanup-phase event: the checker asks
	// whether the rule fires on the adversary action, not on the tool undoing
	// itself, so it must not fire.
	res := check(t, c, []mapping{{"sigma", exampleRuleID}}, seen(marker.PhaseCleanup, grantEvent))
	if res[0].Status != detect.StatusNotFired {
		t.Fatalf("cleanup-phase event fired the rule: %+v", res[0])
	}
}

func TestCheckerUnknownRule(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"sigma", "no-such-rule-id"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusUnknown {
		t.Fatalf("want unknown, got %q", res[0].Status)
	}
	if res[0].Fired != nil {
		t.Fatalf("unknown must not decide fired: %v", res[0].Fired)
	}
	if res[0].Error == "" {
		t.Error("unknown must explain itself, never be a silent pass")
	}
}

func TestCheckerNullMappingSkipped(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// sigma: null is a published coverage-gap statement, not a runtime check.
	res := check(t, c, []mapping{{"sigma", ""}}, seen(marker.PhaseDetonate, grantEvent))
	if len(res) != 0 {
		t.Fatalf("a null mapping must yield no detection result, got %+v", res)
	}
}

func TestCheckerIgnoresOtherCheckers(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"elastic", "some-rule"}}, seen(marker.PhaseDetonate, grantEvent))
	if len(res) != 0 {
		t.Fatalf("sigma must ignore non-sigma mappings, got %+v", res)
	}
}

func TestCheckerUnsupportedCorrelation(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "corr.yml", `
title: Many grants in a short window
id: corr-0001
correlation:
  type: event_count
  rules: [some-base-rule]
  group-by: [actor.id]
  timespan: 5m
  condition: {gte: 5}
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"sigma", "corr-0001"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusUnsupported {
		t.Fatalf("want unsupported for a correlation rule, got %q (%s)", res[0].Status, res[0].Error)
	}
	if res[0].Fired != nil {
		t.Fatalf("unsupported must not decide fired: %v", res[0].Fired)
	}
}

func TestLookupByTitleAndPath(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "sub/mine.yml", `
title: My Grant Rule
id: mine-0001
logsource: {product: fake}
detection:
  selection:
    eventType: user.account.privilege.grant
  condition: selection
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"mine-0001", "My Grant Rule", "sub/mine.yml", "sub/mine"} {
		res := check(t, c, []mapping{{"sigma", ref}}, seen(marker.PhaseDetonate, grantEvent))
		if res[0].Status != detect.StatusFired {
			t.Errorf("reference %q: status %q (%s)", ref, res[0].Status, res[0].Error)
		}
	}
}

func TestAmbiguousTitleIsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "a.yml", "title: Dup\nid: a-1\ndetection:\n  selection:\n    eventType: x\n  condition: selection\n")
	writeRule(t, dir, "b.yml", "title: Dup\nid: b-1\ndetection:\n  selection:\n    eventType: y\n  condition: selection\n")
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"sigma", "Dup"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusUnknown || !strings.Contains(res[0].Error, "matches 2 rules") {
		t.Fatalf("ambiguous title: status=%q error=%q", res[0].Status, res[0].Error)
	}
}

func TestUnparseableRuleIsUnsupported(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "agg.yml", `
title: Many Grants
id: agg-0001
logsource: {product: fake}
detection:
  selection:
    eventType|nosuchmodifier: user.account.privilege.grant
  condition: selection
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.RuleSet().Warnings()) != 1 {
		t.Errorf("want 1 load warning, got %v", c.RuleSet().Warnings())
	}
	for _, ref := range []string{"agg-0001", "Many Grants", "agg.yml", "agg"} {
		res := check(t, c, []mapping{{"sigma", ref}}, seen(marker.PhaseDetonate, grantEvent))
		if res[0].Status != detect.StatusUnsupported {
			t.Errorf("reference %q: want unsupported, got %q (%s)", ref, res[0].Status, res[0].Error)
		}
		if res[0].Fired != nil {
			t.Errorf("reference %q: unsupported must not decide fired", ref)
		}
		if !strings.Contains(res[0].Error, "nosuchmodifier") {
			t.Errorf("reference %q: error must carry the parse error, got %q", ref, res[0].Error)
		}
	}
}

func TestDuplicateIDIsUnknown(t *testing.T) {
	dir := t.TempDir()
	rule := "title: %s\nid: dup-1\ndetection:\n  selection:\n    eventType: user.account.privilege.grant\n  condition: selection\n"
	writeRule(t, dir, "a.yml", strings.Replace(rule, "%s", "First", 1))
	writeRule(t, dir, "b.yml", strings.Replace(rule, "%s", "Second", 1))
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := check(t, c, []mapping{{"sigma", "dup-1"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusUnknown || res[0].Fired != nil {
		t.Fatalf("duplicate id: status=%q fired=%v", res[0].Status, res[0].Fired)
	}
	for _, want := range []string{"declared by 2 rules", "a.yml", "b.yml"} {
		if !strings.Contains(res[0].Error, want) {
			t.Errorf("duplicate id reason %q lacks %q", res[0].Error, want)
		}
	}
	// Each rule is still reachable by an unambiguous reference.
	for _, ref := range []string{"First", "b.yml"} {
		res := check(t, c, []mapping{{"sigma", ref}}, seen(marker.PhaseDetonate, grantEvent))
		if res[0].Status != detect.StatusFired {
			t.Errorf("reference %q: status %q (%s)", ref, res[0].Status, res[0].Error)
		}
	}
}

func TestMultiDocumentPathIsUnknown(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "multi.yml", `
title: Doc One
id: multi-1
detection:
  selection:
    eventType: user.account.privilege.grant
  condition: selection
---
title: Doc Two
id: multi-2
detection:
  selection:
    eventType: user.lifecycle.create
  condition: selection
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"multi.yml", "multi"} {
		res := check(t, c, []mapping{{"sigma", ref}}, seen(marker.PhaseDetonate, grantEvent))
		if res[0].Status != detect.StatusUnknown || !strings.Contains(res[0].Error, "holds 2 rules") {
			t.Errorf("reference %q: status=%q error=%q", ref, res[0].Status, res[0].Error)
		}
	}
	res := check(t, c, []mapping{{"sigma", "multi-1"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusFired {
		t.Errorf("by id: status %q (%s)", res[0].Status, res[0].Error)
	}
}

func TestKeywordSearchMatchesWholeEvent(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "kw.yml", `
title: Keyword Rule
id: kw-0001
logsource: {product: fake}
detection:
  keywords:
    - READ_ONLY_ADMIN
  condition: keywords
`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The keyword appears only in a target's displayName, not displayMessage.
	res := check(t, c, []mapping{{"sigma", "kw-0001"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusFired {
		t.Fatalf("keyword in target: status %q (%s)", res[0].Status, res[0].Error)
	}
	res = check(t, c, []mapping{{"sigma", "kw-0001"}}, seen(marker.PhaseDetonate, createEvent))
	if res[0].Status != detect.StatusNotFired {
		t.Fatalf("keyword absent: status %q", res[0].Status)
	}
}

func TestLoadWarnsOnBadFile(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "broken.yml", "title: No Detection Here\nid: broken-1\n")
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("a single bad rule file must not fail the whole load: %v", err)
	}
	// A file with no detection is simply not a rule; it should not be loaded,
	// and a reference to it is unknown, never a silent pass.
	res := check(t, c, []mapping{{"sigma", "broken-1"}}, seen(marker.PhaseDetonate, grantEvent))
	if res[0].Status != detect.StatusUnknown {
		t.Fatalf("want unknown for a non-rule file, got %q", res[0].Status)
	}
}

func TestLoadDirMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("an explicitly named missing rules dir must be an error")
	}
}

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
