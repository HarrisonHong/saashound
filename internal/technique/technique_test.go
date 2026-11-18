package technique_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/technique"
	_ "github.com/HarrisonHong/saashound/providers/fake"
	"github.com/HarrisonHong/saashound/techniques"
)

func TestTemplates(t *testing.T) {
	env := technique.Env{
		Run:    map[string]string{"id": "k3v9q2", "prefix": "saashound-k3v9q2"},
		Target: map[string]string{"name": "lab", "test_domain": "lab.example.com"},
		Steps:  map[string]map[string]string{"victim": {"id": "00u1", "login": "a@b"}},
	}
	good := map[string]string{
		"plain":      "plain",
		"{{run.id}}": "k3v9q2",
		"{{ run.prefix }}-x@{{target.test_domain}}":         "saashound-k3v9q2-x@lab.example.com",
		"user {{steps.victim.id}} ({{steps.victim.login}})": "user 00u1 (a@b)",
	}
	for in, want := range good {
		tmpl, err := technique.ParseTemplate(in)
		if err != nil {
			t.Fatalf("ParseTemplate(%q): %v", in, err)
		}
		got, err := tmpl.Resolve(env)
		if err != nil || got != want {
			t.Fatalf("Resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"{{env.HOME}}",                // no environment scope
		"{{run.token}}",               // unknown run field
		"{{target.base_url}}",         // there is no host field to reach
		"{{steps.victim}}",            // missing field
		"{{ upper(run.id) }}",         // no functions
		"{{#if run.id}}x{{/if}}",      // no conditionals
		"{{run.id}",                   // malformed
		"x }} y",                      // stray close
		"{{steps.Victim.id}}",         // step ids are lowercase
		"{{steps.victim.id}}{{run.id", // trailing open
	} {
		if _, err := technique.ParseTemplate(bad); err == nil {
			t.Errorf("ParseTemplate(%q) accepted", bad)
		}
	}
	tmpl := technique.MustParseTemplate("{{steps.later.id}}")
	if _, err := tmpl.Resolve(env); err == nil {
		t.Fatal("resolving a step that has not run must fail")
	}
}

// catalog is a test catalog: the real registry plus ops the registry would
// never accept, to prove the validator does not rely on registration alone.
type catalog struct {
	technique.Catalog
	extra map[string]technique.OpInfo
}

func (c catalog) Op(name string) (technique.OpInfo, bool) {
	if o, ok := c.extra[name]; ok {
		return o, true
	}
	return c.Catalog.Op(name)
}

func testCatalog() technique.Catalog {
	real := technique.RegistryCatalog(provider.Default)
	user, _ := real.Op("fake.user.create")
	noUndo := user
	noUndo.Spec.Name = "fake.user.create_forever"
	noUndo.HasUndo = false
	noGone := user
	noGone.Spec.Name = "fake.user.create_unproven"
	noGone.HasGone = false
	return catalog{Catalog: real, extra: map[string]technique.OpInfo{
		noUndo.Spec.Name: noUndo,
		noGone.Spec.Name: noGone,
	}}
}

const base = `id: fake.persistence.test-technique
name: Test technique
author: [tester]
platform: fake
attack: [T1098.005]
tradecraft:
  - {title: "A write-up", url: "https://example.com/a", date: 2026-01-22}
evidence: guidance
safety: {production_safe: true, modifies_existing: false, third_party_contact: none}
steps:
  - id: victim
    op: fake.user.create
  - id: factor
    op: fake.factor.enroll
    with: {user: "{{steps.victim.id}}"}
expect:
  - after: factor
    source: fake.audit
    match: {eventType: user.mfa.factor.activate, "target[].id": "{{steps.victim.id}}"}
    deadline: 1m
cleanup:
  order: [factor, victim]
detections:
  - sigma: null
`

func parseValidate(t *testing.T, src string) error {
	t.Helper()
	tech, err := technique.Parse("test.yaml", []byte(src))
	if err != nil {
		return err
	}
	return technique.Validate(tech, testCatalog())
}

func TestValidTechnique(t *testing.T) {
	if err := parseValidate(t, base); err != nil {
		t.Fatal(err)
	}
	tech, _ := technique.Parse("x", []byte(base))
	if time.Duration(tech.Expect[0].Deadline) != time.Minute {
		t.Fatalf("deadline %v", tech.Expect[0].Deadline)
	}
	if tech.Detections[0].Kind() != "sigma" || tech.Detections[0].Rule() != "" {
		t.Fatalf("null sigma mapping lost: %+v", tech.Detections[0])
	}
}

func TestValidatorRejects(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"unregistered op", "op: fake.factor.enroll", "op: fake.factor.steal", `op "fake.factor.steal" is not registered`},
		{"op without inverse", "op: fake.user.create\n", "op: fake.user.create_forever\n", "has no inverse"},
		{"op without gone check", "op: fake.user.create\n", "op: fake.user.create_unproven\n", "no gone check"},
		{"no expectations", `expect:
  - after: factor
    source: fake.audit
    match: {eventType: user.mfa.factor.activate, "target[].id": "{{steps.victim.id}}"}
    deadline: 1m
`, "", "at least one expected audit event"},
		{"no cleanup declaration", "cleanup:\n  order: [factor, victim]\n", "", "cleanup.order is required"},
		{"cleanup out of order", "order: [factor, victim]", "order: [victim, factor]", "must undo every step in reverse"},
		{"cleanup missing a step", "order: [factor, victim]", "order: [factor]", "must undo every step in reverse"},
		{"host field", "platform: fake\n", "platform: fake\nhost: evil.example.com\n", "field host not found"},
		{"url in a step", "    op: fake.user.create\n", "    op: fake.user.create\n    url: https://evil.example.com\n", "field url not found"},
		{"unknown param", `with: {user: "{{steps.victim.id}}"}`, `with: {user: "{{steps.victim.id}}", endpoint: "https://x"}`, `has no parameter "endpoint"`},
		{"missing required param", `    with: {user: "{{steps.victim.id}}"}
`, "", `parameter "user" is required`},
		{"ref to a later step", `with: {user: "{{steps.victim.id}}"}`, `with: {user: "{{steps.factor.id}}"}`, "does not come earlier"},
		{"ref as free text", `with: {user: "{{steps.victim.id}}"}`, `with: {user: "00u123"}`, "must be exactly {{steps.<id>.id}}"},
		{"env lookup", `with: {user: "{{steps.victim.id}}"}`, `with: {user: "{{env.TOKEN}}"}`, "invalid placeholder"},
		{"wrong platform op", "op: fake.factor.enroll", "op: okta.factor.enroll", "is not registered"},
		{"event the op does not emit", "eventType: user.mfa.factor.activate", "eventType: user.mfa.factor.reset_all", "does not produce event"},
		{"no event type", `match: {eventType: user.mfa.factor.activate, "target[].id": "{{steps.victim.id}}"}`, `match: {"target[].id": "{{steps.victim.id}}"}`, `must include the event type field "eventType"`},
		{"wrong audit source", "source: fake.audit", "source: okta.system_log", `source must be "fake.audit"`},
		{"expect after unknown step", "after: factor", "after: nope", `unknown step "nope"`},
		{"bad deadline", "deadline: 1m", "deadline: 48h", "deadline 48h0m0s must be between"},
		{"bad tactic", "id: fake.persistence.test-technique", "id: fake.defense-evasion.test-technique", "tactic \"defense-evasion\""},
		{"id/platform mismatch", "id: fake.persistence.test-technique", "id: okta.persistence.test-technique", "must start with its platform"},
		{"no author", "author: [tester]\n", "", "author is required"},
		{"third-party contact", "third_party_contact: none", "third_party_contact: email", "third_party_contact must be"},
		{"production-safe and modifies existing", "production_safe: true, modifies_existing: false", "production_safe: true, modifies_existing: true", "can never be production_safe"},
		{"sigma by path", "sigma: null", "sigma: rules/identity/okta/okta_mfa_reset.yml", "by its UUID"},
		{"fixture escapes", "detections:", "fixtures: [../../etc/passwd.jsonl]\ndetections:", "escapes its directory"},
		{"duplicate step id", "  - id: factor\n", "  - id: victim\n", "duplicate step id"},
		{"bad evidence", "evidence: guidance", "evidence: vibes", "evidence must be one of"},
		{"http tradecraft", "https://example.com/a", "http://example.com/a", "url must be https"},
		{"bad attack id", "attack: [T1098.005]", "attack: [persistence]", "is not an ATT&CK technique ID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.old != "" && !strings.Contains(base, c.old) {
				t.Fatalf("test setup: base does not contain %q", c.old)
			}
			src := strings.Replace(base, c.old, c.new, 1)
			err := parseValidate(t, src)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v\nwant an error containing %q", err, c.want)
			}
		})
	}
}

func TestModifyingExistingObjectsMustBeDeclared(t *testing.T) {
	src := `id: fake.defense-impairment.mfa-off
name: Turn off MFA org-wide
author: [tester]
platform: fake
evidence: rules-only
safety: {production_safe: false, modifies_existing: false, third_party_contact: none}
steps:
  - id: mfa
    op: fake.org_setting.set
    with: {setting: session.mfa_required, value: "off"}
expect:
  - after: mfa
    source: fake.audit
    match: {eventType: org.setting.update}
cleanup:
  order: [mfa]
`
	err := parseValidate(t, src)
	if err == nil || !strings.Contains(err.Error(), "set safety.modifies_existing") {
		t.Fatalf("got %v", err)
	}
	if err := parseValidate(t, strings.Replace(src, "modifies_existing: false", "modifies_existing: true", 1)); err != nil {
		t.Fatalf("declared modification rejected: %v", err)
	}
	if err := parseValidate(t, strings.Replace(src, `value: "off"`, `value: "maybe"`, 1)); err == nil {
		t.Fatal("enum value outside the declared set accepted")
	}
}

func TestParseIsStrict(t *testing.T) {
	if _, err := technique.Parse("x", []byte(base+"---\nid: second\n")); err == nil {
		t.Fatal("multiple documents accepted")
	}
	if _, err := technique.Parse("x", []byte(strings.Replace(base, "name: Test technique\n", "name: Test technique\nname: Again\n", 1))); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	if _, err := technique.Parse("x", []byte(strings.Repeat("#", technique.MaxFileSize+1))); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := technique.Parse("x", nil); err == nil {
		t.Fatal("empty file accepted")
	}
}

func TestValidationReportsEveryProblem(t *testing.T) {
	src := strings.Replace(strings.Replace(base, "author: [tester]\n", "", 1), "evidence: guidance", "evidence: vibes", 1)
	err := parseValidate(t, src)
	var ve *technique.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) < 2 {
		t.Fatalf("want every problem listed, got %v", err)
	}
}

func TestEmbeddedCorpusValidates(t *testing.T) {
	c := technique.NewCorpus(techniques.Version())
	if err := c.LoadFS(techniques.FS(), true, technique.RegistryCatalog(provider.Default)); err != nil {
		t.Fatal(err)
	}
	list := c.List()
	if len(list) < 2 {
		t.Fatalf("embedded corpus has %d techniques", len(list))
	}
	for _, tech := range list {
		if !tech.Verified || tech.Digest == "" {
			t.Errorf("%s: verified=%v digest=%q", tech.ID, tech.Verified, tech.Digest)
		}
		if len(tech.Steps) < 2 {
			t.Errorf("%s: the illustrative corpus should exercise multi-step techniques", tech.ID)
		}
	}
	if _, err := c.Lookup("fake.persistence.mfa"); err == nil || !strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("Lookup of a partial id = %v; want a suggestion", err)
	}
	if v := techniques.Version(); v == "" || v == "unknown" {
		t.Fatalf("corpus version %q", v)
	}
}

func TestCorpusRejectsDuplicateIDs(t *testing.T) {
	c := technique.NewCorpus("x")
	cat := technique.RegistryCatalog(provider.Default)
	if err := c.LoadFS(techniques.FS(), true, cat); err != nil {
		t.Fatal(err)
	}
	if err := c.LoadFS(techniques.FS(), false, cat); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("a --corpus-dir technique shadowing a verified one must be refused: %v", err)
	}
}
