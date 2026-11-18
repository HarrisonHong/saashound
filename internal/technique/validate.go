package technique

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Tactics is the tool's own frozen tactic vocabulary. It is deliberately not
// ATT&CK's tactic list, so an ATT&CK reshuffle never renames a technique ID.
// ATT&CK IDs live in the attack: metadata instead.
var Tactics = []string{
	"initial-access",
	"persistence",
	"privilege-escalation",
	"defense-impairment",
	"credential-access",
	"discovery",
	"lateral-movement",
	"collection",
	"exfiltration",
	"impact",
}

// Evidence levels.
var Evidence = []string{"incident", "guidance", "rules-only"}

// Limits.
const (
	MaxSteps        = 32
	MaxExpectations = 64
	MinDeadline     = time.Second
	MaxDeadline     = 24 * time.Hour
)

var (
	idRe        = regexp.MustCompile(`^([a-z][a-z0-9]*)\.([a-z]+(?:-[a-z]+)*)\.([a-z0-9]+(?:-[a-z0-9]+)*)$`)
	attackRe    = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
	uuidRe      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	fieldPathRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[\])?)*$`)
)

func splitID(id string) (platform, tactic, name string) {
	m := idRe.FindStringSubmatch(id)
	if m == nil {
		return "", "", ""
	}
	return m[1], m[2], m[3]
}

// OpInfo is what the validator needs to know about an op.
type OpInfo struct {
	Spec     provider.Spec
	Provider string
	// HasUndo, HasGone and HasRecovery report the op's inverse, its proof,
	// and its crash-recovery method (Locate or Prior). Registered ops always
	// have all three; the validator checks anyway, so a catalog that is not
	// the registry cannot smuggle an irreversible op into a technique.
	HasUndo     bool
	HasGone     bool
	HasRecovery bool
}

// Catalog is the op vocabulary techniques are validated against.
type Catalog interface {
	Audit(platform string) (provider.AuditInfo, bool)
	Op(name string) (OpInfo, bool)
}

// RegistryCatalog adapts a provider registry.
func RegistryCatalog(r *provider.Registry) Catalog { return registryCatalog{r} }

type registryCatalog struct{ r *provider.Registry }

func (c registryCatalog) Audit(platform string) (provider.AuditInfo, bool) {
	p, ok := c.r.Provider(platform)
	if !ok {
		return provider.AuditInfo{}, false
	}
	return p.Audit(), true
}

func (c registryCatalog) Op(name string) (OpInfo, bool) {
	e, ok := c.r.Op(name)
	if !ok {
		return OpInfo{}, false
	}
	return OpInfo{
		Spec:        e.Spec,
		Provider:    e.Provider,
		HasUndo:     e.Undo != nil,
		HasGone:     e.Gone != nil,
		HasRecovery: e.Locate != nil || e.Prior != nil,
	}, true
}

// ValidationError lists every problem found in one technique, so a
// contributor sees them all at once.
type ValidationError struct {
	Source   string
	ID       string
	Problems []string
}

func (e *ValidationError) Error() string {
	name := e.Source
	if e.ID != "" {
		name += " (" + e.ID + ")"
	}
	return fmt.Sprintf("%s: invalid technique:\n  - %s", name, strings.Join(e.Problems, "\n  - "))
}

type checker struct {
	problems []string
}

func (c *checker) addf(format string, a ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, a...))
}

// Validate checks t against the catalog. It returns a *ValidationError
// listing every problem, or nil.
func Validate(t *Technique, cat Catalog) error {
	c := &checker{}
	validate(c, t, cat)
	if len(c.problems) == 0 {
		return nil
	}
	return &ValidationError{Source: t.Source, ID: t.ID, Problems: c.problems}
}

func validate(c *checker, t *Technique, cat Catalog) {
	platform, tactic, _ := splitID(t.ID)
	switch {
	case t.ID == "":
		c.addf("id is required")
	case platform == "":
		c.addf("id %q must be <platform>.<tactic>.<verb-object>, lowercase", t.ID)
	default:
		if platform != t.Platform {
			c.addf("id %q must start with its platform %q", t.ID, t.Platform)
		}
		if !contains(Tactics, tactic) {
			c.addf("id %q: tactic %q is not one of %s", t.ID, tactic, strings.Join(Tactics, ", "))
		}
	}
	if strings.TrimSpace(t.Name) == "" {
		c.addf("name is required")
	} else if len(t.Name) > 120 {
		c.addf("name is longer than 120 characters")
	}
	if len(t.Author) == 0 {
		c.addf("author is required (credit the contributor)")
	}
	for _, a := range t.Author {
		if strings.TrimSpace(a) == "" {
			c.addf("author entries must not be empty")
		}
	}
	audit, platformOK := cat.Audit(t.Platform)
	if t.Platform == "" {
		c.addf("platform is required")
	} else if !platformOK {
		c.addf("platform %q has no registered provider", t.Platform)
	}
	for _, a := range t.Attack {
		if !attackRe.MatchString(a) {
			c.addf("attack %q is not an ATT&CK technique ID like T1098 or T1098.005", a)
		}
	}
	for i, r := range t.Tradecraft {
		if strings.TrimSpace(r.Title) == "" {
			c.addf("tradecraft[%d]: title is required", i)
		}
		if !strings.HasPrefix(r.URL, "https://") {
			c.addf("tradecraft[%d]: url must be https", i)
		}
		if _, err := time.Parse("2006-01-02", r.Date); err != nil {
			c.addf("tradecraft[%d]: date must be YYYY-MM-DD", i)
		}
	}
	if !contains(Evidence, t.Evidence) {
		c.addf("evidence must be one of %s", strings.Join(Evidence, ", "))
	}
	if t.Safety.ThirdPartyContact != "none" {
		c.addf("safety.third_party_contact must be \"none\": techniques never contact anyone outside the tenant")
	}
	if t.Safety.ModifiesExisting && t.Safety.ProductionSafe {
		c.addf("safety: a technique that modifies existing objects can never be production_safe")
	}

	steps := validateSteps(c, t, cat)

	validateExpect(c, t, steps, audit, platformOK)

	// Cleanup must be declared, and must undo every step in reverse.
	want := make([]string, 0, len(t.Steps))
	for i := len(t.Steps) - 1; i >= 0; i-- {
		want = append(want, t.Steps[i].ID)
	}
	if len(t.Cleanup.Order) == 0 {
		c.addf("cleanup.order is required: list every step, last step first (%s)", strings.Join(want, ", "))
	} else if strings.Join(t.Cleanup.Order, ",") != strings.Join(want, ",") {
		c.addf("cleanup.order must undo every step in reverse: want [%s], got [%s]", strings.Join(want, ", "), strings.Join(t.Cleanup.Order, ", "))
	}

	for i, d := range t.Detections {
		switch d.Kind() {
		case "sigma", "elastic":
		default:
			c.addf("detections[%d]: must be sigma: <id|null> or elastic: <id|null>", i)
			continue
		}
		if r := d.Rule(); (d.Sigma != nil || d.Elastic != nil) && !uuidRe.MatchString(r) {
			c.addf("detections[%d]: %s rule %q must be referenced by its UUID (rule paths move), or null", i, d.Kind(), r)
		}
	}
	for i, f := range t.Fixtures {
		if _, err := fsutil.Contain("fixtures", f); err != nil {
			c.addf("fixtures[%d]: %v", i, err)
		} else if !strings.HasSuffix(f, ".jsonl") {
			c.addf("fixtures[%d]: fixtures are .jsonl files", i)
		}
	}
}

// stepInfo is what later checks need to know about each valid step.
type stepInfo struct {
	index int
	op    OpInfo
	ok    bool
}

func validateSteps(c *checker, t *Technique, cat Catalog) map[string]stepInfo {
	steps := map[string]stepInfo{}
	if len(t.Steps) == 0 {
		c.addf("steps: at least one step is required")
	}
	if len(t.Steps) > MaxSteps {
		c.addf("steps: at most %d steps", MaxSteps)
	}
	for i, s := range t.Steps {
		where := fmt.Sprintf("steps[%d] (%s)", i, s.ID)
		if !marker.ValidStepID(s.ID) {
			c.addf("%s: id must be lowercase words joined by '-', at most %d characters", where, marker.MaxStepIDLength)
		}
		if _, dup := steps[s.ID]; dup {
			c.addf("%s: duplicate step id", where)
			continue
		}
		info := stepInfo{index: i}
		op, ok := cat.Op(s.Op)
		switch {
		case s.Op == "":
			c.addf("%s: op is required", where)
		case !ok:
			c.addf("%s: op %q is not registered", where, s.Op)
		case op.Provider != t.Platform:
			c.addf("%s: op %q belongs to platform %q, not %q", where, s.Op, op.Provider, t.Platform)
		case !op.HasUndo:
			c.addf("%s: op %q has no inverse (Undo); every op must be reversible", where, s.Op)
		case !op.HasGone:
			c.addf("%s: op %q has no gone check; cleanup must be provable", where, s.Op)
		case !op.HasRecovery:
			c.addf("%s: op %q cannot be recovered after a crash (no Locate or Prior)", where, s.Op)
		default:
			info.op = op
			info.ok = true
		}
		if info.ok {
			validateParams(c, where, s, info.op.Spec, steps)
			if info.op.Spec.Kind == provider.KindModify && !info.op.Spec.TargetsRunObject() && !t.Safety.ModifiesExisting {
				c.addf("%s: op %q modifies an object the run did not create; set safety.modifies_existing", where, s.Op)
			}
		}
		steps[s.ID] = info
	}
	return steps
}

func validateParams(c *checker, where string, s Step, spec provider.Spec, earlier map[string]stepInfo) {
	for _, name := range sortedKeys(s.With) {
		if _, ok := spec.Param(name); !ok {
			c.addf("%s: op %s has no parameter %q", where, spec.Name, name)
		}
	}
	for _, p := range spec.Params {
		v, set := s.With[p.Name]
		if !set {
			if p.Required {
				c.addf("%s: parameter %q is required", where, p.Name)
			}
			continue
		}
		tmpl, err := ParseTemplate(v)
		if err != nil {
			c.addf("%s: parameter %q: %v", where, p.Name, err)
			continue
		}
		switch p.Type {
		case provider.ParamEnum:
			if len(tmpl.Refs()) > 0 || !contains(p.Enum, v) {
				c.addf("%s: parameter %q must be one of %s", where, p.Name, strings.Join(p.Enum, ", "))
			}
		case provider.ParamRef:
			r, single := tmpl.SingleRef()
			if !single || r.Scope != ScopeSteps || r.Field != "id" {
				c.addf("%s: parameter %q must be exactly {{steps.<id>.id}} of an earlier step that created a %s", where, p.Name, p.Ref)
				continue
			}
			prev, ok := earlier[r.Step]
			switch {
			case !ok:
				c.addf("%s: parameter %q refers to step %q, which does not come earlier", where, p.Name, r.Step)
			case prev.ok && prev.op.Spec.Resource != p.Ref:
				c.addf("%s: parameter %q needs a %s, but step %q produces a %s", where, p.Name, p.Ref, r.Step, prev.op.Spec.Resource)
			}
		case provider.ParamString:
			checkRefs(c, where+": parameter "+fmt.Sprintf("%q", p.Name), tmpl, earlier)
		}
	}
}

// checkRefs validates steps-scope placeholders against the steps that come
// before (or, for expectations, up to and including) the current one.
func checkRefs(c *checker, where string, tmpl Template, visible map[string]stepInfo) {
	for _, r := range tmpl.Refs() {
		if r.Scope != ScopeSteps {
			continue
		}
		prev, ok := visible[r.Step]
		switch {
		case !ok:
			c.addf("%s: %s refers to a step that has not run yet", where, r)
		case prev.ok && !prev.op.Spec.HasOutput(r.Field):
			c.addf("%s: %s: op %s has no output %q", where, r, prev.op.Spec.Name, r.Field)
		}
	}
}

func validateExpect(c *checker, t *Technique, steps map[string]stepInfo, audit provider.AuditInfo, platformOK bool) {
	if len(t.Expect) == 0 {
		c.addf("expect: at least one expected audit event is required; a technique must say what the platform logs")
	}
	if len(t.Expect) > MaxExpectations {
		c.addf("expect: at most %d expectations", MaxExpectations)
	}
	for i, e := range t.Expect {
		where := fmt.Sprintf("expect[%d]", i)
		after, ok := steps[e.After]
		if e.After == "" {
			c.addf("%s: after is required", where)
		} else if !ok {
			c.addf("%s: after refers to unknown step %q", where, e.After)
		}
		if platformOK && e.Source != audit.Name {
			c.addf("%s: source must be %q, the %s audit source", where, audit.Name, t.Platform)
		}
		if len(e.Match) == 0 {
			c.addf("%s: match is required", where)
		}
		// Placeholders may refer to the step itself and anything earlier.
		visible := map[string]stepInfo{}
		for id, s := range steps {
			if ok && s.index <= after.index {
				visible[id] = s
			}
		}
		for _, path := range sortedKeys(e.Match) {
			v := e.Match[path]
			if !fieldPathRe.MatchString(path) {
				c.addf("%s: match key %q is not a field path like eventType or target[].id", where, path)
			}
			tmpl, err := ParseTemplate(v)
			if err != nil {
				c.addf("%s: match %q: %v", where, path, err)
				continue
			}
			checkRefs(c, fmt.Sprintf("%s: match %q", where, path), tmpl, visible)
		}
		if platformOK {
			typ, has := e.Match[audit.TypeField]
			switch {
			case !has:
				c.addf("%s: match must include the event type field %q", where, audit.TypeField)
			case ok && after.ok && !contains(after.op.Spec.Events, typ):
				c.addf("%s: step %q (op %s) does not produce event %q; it produces %s", where, e.After, after.op.Spec.Name, typ, strings.Join(after.op.Spec.Events, ", "))
			}
		}
		if d := time.Duration(e.Deadline); d != 0 && (d < MinDeadline || d > MaxDeadline) {
			c.addf("%s: deadline %s must be between %s and %s", where, d, MinDeadline, MaxDeadline)
		}
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
