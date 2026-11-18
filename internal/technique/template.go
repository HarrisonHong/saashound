package technique

import (
	"fmt"
	"regexp"
	"strings"
)

// Substitution scopes. The set is fixed: there are no functions,
// conditionals, loops or environment lookups.
const (
	ScopeRun    = "run"
	ScopeTarget = "target"
	ScopeSteps  = "steps"
)

// Fields available in the run and target scopes.
var (
	RunFields    = []string{"id", "prefix"}
	TargetFields = []string{"name", "test_domain"}
)

var (
	placeholderRe = regexp.MustCompile(`\{\{(.*?)\}\}`)
	refRe         = regexp.MustCompile(`^\s*(run|target)\.([a-z_]+)\s*$|^\s*steps\.([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.([a-z][a-z0-9_]*)\s*$`)
)

// Ref is one {{scope.field}} placeholder.
type Ref struct {
	Scope string
	Step  string // set for the steps scope
	Field string
}

func (r Ref) String() string {
	if r.Scope == ScopeSteps {
		return "{{steps." + r.Step + "." + r.Field + "}}"
	}
	return "{{" + r.Scope + "." + r.Field + "}}"
}

type part struct {
	lit string
	ref *Ref
}

// Template is a parsed parameter or match value.
type Template struct {
	raw   string
	parts []part
}

// ParseTemplate parses s. Anything that looks like a placeholder but is not
// one of the fixed scopes is an error, as is a stray "{{" or "}}".
func ParseTemplate(s string) (Template, error) {
	t := Template{raw: s}
	last := 0
	for _, loc := range placeholderRe.FindAllStringSubmatchIndex(s, -1) {
		lit := s[last:loc[0]]
		if strings.Contains(lit, "{{") || strings.Contains(lit, "}}") {
			return Template{}, fmt.Errorf("malformed placeholder in %q", s)
		}
		if lit != "" {
			t.parts = append(t.parts, part{lit: lit})
		}
		inner := s[loc[2]:loc[3]]
		m := refRe.FindStringSubmatch(inner)
		if m == nil {
			return Template{}, fmt.Errorf("invalid placeholder {{%s}}: only {{run.<field>}}, {{target.<field>}} and {{steps.<id>.<field>}} are allowed", inner)
		}
		var r Ref
		if m[1] != "" {
			r = Ref{Scope: m[1], Field: m[2]}
			allowed := RunFields
			if r.Scope == ScopeTarget {
				allowed = TargetFields
			}
			if !contains(allowed, r.Field) {
				return Template{}, fmt.Errorf("invalid placeholder {{%s}}: %s has fields %s", strings.TrimSpace(inner), r.Scope, strings.Join(allowed, ", "))
			}
		} else {
			r = Ref{Scope: ScopeSteps, Step: m[3], Field: m[4]}
		}
		t.parts = append(t.parts, part{ref: &r})
		last = loc[1]
	}
	tail := s[last:]
	if strings.Contains(tail, "{{") || strings.Contains(tail, "}}") {
		return Template{}, fmt.Errorf("malformed placeholder in %q", s)
	}
	if tail != "" {
		t.parts = append(t.parts, part{lit: tail})
	}
	return t, nil
}

// MustParseTemplate parses a template already known to be valid.
func MustParseTemplate(s string) Template {
	t, err := ParseTemplate(s)
	if err != nil {
		panic(err)
	}
	return t
}

// Refs returns the template's placeholders in order.
func (t Template) Refs() []Ref {
	var out []Ref
	for _, p := range t.parts {
		if p.ref != nil {
			out = append(out, *p.ref)
		}
	}
	return out
}

// SingleRef returns the placeholder if the template is exactly one
// placeholder and nothing else.
func (t Template) SingleRef() (Ref, bool) {
	if len(t.parts) == 1 && t.parts[0].ref != nil {
		return *t.parts[0].ref, true
	}
	return Ref{}, false
}

// Env holds the values placeholders resolve to.
type Env struct {
	Run    map[string]string
	Target map[string]string
	// Steps maps step ID to that step's outputs (always including id, name).
	Steps map[string]map[string]string
}

// Resolve substitutes every placeholder. A placeholder whose value is not
// known yet (a step that has not run) is an error.
func (t Template) Resolve(env Env) (string, error) {
	var b strings.Builder
	for _, p := range t.parts {
		if p.ref == nil {
			b.WriteString(p.lit)
			continue
		}
		r := *p.ref
		var (
			v  string
			ok bool
		)
		switch r.Scope {
		case ScopeRun:
			v, ok = env.Run[r.Field]
		case ScopeTarget:
			v, ok = env.Target[r.Field]
		case ScopeSteps:
			if outs, found := env.Steps[r.Step]; found {
				v, ok = outs[r.Field]
			}
		}
		if !ok {
			return "", fmt.Errorf("%s has no value", r)
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
