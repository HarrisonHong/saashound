// Package sigma is the Sigma detection checker: given a technique's referenced
// Sigma rules and exactly the events a run produced, it reports, per rule,
// whether the rule fired on the platform's own events.
//
// It implements the internal/detect seam. Rules are evaluated locally with
// runreveal/sigmalite, the Sigma runtime chosen in the design report (section
// 6) for its field-modifier coverage. The rules are the operator's: they are
// loaded from local directories the operator points the tool at, never
// vendored. A small set of example rules for the simulated `fake` platform is
// bundled so the detection loop proves out in tests and `--target fake`
// without a real rule checkout; those are clearly example rules, not SigmaHQ
// rules.
//
// Faithfulness over coverage: a rule that does not match the run's events is a
// real "not-fired" claim; a referenced rule that is not found is reported as
// unknown, never silently a pass; a rule the evaluator cannot handle (a Sigma
// v2 correlation rule, or a rule it cannot parse) is reported as unsupported.
// The checker only ever claims a rule fired when it actually matched an event.
//
// Known limitation: fired/not-fired is judged over exactly the events the
// telemetry collector captured, verbatim, with no re-poll - the design
// constraint is to consume what the collector produced. The collector stops
// once the technique's own expectations are resolved, so a rule keyed on an
// event outside those expectations may be reported not-fired. Widening
// collection for detection-only events is a possible future increment.
package sigma

import (
	"context"
	"embed"
	"io/fs"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/telemetry"
	sigmalite "github.com/runreveal/sigmalite"
)

// Name is the checker's name, as it appears in detections[].checker.
const Name = "sigma"

//go:embed examplerules/*.yml
var exampleFS embed.FS

// ExampleRules is the bundled set of example Sigma rules (for the simulated
// `fake` platform and the test suite). They are examples, not SigmaHQ rules.
func ExampleRules() fs.FS {
	sub, err := fs.Sub(exampleFS, "examplerules")
	if err != nil {
		panic(err) // the embed path is a constant; this cannot fail
	}
	return sub
}

// Checker evaluates a technique's referenced Sigma rules on a run's events.
type Checker struct {
	rules *RuleSet
}

var _ detect.Checker = (*Checker)(nil)

// New returns a checker over an already-loaded rule set.
func New(rs *RuleSet) *Checker { return &Checker{rules: rs} }

// Load builds a checker from the bundled example rules plus every rule under
// each operator-supplied directory. An empty directory string is skipped.
func Load(dirs ...string) (*Checker, error) {
	rs := NewRuleSet()
	if err := rs.LoadFS(ExampleRules()); err != nil {
		return nil, err
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if err := rs.LoadDir(d); err != nil {
			return nil, err
		}
	}
	return New(rs), nil
}

// RuleSet returns the checker's rule set (its warnings and loaded rules).
func (c *Checker) RuleSet() *RuleSet { return c.rules }

// Name implements detect.Checker.
func (c *Checker) Name() string { return Name }

// Check implements detect.Checker. It evaluates every Sigma rule the technique
// references against the run's detonation-phase events and returns one result
// per referenced rule. A null reference ("no public rule covers this") is a
// coverage-gap statement, not a runtime detection, so it yields no result.
func (c *Checker) Check(_ context.Context, in detect.Input) ([]detect.Result, error) {
	var out []detect.Result
	for _, m := range in.Mappings {
		if m.Checker != Name {
			continue
		}
		if m.Rule == "" {
			continue // sigma: null is a published coverage gap, not a check
		}
		out = append(out, c.evaluate(m.Rule, in.Events))
	}
	return out, nil
}

// evaluate resolves one rule reference and, when found, runs it against the
// run's detonation-phase events.
func (c *Checker) evaluate(ref string, events []telemetry.Seen) detect.Result {
	res := detect.Result{Checker: Name}
	r := c.rules.resolve(ref)
	switch r.status {
	case detect.StatusUnknown:
		res.ID = ref
		res.Status = detect.StatusUnknown
		res.Error = r.reason
		return res
	case detect.StatusUnsupported:
		res.ID = ref
		res.Status = detect.StatusUnsupported
		res.Error = r.reason
		return res
	}
	rule := r.rule
	res.Rule = rule.Title
	res.ID = rule.ID
	res.Author = rule.Author

	if matchAny(rule, events) {
		res.Status = detect.StatusFired
	} else {
		res.Status = detect.StatusNotFired
	}
	res.Fired = detect.Fire(res.Status)
	return res
}

// matchAny reports whether rule matches any detonation-phase event. Cleanup
// events are the tool undoing itself, so matching them would be a false fire;
// the detection question is whether the rule fires on the adversary action.
//
// events is exactly what the collector captured: the checker never re-polls,
// so "no match" means no match among the collected events (see the package
// comment for the limitation this implies).
func matchAny(rule *sigmalite.Rule, events []telemetry.Seen) bool {
	for _, ev := range events {
		if ev.Phase != marker.PhaseDetonate {
			continue
		}
		entry, opts, err := newEntry(ev.Raw)
		if err != nil {
			continue // an event that is not JSON cannot match; skip it
		}
		if rule.Detection.Matches(entry, opts) {
			return true
		}
	}
	return false
}
