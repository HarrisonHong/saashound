// Package plan turns a technique into a concrete, printable plan for one run
// against one target: the ordered op invocations with their deterministic
// object names, the expectations with their deadlines, the scopes needed and
// the cleanup order. A plan is pure data; `apply --plan` re-derives it from
// the corpus and refuses if the saved copy differs.
package plan

import (
	"fmt"
	"sort"
	"time"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
)

// Schema identifiers of a saved plan.
const (
	Schema  = "saashound.plan"
	Version = 1
)

// File is a saved plan (plan -o plan.json).
type File struct {
	Schema  string `json:"schema"`
	Version int    `json:"version"`
	Tool    string `json:"tool"`
	Corpus  string `json:"corpus"`
	Runs    []*Run `json:"runs"`
}

// Run is the plan for one technique against one target.
type Run struct {
	Run         string           `json:"run"`
	Technique   string           `json:"technique"`
	Name        string           `json:"name"`
	Digest      string           `json:"technique_digest"`
	Verified    bool             `json:"verified"`
	Attack      []string         `json:"attack,omitempty"`
	Safety      technique.Safety `json:"safety"`
	Target      string           `json:"target"`
	Platform    string           `json:"platform"`
	Tenant      string           `json:"tenant"`
	Principal   string           `json:"principal"`
	Environment string           `json:"environment"`
	TestDomain  string           `json:"test_domain"`
	Ticket      string           `json:"ticket,omitempty"`
	Steps       []Step           `json:"steps"`
	Expect      []Expectation    `json:"expect"`
	Cleanup     []CleanupStep    `json:"cleanup"`
	Scopes      []string         `json:"scopes"`
	Detections  []Detection      `json:"detections,omitempty"`
}

// Step is one planned op invocation.
type Step struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Op       string `json:"op"`
	Kind     string `json:"kind"`
	Resource string `json:"resource"`
	// Name is the deterministic object name, derived from the run ID.
	Name string `json:"name"`
	// With holds the parameters as written; step references resolve at
	// execution time.
	With    map[string]string `json:"with,omitempty"`
	Request string            `json:"request"`
	Note    string            `json:"note,omitempty"`
	Scopes  []string          `json:"scopes"`
	Events  []string          `json:"events"`
}

// Expectation is a planned telemetry expectation.
type Expectation struct {
	After    string            `json:"after"`
	Source   string            `json:"source"`
	Type     string            `json:"event_type"`
	Match    map[string]string `json:"match"`
	Deadline Duration          `json:"deadline"`
}

// CleanupStep is one planned undo.
type CleanupStep struct {
	Step      string `json:"step"`
	Op        string `json:"op"`
	Undo      string `json:"undo"`
	GoneCheck string `json:"gone_check"`
}

// Detection is a declared detection mapping.
type Detection struct {
	Checker string `json:"checker"`
	// Rule is the referenced rule ID, or "" for an explicit "no public rule".
	Rule string `json:"rule,omitempty"`
}

// Duration marshals as a Go duration string.
type Duration time.Duration

// String formats the duration like time.Duration.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Planner builds plans from techniques and the op registry.
type Planner struct {
	Registry *provider.Registry
}

// Plan builds the plan for technique t against target tgt as run runID.
func (p Planner) Plan(t *technique.Technique, tgt *target.Target, runID, ticket string) (*Run, error) {
	if !marker.ValidRunID(runID) {
		return nil, fmt.Errorf("plan: invalid run id %q", runID)
	}
	if t.Platform != tgt.Platform {
		return nil, fmt.Errorf("technique %s is for platform %q, but target %s is %q", t.ID, t.Platform, tgt.Name, tgt.Platform)
	}
	prov, ok := p.Registry.Provider(t.Platform)
	if !ok {
		return nil, fmt.Errorf("plan: no provider for platform %q", t.Platform)
	}
	audit := prov.Audit()
	r := &Run{
		Run:         runID,
		Technique:   t.ID,
		Name:        t.Name,
		Digest:      t.Digest,
		Verified:    t.Verified,
		Attack:      t.Attack,
		Safety:      t.Safety,
		Target:      tgt.Name,
		Platform:    tgt.Platform,
		Tenant:      tgt.Tenant,
		Principal:   tgt.Principal,
		Environment: tgt.Environment,
		TestDomain:  tgt.TestDomain,
		Ticket:      ticket,
	}
	scopes := map[string]bool{}
	for _, s := range audit.Scopes {
		scopes[s] = true
	}
	for i, s := range t.Steps {
		e, ok := p.Registry.Op(s.Op)
		if !ok {
			return nil, fmt.Errorf("plan: step %s: op %q is not registered", s.ID, s.Op)
		}
		with := map[string]string{}
		for k, v := range s.With {
			with[k] = v
		}
		r.Steps = append(r.Steps, Step{
			Index:    i + 1,
			ID:       s.ID,
			Op:       s.Op,
			Kind:     string(e.Spec.Kind),
			Resource: e.Spec.Resource,
			Name:     marker.ObjectName(runID, s.ID),
			With:     with,
			Request:  e.Spec.Request,
			Note:     e.Spec.Note,
			Scopes:   e.Spec.Scopes,
			Events:   e.Spec.Events,
		})
		for _, sc := range e.Spec.Scopes {
			scopes[sc] = true
		}
	}
	for _, x := range t.Expect {
		d := time.Duration(x.Deadline)
		if d == 0 {
			d = audit.Deadline
		}
		match := map[string]string{}
		for k, v := range x.Match {
			match[k] = v
		}
		r.Expect = append(r.Expect, Expectation{
			After:    x.After,
			Source:   x.Source,
			Type:     x.Match[audit.TypeField],
			Match:    match,
			Deadline: Duration(d),
		})
	}
	for _, id := range t.Cleanup.Order {
		s, _, ok := t.Step(id)
		if !ok {
			return nil, fmt.Errorf("plan: cleanup step %q does not exist", id)
		}
		e, _ := p.Registry.Op(s.Op)
		r.Cleanup = append(r.Cleanup, CleanupStep{Step: id, Op: s.Op, Undo: e.Spec.UndoSummary, GoneCheck: e.Spec.GoneCheck})
	}
	for _, d := range t.Detections {
		r.Detections = append(r.Detections, Detection{Checker: d.Kind(), Rule: d.Rule()})
	}
	for s := range scopes {
		r.Scopes = append(r.Scopes, s)
	}
	sort.Strings(r.Scopes)
	return r, nil
}
