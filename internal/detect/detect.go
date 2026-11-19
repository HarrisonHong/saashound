// Package detect is the seam for detection checkers: given exactly the
// events a run produced, did the operator's detection fire?
//
// Two checkers are designed (report section 6): "sigma", which evaluates the
// technique's referenced Sigma rules locally on the raw events, and "exec",
// which hands the result record to the operator's own SIEM query through a
// fixed argv contract. "sigma" is implemented in internal/detect/sigma;
// "exec" is not yet. The engine runs whatever checkers it is given and folds
// their results into the verdict.
package detect

import (
	"context"
	"time"

	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

// Input is what a checker sees.
type Input struct {
	Run       string
	Technique string
	Platform  string
	// Mappings are the technique's declared detection mappings.
	Mappings []plan.Detection
	// Events are the run's raw events (detonation and cleanup phases).
	Events      []telemetry.Seen
	WindowStart time.Time
	WindowEnd   time.Time
}

// Detection statuses. A result always carries one; Fired is the tri-state
// shorthand the verdict keys on (true only for Fired, false only for
// NotFired, nil for everything else, so a result the checker could not
// decide never counts as a pass or a failure).
const (
	// StatusFired: the rule matched at least one of the run's events.
	StatusFired = "fired"
	// StatusNotFired: the rule was evaluated and matched nothing. This is a
	// real claim and fails the verdict.
	StatusNotFired = "not-fired"
	// StatusUnknown: the referenced rule was not found. Never silently a
	// pass: it is reported, but it is not a "did not fire" either.
	StatusUnknown = "unknown"
	// StatusUnsupported: the referenced rule uses a construct the checker
	// cannot evaluate faithfully (for Sigma, a v2 correlation rule or a rule
	// the evaluator cannot parse).
	StatusUnsupported = "unsupported"
	// StatusError: the checker failed to evaluate this rule.
	StatusError = "error"
)

// Result is one detection's outcome.
type Result struct {
	Checker string `json:"checker"`
	// Rule is the rule's title; ID its stable identifier.
	Rule string `json:"rule,omitempty"`
	ID   string `json:"id,omitempty"`
	// Author is carried for rules whose licence requires it in reported
	// matches (the Sigma Detection Rule License 1.1).
	Author string `json:"author,omitempty"`
	Name   string `json:"name,omitempty"`
	// Status is one of the Status* constants: fired, not-fired, unknown,
	// unsupported or error.
	Status string `json:"status,omitempty"`
	// Fired is nil when the checker could not decide.
	Fired    *bool    `json:"fired"`
	LatencyS *float64 `json:"latency_s,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Fire returns a *bool for a status, for the Fired field: true only for
// StatusFired, false only for StatusNotFired, nil otherwise.
func Fire(status string) *bool {
	switch status {
	case StatusFired:
		t := true
		return &t
	case StatusNotFired:
		f := false
		return &f
	}
	return nil
}

// Checker decides whether detections fired.
type Checker interface {
	Name() string
	Check(ctx context.Context, in Input) ([]Result, error)
}
