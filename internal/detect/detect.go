// Package detect is the seam for detection checkers: given exactly the
// events a run produced, did the operator's detection fire?
//
// Two checkers are designed (report section 6): "sigma", which evaluates the
// technique's referenced Sigma rules locally on the raw events, and "exec",
// which hands the result record to the operator's own SIEM query through a
// fixed argv contract. Neither is implemented in this increment; the engine
// already runs whatever checkers it is given and folds their results into
// the verdict.
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
	// Fired is nil when the checker could not decide.
	Fired    *bool    `json:"fired"`
	LatencyS *float64 `json:"latency_s,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// Checker decides whether detections fired.
type Checker interface {
	Name() string
	Check(ctx context.Context, in Input) ([]Result, error)
}
