// Package report defines the versioned result record (one JSON line per
// technique run), the verdict and the CI exit codes, and renders them as
// JSON lines or a terminal table. docs/result-schema.md documents the record;
// a golden test pins its exact shape.
package report

import (
	"encoding/json"
	"time"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

// Record schema identifiers. Version changes only on a breaking change to
// the record; adding a field is not breaking.
const (
	Schema  = "saashound.result"
	Version = 1
)

// Verdicts.
const (
	VerdictPass                 = "pass"
	VerdictDetectionMissing     = "detection-missing"
	VerdictTelemetryMissing     = "telemetry-missing"
	VerdictTelemetryUnsupported = "telemetry-unsupported"
	VerdictCleanupUnverified    = "cleanup-unverified"
	VerdictDetonateFailed       = "detonate-failed"
	VerdictSkipped              = "skipped"
)

// Exit codes.
const (
	ExitOK                = 0 // every expectation met
	ExitExpectationFailed = 1 // telemetry missing, a detection did not fire, or detonation failed
	ExitRefused           = 2 // usage, config or guardrail refusal
	ExitCleanupUnverified = 3 // cleanup not verified; overrides 1
)

// Detonate statuses.
const (
	DetonateOK          = "ok"
	DetonateFailed      = "failed"
	DetonateInterrupted = "interrupted"
	DetonateNotRun      = "not-run"
)

// Cleanup statuses.
const (
	CleanupVerified   = "verified"
	CleanupUnverified = "unverified"
	CleanupNotRun     = "not-run"
)

// Telemetry statuses beyond the per-expectation ones.
const (
	// TelemetryIncomplete: some expectations were never checked, because
	// their step never ran or collection failed or was interrupted.
	TelemetryIncomplete = "incomplete"
)

// Record is one technique run.
type Record struct {
	Schema        string    `json:"schema"`
	Version       int       `json:"version"`
	Run           string    `json:"run"`
	Technique     string    `json:"technique"`
	Corpus        string    `json:"corpus"`
	CorpusVersion string    `json:"corpus_version"`
	Target        string    `json:"target"`
	Platform      string    `json:"platform"`
	Environment   string    `json:"environment"`
	Ticket        *string   `json:"ticket"`
	Tool          string    `json:"tool"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Detonate      Detonate  `json:"detonate"`
	Cleanup       Cleanup   `json:"cleanup"`
	Telemetry     Telemetry `json:"telemetry"`
	// Detections is always an array; empty when no checker is configured or
	// the technique references no rule to check.
	Detections []detect.Result `json:"detections"`
	Verdict    string          `json:"verdict"`
	// Reason explains a verdict other than pass in one sentence.
	Reason string `json:"reason,omitempty"`
}

// Detonate summarises the detonation.
type Detonate struct {
	Status     string `json:"status"`
	Steps      int    `json:"steps"`
	Completed  int    `json:"completed"`
	FailedStep string `json:"failed_step,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Cleanup summarises the cleanup.
type Cleanup struct {
	Status string `json:"status"`
	// Objects counts the steps that were started and are proven undone.
	Objects int      `json:"objects"`
	Orphans []Orphan `json:"orphans"`
	// Retry is the exact command to retry an unverified cleanup.
	Retry string `json:"retry,omitempty"`
}

// Orphan is a step not proven undone.
type Orphan struct {
	Step  string `json:"step"`
	Op    string `json:"op"`
	Name  string `json:"name"`
	ID    string `json:"id,omitempty"`
	Error string `json:"error,omitempty"`
}

// Telemetry summarises the expectation match.
type Telemetry struct {
	Status      string   `json:"status"`
	Source      string   `json:"source"`
	Expected    int      `json:"expected"`
	Observed    int      `json:"observed"`
	Late        int      `json:"late"`
	Missing     int      `json:"missing"`
	MaxLatencyS *float64 `json:"max_latency_s"`
	// EventsFile is the run's raw events, relative to the state directory.
	EventsFile   string              `json:"events_file"`
	Expectations []telemetry.Outcome `json:"expectations"`
	Error        string              `json:"error,omitempty"`
}

// Summarize fills the telemetry counters and status from its expectations.
func (t *Telemetry) Summarize() {
	t.Expected = len(t.Expectations)
	t.Observed, t.Late, t.Missing = 0, 0, 0
	t.MaxLatencyS = nil
	var notRun, unsupported int
	for _, o := range t.Expectations {
		switch o.Status {
		case telemetry.StatusObserved:
			t.Observed++
		case telemetry.StatusLate:
			t.Late++
		case telemetry.StatusMissing:
			t.Missing++
		case telemetry.StatusNotRun:
			notRun++
		case telemetry.StatusUnsupported:
			unsupported++
		}
		if o.LatencyS != nil && (t.MaxLatencyS == nil || *o.LatencyS > *t.MaxLatencyS) {
			v := *o.LatencyS
			t.MaxLatencyS = &v
		}
	}
	switch {
	case unsupported > 0:
		t.Status = telemetry.StatusUnsupported
	case t.Missing > 0:
		t.Status = telemetry.StatusMissing
	case t.Late > 0:
		t.Status = telemetry.StatusLate
	case notRun > 0:
		t.Status = TelemetryIncomplete
	default:
		t.Status = telemetry.StatusObserved
	}
}

// Unchecked reports whether some expectations were never resolved: they are
// not-run, or collection reported an error and left them unseen. A run in
// that state has not had its telemetry verified.
func (t *Telemetry) Unchecked() bool {
	return t.Status == TelemetryIncomplete || (t.Error != "" && t.Observed+t.Late < t.Expected)
}

// Decide sets the verdict and reason from the record's parts. Precedence:
// an unproven cleanup outranks everything, because it may be a live
// backdoor. A completed detonation passes only when every expectation was
// actually checked and met.
func (r *Record) Decide() {
	r.Verdict, r.Reason = VerdictPass, ""
	switch {
	case r.Cleanup.Status == CleanupUnverified:
		r.Verdict = VerdictCleanupUnverified
		r.Reason = "at least one object could not be proven gone; retry with: " + r.Cleanup.Retry
	case r.Detonate.Status == DetonateNotRun:
		r.Verdict = VerdictSkipped
		if r.Reason == "" {
			r.Reason = "the technique was not run"
		}
	case r.Detonate.Status != DetonateOK:
		r.Verdict = VerdictDetonateFailed
		r.Reason = "detonation stopped at step " + r.Detonate.FailedStep + ": " + r.Detonate.Error
	case r.Telemetry.Status == telemetry.StatusUnsupported:
		r.Verdict = VerdictTelemetryUnsupported
		r.Reason = "this tenant's tier has no API for the audit log"
	case r.Telemetry.Unchecked():
		r.Verdict = VerdictTelemetryMissing
		r.Reason = "telemetry collection failed or was interrupted, so not every expected event was checked"
		if r.Telemetry.Error != "" {
			r.Reason += ": " + r.Telemetry.Error
		}
	case r.Telemetry.Missing > 0 || r.Telemetry.Late > 0:
		r.Verdict = VerdictTelemetryMissing
		r.Reason = "expected events did not arrive by their deadline"
	default:
		for _, d := range r.Detections {
			if d.Fired != nil && !*d.Fired {
				r.Verdict = VerdictDetectionMissing
				r.Reason = "telemetry arrived but a configured detection did not fire"
				break
			}
		}
	}
}

// ExitCode maps a verdict to its exit code.
func ExitCode(verdict string) int {
	switch verdict {
	case VerdictPass, VerdictSkipped, VerdictTelemetryUnsupported:
		return ExitOK
	case VerdictCleanupUnverified:
		return ExitCleanupUnverified
	default:
		return ExitExpectationFailed
	}
}

// Combine returns the exit code for a set of records: 3 if any cleanup is
// unverified, else 1 if any expectation failed, else 0.
func Combine(records []*Record) int {
	code := ExitOK
	for _, r := range records {
		switch c := ExitCode(r.Verdict); {
		case c == ExitCleanupUnverified:
			return ExitCleanupUnverified
		case c > code:
			code = c
		}
	}
	return code
}

// MarshalLine returns the record as one JSON line.
func (r *Record) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
