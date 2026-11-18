// Package telemetry reads the platform's own audit log after a run, keeps
// exactly that run's events, and matches them against the technique's
// expectations.
//
// Correlation is an exact identity: an event belongs to the run only if the
// User-Agent the platform recorded parses as this tool's marker with this
// run's ID. Expectations are matched against detonation-phase events only, so
// cleanup traffic never satisfies an expectation.
package telemetry

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Expectation outcomes.
const (
	StatusObserved    = "observed"
	StatusLate        = "late"
	StatusMissing     = "missing"
	StatusUnsupported = "unsupported"
	// StatusNotRun means the expectation was never checked: its step never
	// completed, or collection did not run or was interrupted.
	StatusNotRun = "not-run"
)

// Interrupted is the Result.Error prefix for a collection that was cancelled
// before every expectation was resolved.
const Interrupted = "telemetry collection was interrupted"

// Expectation is one resolved expectation.
type Expectation struct {
	After string
	Type  string
	// Match holds the resolved field values to match.
	Match    map[string]string
	Deadline time.Duration
	// ActionAt is when the step completed; zero if it never did.
	ActionAt time.Time
}

// Outcome is the result for one expectation.
type Outcome struct {
	After    string            `json:"after"`
	Type     string            `json:"event_type"`
	Status   string            `json:"status"`
	Match    map[string]string `json:"match"`
	Deadline float64           `json:"deadline_s"`
	// LatencyS is an upper bound on the time from the step completing to the
	// event being readable from the audit API.
	LatencyS *float64 `json:"latency_s"`
	EventID  string   `json:"event_id,omitempty"`
}

// Seen is a run event with the time the collector first saw it.
type Seen struct {
	provider.Event
	Phase     marker.Phase
	FirstSeen time.Time
}

// Result is the collector's output.
type Result struct {
	// Events are every event the run produced, in the order they were seen.
	Events   []Seen
	Outcomes []Outcome
	// Error is a persistent audit API failure or an interruption, if any.
	Error string
}

// Collector polls an audit source.
type Collector struct {
	Source provider.AuditSource
	Info   provider.AuditInfo
	Clock  clock.Clock
	// Skew widens the query window to tolerate clock differences between
	// this machine and the platform.
	Skew time.Duration
	// Trace receives per-event matching detail (-vv).
	Trace func(format string, a ...any)
}

func (c *Collector) trace(format string, a ...any) {
	if c.Trace != nil {
		c.Trace(format, a...)
	}
}

// Collect polls from since until every expectation is met or its deadline
// passes, and returns the run's events and an outcome per expectation.
//
// An event first seen after its deadline is late when an earlier successful
// poll, at or before the deadline, did not return it. When no poll happened
// in time (collection only starts after cleanup), the collector cannot know
// when the event became readable, so the platform's own event timestamp
// decides. If ctx is cancelled first, the expectations still pending are
// reported as not-run, not missing: they were never checked to the end.
func (c *Collector) Collect(ctx context.Context, run string, since time.Time, exps []Expectation) Result {
	res := Result{}
	outcomes := make([]Outcome, len(exps))
	pending := map[int]bool{}
	var last time.Time
	for i, e := range exps {
		outcomes[i] = Outcome{After: e.After, Type: e.Type, Match: e.Match, Deadline: e.Deadline.Seconds(), Status: StatusMissing}
		if e.ActionAt.IsZero() {
			outcomes[i].Status = StatusNotRun
			continue
		}
		pending[i] = true
		if d := e.ActionAt.Add(e.Deadline); d.After(last) {
			last = d
		}
	}
	seen := map[string]bool{}
	var pollErr error
	var firstPoll time.Time
	for len(pending) > 0 {
		if ctx.Err() != nil {
			break
		}
		now := c.Clock.Now()
		evs, err := c.Source.Poll(ctx, provider.AuditQuery{Since: since.Add(-c.Skew), Until: now.Add(c.Skew), Run: run})
		if err != nil {
			pollErr = err
			c.trace("audit poll failed: %v", err)
		} else {
			pollErr = nil
			if firstPoll.IsZero() {
				firstPoll = now
			}
		}
		for _, ev := range evs {
			if seen[ev.ID] {
				continue
			}
			ua, ok := marker.ParseUserAgent(ev.UserAgent)
			if !ok || ua.Run != run {
				continue // not this run's: another run, a person, the platform
			}
			seen[ev.ID] = true
			s := Seen{Event: ev, Phase: ua.Phase, FirstSeen: now}
			res.Events = append(res.Events, s)
			c.trace("event %s %s phase=%s", ev.ID, ev.Type, ua.Phase)
			if ua.Phase != marker.PhaseDetonate {
				continue
			}
			doc, err := Decode(ev.Raw)
			if err != nil {
				c.trace("event %s is not valid JSON; ignored", ev.ID)
				continue
			}
			for _, i := range sortedKeys(pending) {
				if !Matches(doc, exps[i].Match) {
					continue
				}
				lat := now.Sub(exps[i].ActionAt).Seconds()
				if lat < 0 {
					lat = 0
				}
				lat = roundTo(lat, 3)
				outcomes[i].LatencyS = &lat
				outcomes[i].EventID = ev.ID
				outcomes[i].Status = StatusObserved
				if deadline := exps[i].ActionAt.Add(exps[i].Deadline); now.After(deadline) {
					polledInTime := !firstPoll.IsZero() && !firstPoll.After(deadline)
					if polledInTime || ev.Time.IsZero() || ev.Time.After(deadline) {
						outcomes[i].Status = StatusLate
					}
				}
				c.trace("expect[%d] %s after %s: %s by %s (%.3fs)", i, exps[i].Type, exps[i].After, outcomes[i].Status, ev.ID, lat)
				delete(pending, i)
			}
		}
		if len(pending) == 0 || !now.Before(last) || ctx.Err() != nil {
			break
		}
		wait := c.Info.PollInterval
		if until := last.Sub(now); until < wait {
			wait = until
		}
		if err := c.Clock.Sleep(ctx, wait); err != nil {
			break
		}
	}
	if pollErr != nil {
		res.Error = pollErr.Error()
	}
	if err := ctx.Err(); err != nil && len(pending) > 0 {
		for i := range pending {
			outcomes[i].Status = StatusNotRun
		}
		res.Error = Interrupted + ": " + err.Error()
	}
	res.Outcomes = outcomes
	sort.SliceStable(res.Events, func(i, j int) bool { return res.Events[i].Time.Before(res.Events[j].Time) })
	return res
}

// Unsupported returns outcomes for a tier without an audit API.
func Unsupported(exps []Expectation) []Outcome {
	out := make([]Outcome, len(exps))
	for i, e := range exps {
		out[i] = Outcome{After: e.After, Type: e.Type, Match: e.Match, Deadline: e.Deadline.Seconds(), Status: StatusUnsupported}
		if e.ActionAt.IsZero() {
			out[i].Status = StatusNotRun
		}
	}
	return out
}

func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func roundTo(v float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	return float64(int64(v*p+0.5)) / p
}

// String renders an outcome for progress output.
func (o Outcome) String() string {
	if o.LatencyS != nil {
		return fmt.Sprintf("%s %s (%.1fs)", o.Type, o.Status, *o.LatencyS)
	}
	return fmt.Sprintf("%s %s", o.Type, o.Status)
}
