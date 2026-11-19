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

// Unsettled says why a drain ended while Await still reported a detection
// waiting without the audit log having been read to the drain's end, so a
// "did not fire" judged over the collected events is unproven.
type Unsettled string

const (
	// Settled: there was no drain, it ended because nothing was waiting any
	// more, or it spent its polls and the last one read the audit log.
	Settled Unsettled = ""
	// UnsettledInterrupted: collection was cancelled during the drain.
	UnsettledInterrupted Unsettled = "interrupted"
	// UnsettledAuditFailure: the drain spent its polls and the last one
	// failed. Every poll re-reads the whole window, so a successful poll
	// covers the failed ones before it, but nothing covers a failed last
	// one.
	UnsettledAuditFailure Unsettled = "audit-failure"
)

// DrainPolls bounds the drain (see Collector.Await): once every expectation
// is resolved, the collector polls at most this many more times, one poll
// interval apart, so it can never extend a run by more than DrainPolls poll
// intervals.
const DrainPolls = 5

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
	// The drain never sets it: by then every expectation is resolved.
	Error string
	// Unsettled is not Settled when the drain ended, by an interruption or
	// with a failed last poll, while Await still reported a detection
	// waiting for an event, so a "did not fire" judged over Events is
	// unproven.
	Unsettled Unsettled
	// DrainError is the error of the drain's last poll when Unsettled is
	// UnsettledAuditFailure. It is never a telemetry error: the
	// expectations were resolved before the drain started.
	DrainError string
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
	// Await, if set, extends collection for the detection checkers. A rule
	// may key on an event no expectation asked for, which can land after the
	// expected ones; stopping the moment the expectations are resolved would
	// leave the rule to judge an event set without it. So once every
	// expectation is resolved, the collector keeps polling, at most
	// DrainPolls more times and one poll interval apart, for as long as
	// Await reports that the events seen so far still leave a detection
	// waiting. The drain only widens Events: outcomes are final before it
	// starts. A drain that is interrupted, or whose last poll fails, while
	// Await still reports a detection waiting is recorded in
	// Result.Unsettled. Nil stops collection as soon as the expectations
	// are resolved.
	Await func(events []Seen) bool
}

func (c *Collector) trace(format string, a ...any) {
	if c.Trace != nil {
		c.Trace(format, a...)
	}
}

// Collect polls from since until every expectation is met or its deadline
// passes, then drains for the detection checkers (see Await), and returns
// the run's events and an outcome per expectation.
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
	// The drain follows only a collection that checked every expectation.
	checkedAll := len(exps) > 0 && len(pending) == len(exps)
	seen := map[string]bool{}
	var firstPoll time.Time

	// poll reads the audit log once, keeps the run's events it has not seen
	// before and resolves the pending expectations they match. It returns
	// how many new run events it kept, and the poll's error.
	poll := func(now time.Time) (int, error) {
		evs, err := c.Source.Poll(ctx, provider.AuditQuery{Since: since.Add(-c.Skew), Until: now.Add(c.Skew), Run: run})
		if err != nil {
			c.trace("audit poll failed: %v", err)
		} else if firstPoll.IsZero() {
			firstPoll = now
		}
		kept := 0
		for _, ev := range evs {
			if seen[ev.ID] {
				continue
			}
			ua, ok := marker.ParseUserAgent(ev.UserAgent)
			if !ok || ua.Run != run {
				continue // not this run's: another run, a person, the platform
			}
			seen[ev.ID] = true
			kept++
			s := Seen{Event: ev, Phase: ua.Phase, FirstSeen: now}
			res.Events = append(res.Events, s)
			c.trace("event %s %s phase=%s", ev.ID, ev.Type, ua.Phase)
			if ua.Phase != marker.PhaseDetonate || len(pending) == 0 {
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
		return kept, err
	}

	var pollErr error
	for len(pending) > 0 {
		if ctx.Err() != nil {
			break
		}
		now := c.Clock.Now()
		_, pollErr = poll(now)
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
	if checkedAll && len(pending) == 0 {
		c.drain(ctx, &res, poll)
	}
	res.Outcomes = outcomes
	sort.SliceStable(res.Events, func(i, j int) bool { return res.Events[i].Time.Before(res.Events[j].Time) })
	return res
}

// drain is the post-expectation drain (see Await). It follows only a
// collection that saw every expectation's event: when one is missing or
// not-run the verdict cannot reach the detections (and for a missing one
// the main loop has already polled up to the last deadline). A failed
// drain poll is traced and retried on the next one, and never becomes
// Result.Error, since every expectation is already resolved. Every poll
// re-reads the whole window, so a successful poll covers the failed ones
// before it. An interruption while a detection is still waiting, or a
// spent drain whose last poll failed, sets Result.Unsettled.
func (c *Collector) drain(ctx context.Context, res *Result, poll func(time.Time) (int, error)) {
	if c.Await == nil || !c.Await(res.Events) {
		return
	}
	c.trace("expectations resolved, a detection is still waiting: draining for up to %d more polls", DrainPolls)
	var lastErr error
	for n := 1; n <= DrainPolls; n++ {
		if c.Clock.Sleep(ctx, c.Info.PollInterval) != nil || ctx.Err() != nil {
			c.trace("drain interrupted after %d of %d polls, a detection still waiting", n-1, DrainPolls)
			res.Unsettled = UnsettledInterrupted
			return
		}
		kept, err := poll(c.Clock.Now())
		lastErr = err
		// A rule that fired stays fired, so a fire is final even if the
		// poll was the last thing before an interrupt.
		if kept > 0 && !c.Await(res.Events) {
			c.trace("drain: no detection waiting after %d of %d polls", n, DrainPolls)
			return
		}
		if ctx.Err() != nil {
			c.trace("drain interrupted at poll %d of %d, a detection still waiting", n, DrainPolls)
			res.Unsettled = UnsettledInterrupted
			return
		}
	}
	if lastErr != nil {
		c.trace("drain: %d polls spent and the last one failed, a detection still waiting", DrainPolls)
		res.Unsettled = UnsettledAuditFailure
		res.DrainError = lastErr.Error()
		return
	}
	c.trace("drain: %d polls spent, a detection still waiting", DrainPolls)
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
