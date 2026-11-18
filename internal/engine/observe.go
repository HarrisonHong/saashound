package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

// AuditSkew widens audit queries to tolerate clock differences.
const AuditSkew = time.Minute

// expectations resolves the plan's expectations from the journal: the step
// outputs fill the match templates and each result's timestamp is the time
// latency is measured from.
func (e *Engine) expectations(jpath string, p *plan.Run) ([]telemetry.Expectation, error) {
	j, err := journal.Load(jpath)
	if err != nil {
		return nil, err
	}
	env := technique.Env{
		Run:    map[string]string{"id": p.Run, "prefix": marker.RunPrefix(p.Run)},
		Target: map[string]string{"name": p.Target, "test_domain": p.TestDomain},
		Steps:  map[string]map[string]string{},
	}
	done := map[string]time.Time{}
	for _, s := range j.Steps() {
		if s.Result == nil {
			continue
		}
		outs := map[string]string{"id": s.Result.ID, "name": s.Name}
		for k, v := range s.Result.Outputs {
			outs[k] = v
		}
		env.Steps[s.ID] = outs
		done[s.ID] = s.Result.Time
	}
	out := make([]telemetry.Expectation, 0, len(p.Expect))
	for _, x := range p.Expect {
		exp := telemetry.Expectation{After: x.After, Type: x.Type, Deadline: time.Duration(x.Deadline), Match: map[string]string{}}
		at, ran := done[x.After]
		resolved := ran
		for k, v := range x.Match {
			exp.Match[k] = v
			if !ran {
				continue
			}
			tmpl, err := technique.ParseTemplate(v)
			if err != nil {
				return nil, err
			}
			s, err := tmpl.Resolve(env)
			if err != nil {
				resolved = false
				continue
			}
			exp.Match[k] = s
		}
		if resolved {
			exp.ActionAt = at
		}
		out = append(out, exp)
	}
	return out, nil
}

// unresolved lists the plan's expectations with nothing filled in, for a
// run whose journal could not be read back.
func unresolved(p *plan.Run) []telemetry.Expectation {
	out := make([]telemetry.Expectation, 0, len(p.Expect))
	for _, x := range p.Expect {
		exp := telemetry.Expectation{After: x.After, Type: x.Type, Deadline: time.Duration(x.Deadline), Match: map[string]string{}}
		for k, v := range x.Match {
			exp.Match[k] = v
		}
		out = append(out, exp)
	}
	return out
}

// notCollected is the telemetry record for a run whose audit log was never
// read, or not read to the end. Its expectations are not-run and the reason
// is in the record's error, so the verdict cannot be pass.
func (e *Engine) notCollected(p *plan.Run, exps []telemetry.Expectation, reason string) report.Telemetry {
	e.emit(Event{Run: p.Run, Stage: "telemetry", Msg: "not collected: " + reason, Alarm: true})
	return e.telemetryRecord(p, notRun(exps), reason)
}

func notRun(exps []telemetry.Expectation) []telemetry.Outcome {
	out := make([]telemetry.Outcome, len(exps))
	for i, x := range exps {
		out[i] = telemetry.Outcome{After: x.After, Type: x.Type, Match: x.Match, Deadline: x.Deadline.Seconds(), Status: telemetry.StatusNotRun}
	}
	return out
}

func (e *Engine) eventsFile(run string) string {
	return path.Join("runs", run, state.EventsFile)
}

func (e *Engine) telemetryRecord(p *plan.Run, outcomes []telemetry.Outcome, errMsg string) report.Telemetry {
	src := ""
	if len(p.Expect) > 0 {
		src = p.Expect[0].Source
	}
	t := report.Telemetry{Source: src, EventsFile: e.eventsFile(p.Run), Expectations: outcomes, Error: errMsg}
	if t.Expectations == nil {
		t.Expectations = []telemetry.Outcome{}
	}
	t.Summarize()
	return t
}

// observe collects the run's audit events, matches the expectations and
// runs the detection checkers. Its own requests carry the run's
// collect-phase User-Agent, so the audit-log reads are attributable too.
func (e *Engine) observe(ctx context.Context, tenant provider.Tenant, p *plan.Run, since time.Time, exps []telemetry.Expectation) (report.Telemetry, []detect.Result) {
	run := p.Run
	start := e.Clock.Now()
	detections := []detect.Result{}
	prov, ok := e.Registry.Provider(p.Platform)
	if !ok {
		return e.notCollected(p, exps, "no provider for "+p.Platform), detections
	}
	cctx := provider.WithUserAgent(ctx, e.ua(run, marker.PhaseCollect))
	caps, err := tenant.Capabilities(cctx)
	if err != nil {
		if ctx.Err() != nil {
			return e.notCollected(p, exps, telemetry.Interrupted+": "+err.Error()), detections
		}
		return e.notCollected(p, exps, "capabilities: "+err.Error()), detections
	}
	if !caps.Audit {
		e.emit(Event{Run: run, Stage: "telemetry", Msg: "unsupported on this tier: " + caps.Note})
		return e.telemetryRecord(p, telemetry.Unsupported(exps), ""), detections
	}
	e.emit(Event{Run: run, Level: 1, Stage: "telemetry", Msg: fmt.Sprintf("polling %s for %d expected events", prov.Audit().Name, len(exps))})
	col := &telemetry.Collector{
		Source: tenant.AuditSource(),
		Info:   prov.Audit(),
		Clock:  e.Clock,
		Skew:   AuditSkew,
		Trace: func(format string, a ...any) {
			e.emit(Event{Run: run, Level: 2, Stage: "telemetry", Msg: fmt.Sprintf(format, a...)})
		},
	}
	res := col.Collect(cctx, run, since, exps)
	if err := e.writeEvents(run, res.Events); err != nil {
		e.emit(Event{Run: run, Stage: "telemetry", Msg: "write events.jsonl: " + err.Error(), Alarm: true})
	}
	tel := e.telemetryRecord(p, res.Outcomes, res.Error)
	e.emitTelemetry(run, tel, e.Clock.Now().Sub(start))

	for _, c := range e.Checkers {
		rs, err := c.Check(ctx, detect.Input{
			Run: run, Technique: p.Technique, Platform: p.Platform, Mappings: p.Detections,
			Events: res.Events, WindowStart: since, WindowEnd: e.Clock.Now(),
		})
		if err != nil {
			detections = append(detections, detect.Result{Checker: c.Name(), Error: err.Error()})
			continue
		}
		detections = append(detections, rs...)
	}
	return tel, detections
}

func (e *Engine) emitTelemetry(run string, t report.Telemetry, d time.Duration) {
	msg := fmt.Sprintf("%d/%d expected events observed", t.Observed, t.Expected)
	if t.MaxLatencyS != nil {
		msg += fmt.Sprintf(", max latency %.1fs", *t.MaxLatencyS)
	}
	var problems []string
	for _, o := range t.Expectations {
		if o.Status == telemetry.StatusMissing || o.Status == telemetry.StatusLate {
			problems = append(problems, fmt.Sprintf("%s %s after %s", o.Type, o.Status, o.After))
		}
	}
	if len(problems) > 0 {
		msg += "; " + strings.Join(problems, ", ")
	}
	switch {
	case strings.HasPrefix(t.Error, telemetry.Interrupted):
		msg += "; " + t.Error
	case t.Error != "":
		msg += "; audit API error: " + t.Error
	}
	e.emit(Event{Run: run, Stage: "telemetry", Msg: msg, Alarm: len(problems) > 0 || t.Unchecked()})
	e.emit(Event{Run: run, Level: 1, Stage: "telemetry", Msg: "collection finished", Duration: d})
}

// writeEvents stores the run's raw events verbatim, one per line.
func (e *Engine) writeEvents(run string, evs []telemetry.Seen) error {
	var buf bytes.Buffer
	for _, ev := range evs {
		var compact bytes.Buffer
		if err := jsonCompact(&compact, ev.Raw); err != nil {
			continue
		}
		buf.Write(compact.Bytes())
		buf.WriteByte('\n')
	}
	p, err := e.State.File(run, state.EventsFile)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, buf.Bytes())
}

func jsonCompact(dst *bytes.Buffer, src []byte) error { return json.Compact(dst, src) }
