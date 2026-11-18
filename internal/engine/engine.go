// Package engine runs the core loop for one technique against one target:
// detonate with a write-ahead journal, clean up from that journal and prove
// every object gone, then collect the run's own audit events, match them
// against the expectations, run the detection checkers and build the result
// record.
//
// Cleanup reads the journal back from disk rather than trusting memory, so
// the cleanup that follows a normal detonation, the one after Ctrl-C and the
// one `saashound cleanup <run>` performs after a crash are the same code.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

// Point is a crash-injection point. The crash-injection tests kill the
// process at each one and prove the cleaner recovers.
type Point string

// Crash-injection points, in the order a step passes them.
const (
	// AfterIntent: the intent is durable; Do has not been called.
	AfterIntent Point = "after-intent"
	// AfterDo: Do returned (the object exists); the result is not written.
	AfterDo Point = "after-do"
	// AfterResult: the result is durable.
	AfterResult Point = "after-result"
	// AfterUndoCall: Undo returned (the object is gone); no undo record.
	AfterUndoCall Point = "after-undo-call"
	// AfterUndo: the undo record is durable; Gone has not been called.
	AfterUndo Point = "after-undo"
	// AfterGone: the gone record is durable.
	AfterGone Point = "after-gone"
)

// Points lists every crash-injection point.
var Points = []Point{AfterIntent, AfterDo, AfterResult, AfterUndoCall, AfterUndo, AfterGone}

// Event is a progress event for the stderr reporter.
type Event struct {
	Run string
	// Level is 0 for normal progress, 1 for -v detail, 2 for -vv.
	Level    int
	Stage    string
	Msg      string
	Duration time.Duration
	// Alarm marks something the operator must act on.
	Alarm bool
}

// Retry bounds the cleaner's retries.
type Retry struct {
	// Attempts per Locate or Undo call.
	Attempts int
	Backoff  time.Duration
	// GoneAttempts and GoneInterval bound polling for an eventually
	// consistent platform to stop returning a deleted object.
	GoneAttempts int
	GoneInterval time.Duration
}

// DefaultRetry is the retry policy for real runs.
func DefaultRetry() Retry {
	return Retry{Attempts: 3, Backoff: time.Second, GoneAttempts: 5, GoneInterval: time.Second}
}

// Engine runs techniques.
type Engine struct {
	Registry      *provider.Registry
	State         state.Dir
	Clock         clock.Clock
	Version       string
	CorpusVersion string
	Checkers      []detect.Checker
	Retry         Retry
	// Progress receives progress events; nil discards them.
	Progress func(Event)
	// Hook is called at every crash-injection point. Only the
	// crash-injection tests set it.
	Hook func(p Point, step string)
}

func (e *Engine) emit(ev Event) {
	if e.Progress != nil {
		e.Progress(ev)
	}
}

func (e *Engine) hook(p Point, step string) {
	if e.Hook != nil {
		e.Hook(p, step)
	}
}

func (e *Engine) ua(run string, phase marker.Phase) string {
	return marker.UserAgent(e.Version, run, phase)
}

// safely runs an op method, turning a panic into an error so that a bug in
// one op still ends in cleanup rather than a crash.
func safely(name string, f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s panicked: %v\n%s", name, r, debug.Stack())
		}
	}()
	return f()
}

// Apply runs one planned technique end to end and returns its record. ctx
// governs detonation and telemetry (the first Ctrl-C cancels it);
// cleanupCtx governs cleanup (the second Ctrl-C cancels it). Apply returns
// an error only for a failure before the first mutation, when nothing can
// have been created.
func (e *Engine) Apply(ctx, cleanupCtx context.Context, tgt *target.Target, tenant provider.Tenant, p *plan.Run) (*report.Record, error) {
	run := p.Run
	started := e.Clock.Now().UTC()
	if _, err := e.State.CreateRun(run); err != nil {
		return nil, err
	}
	pb, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	planPath, _ := e.State.File(run, state.PlanFile)
	if err := fsutil.WriteFileAtomic(planPath, append(pb, '\n')); err != nil {
		return nil, err
	}
	lock, err := e.State.LockRun(run)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()

	header := journal.Header{
		Run:             run,
		Technique:       p.Technique,
		TechniqueDigest: p.Digest,
		Corpus:          corpusLabel(p.Verified),
		Target:          p.Target,
		Platform:        p.Platform,
		Tenant:          p.Tenant,
		Principal:       p.Principal,
		Environment:     p.Environment,
		Ticket:          p.Ticket,
		Tool:            "saashound/" + e.Version,
		Started:         started,
	}
	for _, s := range p.Steps {
		header.Steps = append(header.Steps, journal.HeaderStep{ID: s.ID, Op: s.Op, Kind: s.Kind, Name: s.Name})
	}
	for _, c := range p.Cleanup {
		header.Cleanup = append(header.Cleanup, c.Step)
	}
	jpath, _ := e.State.File(run, state.JournalFile)
	w, err := journal.Create(jpath, header, e.Clock)
	if err != nil {
		return nil, err
	}

	e.emit(Event{Run: run, Stage: "run", Msg: fmt.Sprintf("%s -> %s (%s)", p.Technique, p.Target, p.Environment)})
	det := e.detonate(ctx, w, tgt, tenant, p)
	if err := w.Close(); err != nil {
		e.emit(Event{Run: run, Level: 1, Stage: "journal", Msg: "close: " + err.Error()})
	}

	cl, err := e.Cleanup(cleanupCtx, run, tgt, tenant, "apply")
	if err != nil {
		// The journal could not even be re-read: nothing is proven.
		cl = &CleanupResult{Status: CleanupError, Error: err.Error()}
	}

	rec := &report.Record{
		Schema:        report.Schema,
		Version:       report.Version,
		Run:           run,
		Technique:     p.Technique,
		Corpus:        corpusLabel(p.Verified),
		CorpusVersion: e.CorpusVersion,
		Target:        p.Target,
		Platform:      p.Platform,
		Environment:   p.Environment,
		Tool:          "saashound/" + e.Version,
		Started:       started,
		Detonate:      det.summary(),
		Cleanup:       cl.summary(run),
		Detections:    []detect.Result{},
	}
	if p.Ticket != "" {
		t := p.Ticket
		rec.Ticket = &t
	}

	// Telemetry is collected only after cleanup: audit events outlive the
	// objects they describe, and nothing should stay open during log lag.
	exps, err := e.expectations(jpath, p)
	switch {
	case err != nil:
		rec.Telemetry = e.notCollected(p, unresolved(p), "resolve expectations: "+err.Error())
	case cl.Status == CleanupAbandoned || det.Status == report.DetonateInterrupted:
		rec.Telemetry = e.telemetryRecord(p, notRun(exps), "")
	case ctx.Err() != nil:
		// Interrupted during cleanup: the run is over, nothing was read.
		rec.Telemetry = e.notCollected(p, exps, telemetry.Interrupted+" before it started: "+ctx.Err().Error())
	default:
		rec.Telemetry, rec.Detections = e.observe(ctx, tenant, p, header.Started, exps)
	}
	rec.Finished = e.Clock.Now().UTC()
	rec.Decide()

	if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
		rp, _ := e.State.File(run, state.ResultFile)
		if err := fsutil.WriteFileAtomic(rp, append(b, '\n')); err != nil {
			e.emit(Event{Run: run, Level: 1, Stage: "result", Msg: "write result.json: " + err.Error()})
		}
	}
	if cl.Status != CleanupAbandoned {
		if w, _, err := journal.OpenAppend(jpath, e.Clock); err == nil {
			_ = w.Append(journal.Record{Kind: journal.KindPhase, Phase: journal.PhaseComplete, By: "apply"})
			_ = w.Close()
		}
	}
	return rec, nil
}

func corpusLabel(verified bool) string {
	if verified {
		return "verified"
	}
	return "unverified"
}

// Detonation is what the executor did.
type Detonation struct {
	Status     string
	Steps      int
	Completed  int
	FailedStep string
	Error      string
}

func (d Detonation) summary() report.Detonate {
	return report.Detonate{Status: d.Status, Steps: d.Steps, Completed: d.Completed, FailedStep: d.FailedStep, Error: d.Error}
}

// detonate executes the plan's steps in order. Every step writes and fsyncs
// its intent before the op runs and its result after; any error stops
// detonation and hands over to cleanup.
func (e *Engine) detonate(ctx context.Context, w *journal.Writer, tgt *target.Target, tenant provider.Tenant, p *plan.Run) Detonation {
	run := p.Run
	start := e.Clock.Now()
	det := Detonation{Status: report.DetonateOK, Steps: len(p.Steps)}
	env := templateEnv(run, tgt)
	info := tgt.Info()
	dctx := provider.WithUserAgent(ctx, e.ua(run, marker.PhaseDetonate))

	fail := func(step string, err error) {
		det.FailedStep = step
		det.Error = err.Error()
		det.Status = report.DetonateFailed
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			det.Status = report.DetonateInterrupted
		}
	}
	for i, s := range p.Steps {
		if err := ctx.Err(); err != nil {
			fail(s.ID, err)
			break
		}
		entry, ok := e.Registry.Op(s.Op)
		if !ok {
			fail(s.ID, fmt.Errorf("op %s is not registered in this binary", s.Op))
			break
		}
		params, err := resolveParams(s.With, env)
		if err != nil {
			fail(s.ID, err)
			break
		}
		call := &provider.Call{Run: run, Step: s.ID, Name: s.Name, Params: params, Target: info, Tenant: tenant}

		// A modify op's prior value goes into the intent, before anything
		// changes, so even a crash mid-call can be undone exactly.
		var prior json.RawMessage
		if entry.Prior != nil {
			err := safely(s.Op+".Prior", func() error {
				var perr error
				prior, perr = entry.Prior.Prior(dctx, call)
				return perr
			})
			if err == nil && len(prior) == 0 {
				err = fmt.Errorf("%s returned no prior value", s.Op)
			}
			if err != nil {
				fail(s.ID, fmt.Errorf("read prior value: %w", err))
				break
			}
		}
		if err := w.Append(journal.Record{Kind: journal.KindIntent, Step: s.ID, Op: s.Op, Name: s.Name, Params: params, Prior: prior, By: "apply"}); err != nil {
			fail(s.ID, err)
			break
		}
		e.hook(AfterIntent, s.ID)

		t0 := e.Clock.Now()
		var res provider.Result
		err = safely(s.Op+".Do", func() error {
			var derr error
			res, derr = entry.Op.Do(dctx, call)
			return derr
		})
		e.hook(AfterDo, s.ID)
		if err == nil {
			err = checkResult(entry.Spec, res)
		}
		if err != nil {
			_ = w.Append(journal.Record{Kind: journal.KindError, Step: s.ID, Op: s.Op, Error: err.Error(), By: "apply"})
			e.emit(Event{Run: run, Level: 1, Stage: "detonate", Msg: fmt.Sprintf("step %d/%d %s %s failed: %v", i+1, len(p.Steps), s.ID, s.Op, err)})
			fail(s.ID, err)
			break
		}
		if err := w.Append(journal.Record{Kind: journal.KindResult, Step: s.ID, Op: s.Op, ID: res.ID, Outputs: res.Outputs, By: "apply"}); err != nil {
			fail(s.ID, err)
			break
		}
		e.hook(AfterResult, s.ID)
		det.Completed++
		outs := map[string]string{"id": res.ID, "name": s.Name}
		for k, v := range res.Outputs {
			outs[k] = v
		}
		env.Steps[s.ID] = outs
		e.emit(Event{Run: run, Level: 1, Stage: "detonate", Msg: fmt.Sprintf("step %d/%d %s %s -> %s (%s)", i+1, len(p.Steps), s.ID, s.Op, res.ID, s.Name), Duration: e.Clock.Now().Sub(t0)})
	}

	phase := journal.PhaseDetonateDone
	switch det.Status {
	case report.DetonateFailed:
		phase = journal.PhaseDetonateFailed
	case report.DetonateInterrupted:
		phase = journal.PhaseDetonateAborted
	}
	_ = w.Append(journal.Record{Kind: journal.KindPhase, Phase: phase, By: "apply"})

	msg := fmt.Sprintf("%d/%d steps ok", det.Completed, det.Steps)
	if det.Status != report.DetonateOK {
		msg = fmt.Sprintf("%s at step %s (%d/%d done): %s", det.Status, det.FailedStep, det.Completed, det.Steps, det.Error)
	}
	e.emit(Event{Run: run, Stage: "detonate", Msg: msg, Duration: e.Clock.Now().Sub(start), Alarm: det.Status != report.DetonateOK})
	return det
}

// checkResult rejects a result that would leave the journal unable to undo
// the step or that carries undeclared (possibly secret) outputs.
func checkResult(spec provider.Spec, res provider.Result) error {
	if res.ID == "" {
		return fmt.Errorf("%s returned no resource id", spec.Name)
	}
	for k := range res.Outputs {
		if !spec.HasOutput(k) {
			return fmt.Errorf("%s returned undeclared output %q", spec.Name, k)
		}
	}
	return nil
}

func templateEnv(run string, tgt *target.Target) technique.Env {
	return technique.Env{
		Run:    map[string]string{"id": run, "prefix": marker.RunPrefix(run)},
		Target: map[string]string{"name": tgt.Name, "test_domain": tgt.TestDomain},
		Steps:  map[string]map[string]string{},
	}
}

func resolveParams(with map[string]string, env technique.Env) (map[string]string, error) {
	out := make(map[string]string, len(with))
	for k, v := range with {
		tmpl, err := technique.ParseTemplate(v)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w", k, err)
		}
		s, err := tmpl.Resolve(env)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w", k, err)
		}
		out[k] = s
	}
	return out, nil
}
