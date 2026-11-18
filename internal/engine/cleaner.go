package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/target"
)

// Cleanup statuses.
const (
	CleanupVerified   = "verified"
	CleanupUnverified = "unverified"
	CleanupAbandoned  = "abandoned"
	CleanupError      = "error"
)

// CleanupResult is what the cleaner did.
type CleanupResult struct {
	Status   string
	Steps    []StepOutcome
	Objects  int
	Duration time.Duration
	Error    string
}

// StepOutcome is the cleaner's result for one step.
type StepOutcome struct {
	Step     string `json:"step"`
	Op       string `json:"op"`
	Name     string `json:"name"`
	ID       string `json:"id,omitempty"`
	Outcome  string `json:"outcome"`
	Verified bool   `json:"verified"`
	// Located is true when the journal had no ID and the object was found
	// by its exact deterministic name.
	Located bool   `json:"located,omitempty"`
	Skipped bool   `json:"skipped,omitempty"` // already verified by an earlier cleanup
	Error   string `json:"error,omitempty"`
}

// Verified reports whether every started step is proven undone.
func (c *CleanupResult) Verified() bool { return c.Status == CleanupVerified }

func (c *CleanupResult) summary(run string) report.Cleanup {
	out := report.Cleanup{Objects: c.Objects, Orphans: []report.Orphan{}}
	switch c.Status {
	case CleanupVerified:
		out.Status = report.CleanupVerified
	default:
		out.Status = report.CleanupUnverified
		out.Retry = "saashound cleanup " + run
	}
	for _, s := range c.Steps {
		if !s.Verified {
			out.Orphans = append(out.Orphans, report.Orphan{Step: s.Step, Op: s.Op, Name: s.Name, ID: s.ID, Error: s.Error})
		}
	}
	if c.Status == CleanupError && len(out.Orphans) == 0 {
		out.Orphans = append(out.Orphans, report.Orphan{Error: c.Error})
	}
	return out
}

// Cleanup undoes a run from its journal: in the declared (reverse) order,
// for every step whose intent was written and which is not yet proven
// undone, call Undo (an already-gone object counts as success) and then
// require Gone. A step with an intent but no recorded ID is found by its
// exact deterministic name. Every action is journalled, so Cleanup is
// idempotent and resumable: running it again skips what is proven and
// retries the rest.
//
// The caller must hold the target lock and have checked that tenant is the
// tenant the run was against; Cleanup checks the target entry matches the
// journal.
func (e *Engine) Cleanup(ctx context.Context, run string, tgt *target.Target, tenant provider.Tenant, by string) (*CleanupResult, error) {
	start := e.Clock.Now()
	jpath, err := e.State.File(run, state.JournalFile)
	if err != nil {
		return nil, err
	}
	w, j, err := journal.OpenAppend(jpath, e.Clock)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if j.TornBytes > 0 {
		e.emit(Event{Run: run, Level: 1, Stage: "cleanup", Msg: fmt.Sprintf("journal had a torn final record (%d bytes) from a crash; repaired", j.TornBytes)})
	}
	h := j.Header
	if h.Target != tgt.Name || h.Tenant != tgt.Tenant || h.Platform != tgt.Platform {
		return nil, fmt.Errorf("run %s was against %s/%s (%s), not target %s/%s", run, h.Target, h.Tenant, h.Platform, tgt.Name, tgt.Tenant)
	}
	cctx := provider.WithUserAgent(ctx, e.ua(run, marker.PhaseCleanup))
	info := tgt.Info()
	res := &CleanupResult{Status: CleanupVerified}

	byID := map[string]*journal.StepState{}
	for _, s := range j.Steps() {
		byID[s.ID] = s
	}
	order := h.Cleanup
	if len(order) == 0 {
		for i := len(h.Steps) - 1; i >= 0; i-- {
			order = append(order, h.Steps[i].ID)
		}
	}
	for _, id := range order {
		s, ok := byID[id]
		if !ok || !s.Started() {
			continue // never begun: nothing can exist
		}
		if s.Verified() {
			res.Objects++
			res.Steps = append(res.Steps, StepOutcome{Step: s.ID, Op: s.Op, Name: s.Name, ID: s.Gone.ID, Outcome: "verified earlier", Verified: true, Skipped: true})
			continue
		}
		if ctx.Err() != nil {
			res.Status = CleanupAbandoned
			res.Steps = append(res.Steps, StepOutcome{Step: s.ID, Op: s.Op, Name: s.Name, Outcome: "abandoned", Error: "cleanup abandoned"})
			continue
		}
		out := e.cleanStep(ctx, cctx, w, run, s, info, tenant, by)
		res.Steps = append(res.Steps, out)
		if out.Verified {
			res.Objects++
		} else if res.Status == CleanupVerified {
			res.Status = CleanupUnverified
		}
		if ctx.Err() != nil && !out.Verified {
			res.Status = CleanupAbandoned
		}
	}

	phase := journal.PhaseCleanupVerified
	switch res.Status {
	case CleanupUnverified:
		phase = journal.PhaseCleanupFailed
	case CleanupAbandoned:
		phase = journal.PhaseCleanupAbandoned
	}
	_ = w.Append(journal.Record{Kind: journal.KindPhase, Phase: phase, By: by})
	res.Duration = e.Clock.Now().Sub(start)
	e.emitCleanup(run, res)
	return res, nil
}

func (e *Engine) emitCleanup(run string, res *CleanupResult) {
	for _, s := range res.Steps {
		if s.Skipped {
			continue
		}
		msg := fmt.Sprintf("step %s %s: %s", s.Step, s.Op, s.Outcome)
		if s.Outcome == "" {
			msg = fmt.Sprintf("step %s %s:", s.Step, s.Op)
		}
		if s.Located {
			msg = fmt.Sprintf("step %s %s: no recorded id; found exact name %q -> %s", s.Step, s.Op, s.Name, s.Outcome)
		}
		if s.Verified {
			msg += " -> verified gone"
		} else {
			msg += " -> NOT verified: " + s.Error
		}
		e.emit(Event{Run: run, Level: 1, Stage: "cleanup", Msg: msg, Alarm: !s.Verified})
	}
	var msg string
	switch res.Status {
	case CleanupVerified:
		msg = fmt.Sprintf("%d %s undone, verified gone", res.Objects, plural(res.Objects, "object", "objects"))
	case CleanupAbandoned:
		msg = fmt.Sprintf("cleanup abandoned. Resume with:  saashound cleanup %s", run)
	default:
		n := 0
		for _, s := range res.Steps {
			if !s.Verified {
				n++
			}
		}
		msg = fmt.Sprintf("%d %s NOT verified gone. Retry with:  saashound cleanup %s", n, plural(n, "object", "objects"), run)
	}
	e.emit(Event{Run: run, Stage: "cleanup", Msg: msg, Duration: res.Duration, Alarm: res.Status != CleanupVerified})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// cleanStep undoes one step and proves it, journalling each action.
func (e *Engine) cleanStep(ctx, cctx context.Context, w *journal.Writer, run string, s *journal.StepState, info provider.TargetInfo, tenant provider.Tenant, by string) StepOutcome {
	out := StepOutcome{Step: s.ID, Op: s.Op, Name: s.Name}
	failed := func(err error) StepOutcome {
		out.Error = err.Error()
		_ = w.Append(journal.Record{Kind: journal.KindGone, Step: s.ID, Op: s.Op, ID: out.ID, Verified: journal.Bool(false), Error: out.Error, By: by})
		return out
	}
	entry, ok := e.Registry.Op(s.Op)
	if !ok {
		return failed(fmt.Errorf("op %s is not registered in this binary", s.Op))
	}
	call := &provider.Call{Run: run, Step: s.ID, Name: s.Intent.Name, Params: s.Intent.Params, Target: info, Tenant: tenant}
	rec := provider.Record{Prior: s.Intent.Prior}
	if s.Result != nil {
		rec.ID, rec.Outputs = s.Result.ID, s.Result.Outputs
	} else if s.Undo != nil && s.Undo.ID != "" {
		rec.ID = s.Undo.ID // located by an earlier cleanup attempt
	}
	out.ID = rec.ID

	switch entry.Spec.Kind {
	case provider.KindModify:
		if len(rec.Prior) == 0 {
			return failed(errors.New("the journal holds no prior value to restore"))
		}
	case provider.KindCreate:
		if rec.ID == "" {
			// Intent without result: the process died mid-call or Do
			// failed. Look the object up by its exact deterministic name.
			var (
				found bool
				lres  provider.Result
			)
			err := e.retry(ctx, func() error {
				return safely(s.Op+".Locate", func() error {
					var lerr error
					lres, found, lerr = entry.Locate.Locate(cctx, call)
					return lerr
				})
			})
			if err != nil {
				return failed(fmt.Errorf("look up %q: %w", call.Name, err))
			}
			if !found {
				out.Outcome = journal.OutcomeAbsent
				out.Verified = true
				_ = w.Append(journal.Record{Kind: journal.KindUndo, Step: s.ID, Op: s.Op, Outcome: out.Outcome, By: by})
				e.hook(AfterUndo, s.ID)
				_ = w.Append(journal.Record{Kind: journal.KindGone, Step: s.ID, Op: s.Op, Verified: journal.Bool(true), By: by})
				e.hook(AfterGone, s.ID)
				return out
			}
			rec.ID, rec.Outputs = lres.ID, lres.Outputs
			out.ID, out.Located = lres.ID, true
		}
	}

	outcome := journal.OutcomeRemoved
	if entry.Spec.Kind == provider.KindModify {
		outcome = journal.OutcomeRestored
	}
	err := e.retry(ctx, func() error {
		uerr := safely(s.Op+".Undo", func() error { return entry.Undo.Undo(cctx, call, rec) })
		if errors.Is(uerr, provider.ErrNotFound) {
			outcome = journal.OutcomeAlreadyGone
			return nil
		}
		return uerr
	})
	e.hook(AfterUndoCall, s.ID)
	if err != nil {
		_ = w.Append(journal.Record{Kind: journal.KindUndo, Step: s.ID, Op: s.Op, ID: rec.ID, Outcome: journal.OutcomeFailed, Error: err.Error(), By: by})
		return failed(fmt.Errorf("undo: %w", err))
	}
	out.Outcome = outcome
	if err := w.Append(journal.Record{Kind: journal.KindUndo, Step: s.ID, Op: s.Op, ID: rec.ID, Outcome: outcome, By: by}); err != nil {
		return failed(err)
	}
	e.hook(AfterUndo, s.ID)

	gone, err := e.proveGone(ctx, func() (bool, error) {
		var g bool
		gerr := safely(s.Op+".Gone", func() error {
			var e2 error
			g, e2 = entry.Gone.Gone(cctx, call, rec)
			return e2
		})
		return g, gerr
	})
	if err != nil {
		return failed(fmt.Errorf("gone check: %w", err))
	}
	if !gone {
		return failed(errors.New("the object still exists after undo"))
	}
	out.Verified = true
	if err := w.Append(journal.Record{Kind: journal.KindGone, Step: s.ID, Op: s.Op, ID: rec.ID, Verified: journal.Bool(true), By: by}); err != nil {
		out.Verified = false
		out.Error = err.Error()
		return out
	}
	e.hook(AfterGone, s.ID)
	return out
}

func (e *Engine) retry(ctx context.Context, f func() error) error {
	attempts := max(e.Retry.Attempts, 1)
	var err error
	for i := 0; i < attempts; i++ {
		if err = f(); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return err
		}
		if i < attempts-1 {
			if serr := e.Clock.Sleep(ctx, e.Retry.Backoff*time.Duration(i+1)); serr != nil {
				return err
			}
		}
	}
	return err
}

// proveGone polls Gone until it is true, tolerating an eventually
// consistent platform briefly still returning a deleted object.
func (e *Engine) proveGone(ctx context.Context, f func() (bool, error)) (bool, error) {
	attempts := max(e.Retry.GoneAttempts, 1)
	var (
		gone bool
		err  error
	)
	for i := 0; i < attempts; i++ {
		gone, err = f()
		if err == nil && gone {
			return true, nil
		}
		if ctx.Err() != nil {
			break
		}
		if i < attempts-1 {
			if serr := e.Clock.Sleep(ctx, e.Retry.GoneInterval); serr != nil {
				break
			}
		}
	}
	return gone, err
}

// RemoveOrphan removes one object Sweep found, with the op that creates
// that kind of object: Undo, then Gone must hold.
func (e *Engine) RemoveOrphan(ctx context.Context, tgt *target.Target, tenant provider.Tenant, o provider.Orphan) StepOutcome {
	run, step, _ := marker.ParseObjectName(o.Name)
	out := StepOutcome{Step: step, Op: o.Op, Name: o.Name, ID: o.Record.ID}
	entry, ok := e.Registry.Op(o.Op)
	if !ok || entry.Spec.Kind != provider.KindCreate {
		out.Error = fmt.Sprintf("op %s cannot remove this object", o.Op)
		return out
	}
	sctx := provider.WithUserAgent(ctx, e.ua(run, marker.PhaseSweep))
	call := &provider.Call{Run: run, Step: step, Name: o.Name, Params: o.Params, Target: tgt.Info(), Tenant: tenant}
	out.Outcome = journal.OutcomeRemoved
	err := e.retry(ctx, func() error {
		uerr := safely(o.Op+".Undo", func() error { return entry.Undo.Undo(sctx, call, o.Record) })
		if errors.Is(uerr, provider.ErrNotFound) {
			out.Outcome = journal.OutcomeAlreadyGone
			return nil
		}
		return uerr
	})
	if err != nil {
		out.Outcome, out.Error = journal.OutcomeFailed, err.Error()
		return out
	}
	gone, err := e.proveGone(ctx, func() (bool, error) {
		var g bool
		gerr := safely(o.Op+".Gone", func() error {
			var e2 error
			g, e2 = entry.Gone.Gone(sctx, call, o.Record)
			return e2
		})
		return g, gerr
	})
	switch {
	case err != nil:
		out.Error = err.Error()
	case !gone:
		out.Error = "the object still exists after removal"
	default:
		out.Verified = true
	}
	return out
}
