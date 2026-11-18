package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/providers/fake"
	"github.com/HarrisonHong/saashound/techniques"
)

// world is one simulated tenant plus everything needed to run against it.
type world struct {
	t      *testing.T
	store  *flakyStore
	prov   *fake.Provider
	reg    *provider.Registry
	clk    *clock.Fake
	st     state.Dir
	tgt    *target.Target
	corpus *technique.Corpus
	runs   int
}

// flakyStore can make every write or every read fail, to simulate a
// platform outage.
type flakyStore struct {
	*fake.MemoryStore
	failWrites bool
	failReads  bool
}

func (f *flakyStore) View(id string, fn func(*fake.State) error) error {
	if f.failReads {
		return errors.New("503 service unavailable")
	}
	return f.MemoryStore.View(id, fn)
}

func (f *flakyStore) Update(id string, fn func(*fake.State) error) error {
	if f.failWrites {
		return errors.New("503 service unavailable")
	}
	return f.MemoryStore.Update(id, fn)
}

func newWorld(t *testing.T, opts map[string]string) *world {
	t.Helper()
	store := &flakyStore{MemoryStore: fake.NewMemoryStore()}
	p := fake.New(fake.WithStore(store))
	reg := provider.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatal(err)
	}
	w := &world{
		t: t, store: store, prov: p, reg: reg,
		clk: clock.NewFake(time.Date(2026, 11, 14, 15, 2, 11, 0, time.UTC)),
		st:  state.Dir{Root: t.TempDir()},
		tgt: &target.Target{Name: "lab", Platform: fake.Name, Tenant: "sim-lab", Principal: "saashound-operator",
			Environment: target.Lab, TestDomain: "lab.example.com", MaxLabUsers: 25, Options: opts},
	}
	cfg := w.config()
	if err := p.Provision(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.PlaceMarker(context.Background(), cfg, w.tgt.MarkerValue()); err != nil {
		t.Fatal(err)
	}
	w.corpus = technique.NewCorpus(techniques.Version())
	if err := w.corpus.LoadFS(techniques.FS(), true, technique.RegistryCatalog(reg)); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) config() provider.Config {
	return provider.Config{Target: w.tgt.Info(), Secrets: secret.DefaultSource{}, Clock: w.clk}
}

func (w *world) open() provider.Tenant {
	w.t.Helper()
	ten, err := w.prov.Open(context.Background(), w.config())
	if err != nil {
		w.t.Fatal(err)
	}
	return ten
}

func (w *world) engine(hook func(engine.Point, string)) *engine.Engine {
	return &engine.Engine{
		Registry: w.reg, State: w.st, Clock: w.clk, Version: "test", CorpusVersion: techniques.Version(),
		Retry: engine.Retry{Attempts: 2, GoneAttempts: 2},
		Hook:  hook,
	}
}

func (w *world) plan(id string) *plan.Run {
	w.t.Helper()
	tech, err := w.corpus.Lookup(id)
	if err != nil {
		w.t.Fatal(err)
	}
	w.runs++
	run := fmt.Sprintf("tst%03d", w.runs)
	run = strings.NewReplacer("0", "a", "1", "b").Replace(run) // run ids avoid 0 and 1
	r, err := plan.Planner{Registry: w.reg}.Plan(tech, w.tgt, run, "")
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) snapshot() string {
	w.t.Helper()
	s, err := fake.Snapshot(w.store, w.tgt.Tenant)
	if err != nil {
		w.t.Fatal(err)
	}
	return string(s)
}

func (w *world) leftovers() []provider.Orphan {
	w.t.Helper()
	o, err := w.open().Sweep(context.Background(), marker.Prefix+"-")
	if err != nil {
		w.t.Fatal(err)
	}
	return o
}

func (w *world) apply(e *engine.Engine, p *plan.Run) *report.Record {
	w.t.Helper()
	rec, err := e.Apply(context.Background(), context.Background(), w.tgt, w.open(), p)
	if err != nil {
		w.t.Fatal(err)
	}
	return rec
}

func (w *world) journal(run string) *journal.Journal {
	w.t.Helper()
	p, _ := w.st.File(run, state.JournalFile)
	j, err := journal.Load(p)
	if err != nil {
		w.t.Fatal(err)
	}
	return j
}

// assertPristine proves the run left nothing: no prefixed object, and the
// tenant's objects byte-identical to before.
func (w *world) assertPristine(before string) {
	w.t.Helper()
	if left := w.leftovers(); len(left) != 0 {
		w.t.Fatalf("objects left behind: %+v", left)
	}
	if after := w.snapshot(); after != before {
		w.t.Fatalf("tenant changed:\nbefore %s\nafter  %s", before, after)
	}
}

// TestTechniqueConformance: every embedded technique validates, plans,
// applies, cleans up verified, observes its telemetry and leaves the tenant
// exactly as it found it.
func TestTechniqueConformance(t *testing.T) {
	ids := []string{}
	w0 := newWorld(t, nil)
	for _, tech := range w0.corpus.List() {
		ids = append(ids, tech.ID)
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			w := newWorld(t, nil)
			before := w.snapshot()
			p := w.plan(id)
			rec := w.apply(w.engine(nil), p)
			if rec.Verdict != report.VerdictPass {
				b, _ := json.MarshalIndent(rec, "", "  ")
				t.Fatalf("verdict %s:\n%s", rec.Verdict, b)
			}
			if rec.Cleanup.Status != report.CleanupVerified || rec.Cleanup.Objects != len(p.Steps) {
				t.Fatalf("cleanup %+v", rec.Cleanup)
			}
			if rec.Telemetry.Observed != len(p.Expect) || rec.Telemetry.Expected != len(p.Expect) {
				t.Fatalf("telemetry %+v", rec.Telemetry)
			}
			w.assertPristine(before)

			j := w.journal(p.Run)
			for _, s := range j.Steps() {
				if s.Intent == nil || s.Result == nil || s.Undo == nil || !s.Verified() {
					t.Errorf("step %s journal incomplete: %+v", s.ID, s)
				}
				if s.Intent.Seq >= s.Result.Seq {
					t.Errorf("step %s: intent must precede result", s.ID)
				}
			}
			if got := j.LastPhase(); got != journal.PhaseComplete {
				t.Errorf("last phase %q", got)
			}
			if st := state.DeriveState(j, false); st != state.StateComplete {
				t.Errorf("state %s", st)
			}
			evs, err := os.ReadFile(w.st.Root + "/" + rec.Telemetry.EventsFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(evs)), "\n") {
				if !strings.Contains(line, "run="+p.Run+";") {
					t.Errorf("events.jsonl holds another run's event: %s", line)
				}
			}
			// The cleanup phase is logged too, under its own marker.
			if !strings.Contains(string(evs), "phase=cleanup") || !strings.Contains(string(evs), "phase=detonate") {
				t.Errorf("events.jsonl should hold both phases: %s", evs)
			}
		})
	}
}

type crash struct{ point engine.Point }

// TestCrashInjection kills the run at every crash point of every step of
// every embedded technique and proves the cleaner, reading only the
// journal, recovers with nothing orphaned; running it twice is harmless.
func TestCrashInjection(t *testing.T) {
	w0 := newWorld(t, nil)
	for _, tech := range w0.corpus.List() {
		for _, step := range tech.Steps {
			for _, point := range engine.Points {
				name := fmt.Sprintf("%s/%s/%s", tech.ID, step.ID, point)
				t.Run(name, func(t *testing.T) {
					w := newWorld(t, nil)
					before := w.snapshot()
					p := w.plan(tech.ID)
					killed := func() (killed bool) {
						defer func() {
							if r := recover(); r != nil {
								if _, ok := r.(crash); !ok {
									panic(r)
								}
								killed = true
							}
						}()
						w.apply(w.engine(func(pt engine.Point, s string) {
							if pt == point && s == step.ID {
								panic(crash{pt})
							}
						}), p)
						return false
					}()
					if !killed {
						t.Fatalf("crash point %s on step %s was never reached", point, step.ID)
					}

					// A fresh process: new engine, new connection, the journal on disk.
					e := w.engine(nil)
					res, err := e.Cleanup(context.Background(), p.Run, w.tgt, w.open(), "cleanup")
					if err != nil {
						t.Fatal(err)
					}
					if !res.Verified() {
						t.Fatalf("cleanup after crash not verified: %+v", res)
					}
					w.assertPristine(before)
					if st := w.st.Info(p.Run).State; st != state.StateCleaned && st != state.StateComplete {
						t.Fatalf("state after recovery = %s", st)
					}

					undos := count(w.journal(p.Run), journal.KindUndo)
					again, err := e.Cleanup(context.Background(), p.Run, w.tgt, w.open(), "cleanup")
					if err != nil || !again.Verified() {
						t.Fatalf("second cleanup = %+v, %v", again, err)
					}
					if n := count(w.journal(p.Run), journal.KindUndo); n != undos {
						t.Fatalf("a second cleanup undid things again (%d -> %d undo records)", undos, n)
					}
					w.assertPristine(before)
				})
			}
		}
	}
}

func count(j *journal.Journal, k journal.Kind) int {
	n := 0
	for _, r := range j.Records {
		if r.Kind == k {
			n++
		}
	}
	return n
}

// TestTornJournalAfterCrash: the crash also tore the journal's last line.
func TestTornJournalAfterCrash(t *testing.T) {
	w := newWorld(t, nil)
	before := w.snapshot()
	p := w.plan("fake.persistence.mfa-factor-register")
	func() {
		defer func() { _ = recover() }()
		w.apply(w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterDo && s == "factor" {
				panic(crash{pt})
			}
		}), p)
	}()
	jp, _ := w.st.File(p.Run, state.JournalFile)
	f, err := os.OpenFile(jp, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"v":1,"seq":99,"kind":"resu`)
	_ = f.Close()
	res, err := w.engine(nil).Cleanup(context.Background(), p.Run, w.tgt, w.open(), "cleanup")
	if err != nil || !res.Verified() {
		t.Fatalf("cleanup = %+v, %v", res, err)
	}
	located := false
	for _, s := range res.Steps {
		located = located || s.Located
	}
	if !located {
		t.Fatal("the factor had no recorded id; it must have been found by its exact name")
	}
	w.assertPristine(before)
}

func TestDetonationFailureCleansUp(t *testing.T) {
	w := newWorld(t, nil)
	before := w.snapshot()
	p := w.plan("fake.persistence.mfa-factor-register")
	// Point the second step at a user that does not exist: the platform
	// rejects it after the first step created a user.
	p.Steps[1].With = map[string]string{"user": "00u9999999"}
	rec := w.apply(w.engine(nil), p)
	if rec.Verdict != report.VerdictDetonateFailed || rec.Detonate.FailedStep != "factor" || rec.Detonate.Completed != 1 {
		t.Fatalf("record %+v", rec.Detonate)
	}
	if rec.Cleanup.Status != report.CleanupVerified {
		t.Fatalf("cleanup %+v", rec.Cleanup)
	}
	if report.ExitCode(rec.Verdict) != report.ExitExpectationFailed {
		t.Fatal("a failed detonation must fail CI")
	}
	w.assertPristine(before)
}

func TestCleanupFailureIsUnverifiedThenRecoverable(t *testing.T) {
	w := newWorld(t, nil)
	before := w.snapshot()
	p := w.plan("fake.privilege-escalation.admin-role-assign")
	e := w.engine(func(pt engine.Point, s string) {
		if pt == engine.AfterResult && s == "grant" {
			w.store.failWrites = true // the platform goes down before cleanup
		}
	})
	rec := w.apply(e, p)
	if rec.Verdict != report.VerdictCleanupUnverified || report.ExitCode(rec.Verdict) != report.ExitCleanupUnverified {
		t.Fatalf("verdict %s", rec.Verdict)
	}
	if len(rec.Cleanup.Orphans) != 2 || rec.Cleanup.Retry != "saashound cleanup "+p.Run {
		t.Fatalf("cleanup %+v", rec.Cleanup)
	}
	if st := w.st.Info(p.Run).State; st != state.StateCleanupUnverified {
		t.Fatalf("state %s", st)
	}
	w.store.failWrites = false
	res, err := w.engine(nil).Cleanup(context.Background(), p.Run, w.tgt, w.open(), "cleanup")
	if err != nil || !res.Verified() {
		t.Fatalf("retry = %+v %v", res, err)
	}
	w.assertPristine(before)
}

func TestInterrupts(t *testing.T) {
	t.Run("first interrupt stops detonation and cleans up", func(t *testing.T) {
		w := newWorld(t, nil)
		before := w.snapshot()
		p := w.plan("fake.persistence.mfa-factor-register")
		ctx, cancel := context.WithCancel(context.Background())
		e := w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterResult && s == "victim" {
				cancel()
			}
		})
		rec, err := e.Apply(ctx, context.Background(), w.tgt, w.open(), p)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Detonate.Status != report.DetonateInterrupted || rec.Cleanup.Status != report.CleanupVerified {
			t.Fatalf("detonate %+v cleanup %+v", rec.Detonate, rec.Cleanup)
		}
		w.assertPristine(before)
	})
	t.Run("second interrupt abandons cleanup, resumable", func(t *testing.T) {
		w := newWorld(t, nil)
		before := w.snapshot()
		p := w.plan("fake.persistence.mfa-factor-register")
		cctx, cancel := context.WithCancel(context.Background())
		e := w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterGone && s == "factor" {
				cancel()
			}
		})
		rec, err := e.Apply(context.Background(), cctx, w.tgt, w.open(), p)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Verdict != report.VerdictCleanupUnverified {
			t.Fatalf("verdict %s", rec.Verdict)
		}
		if st := w.st.Info(p.Run).State; st != state.StateCleanupPending {
			t.Fatalf("state %s", st)
		}
		res, err := w.engine(nil).Cleanup(context.Background(), p.Run, w.tgt, w.open(), "cleanup")
		if err != nil || !res.Verified() {
			t.Fatalf("resume = %+v %v", res, err)
		}
		w.assertPristine(before)
	})
}

func TestTelemetryOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		opts    map[string]string
		verdict string
		status  string
	}{
		{"observed with lag", map[string]string{"audit_lag": "5s"}, report.VerdictPass, "observed"},
		{"missing", map[string]string{"audit_drop": "user.mfa.factor.activate"}, report.VerdictTelemetryMissing, "missing"},
		{"late", map[string]string{"audit_lag/user.mfa.factor.activate": "25s"}, report.VerdictTelemetryMissing, "late"},
		{"unsupported tier", map[string]string{"audit": "unsupported"}, report.VerdictTelemetryUnsupported, "unsupported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t, c.opts)
			before := w.snapshot()
			rec := w.apply(w.engine(nil), w.plan("fake.persistence.mfa-factor-register"))
			if rec.Verdict != c.verdict || rec.Telemetry.Status != c.status {
				t.Fatalf("verdict %s telemetry %+v", rec.Verdict, rec.Telemetry)
			}
			if rec.Cleanup.Status != report.CleanupVerified {
				t.Fatal("cleanup must not depend on telemetry")
			}
			w.assertPristine(before)
		})
	}
}

type stubChecker struct{ fired bool }

func (stubChecker) Name() string { return "stub" }
func (s stubChecker) Check(_ context.Context, in detect.Input) ([]detect.Result, error) {
	if len(in.Events) == 0 {
		return nil, errors.New("no events handed to the checker")
	}
	f := s.fired
	return []detect.Result{{Checker: "stub", Rule: "Stub rule", Fired: &f}}, nil
}

func TestDetectionCheckerSeam(t *testing.T) {
	for _, fired := range []bool{true, false} {
		w := newWorld(t, nil)
		e := w.engine(nil)
		e.Checkers = []detect.Checker{stubChecker{fired: fired}}
		rec := w.apply(e, w.plan("fake.persistence.mfa-factor-register"))
		want := report.VerdictPass
		if !fired {
			want = report.VerdictDetectionMissing
		}
		if rec.Verdict != want || len(rec.Detections) != 1 {
			t.Fatalf("fired=%v: verdict %s detections %+v", fired, rec.Verdict, rec.Detections)
		}
	}
}

func TestCleanupRefusesAnotherTarget(t *testing.T) {
	w := newWorld(t, nil)
	p := w.plan("fake.persistence.mfa-factor-register")
	w.apply(w.engine(nil), p)
	other := *w.tgt
	other.Tenant = "corp-prod"
	if _, err := w.engine(nil).Cleanup(context.Background(), p.Run, &other, w.open(), "cleanup"); err == nil {
		t.Fatal("a journal must only be replayed against the tenant it was written for")
	}
}

func TestRemoveOrphan(t *testing.T) {
	w := newWorld(t, nil)
	before := w.snapshot()
	p := w.plan("fake.persistence.mfa-factor-register")
	func() {
		defer func() { _ = recover() }()
		w.apply(w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterResult && s == "factor" {
				panic(crash{pt})
			}
		}), p)
	}()
	// The journal is lost (another machine, a vanished CI runner).
	dir, _ := w.st.RunDir(p.Run)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	orphans := w.leftovers()
	if len(orphans) != 2 || orphans[0].Op != "fake.factor.enroll" {
		t.Fatalf("sweep = %+v; children must come first", orphans)
	}
	e := w.engine(nil)
	for _, o := range orphans {
		if out := e.RemoveOrphan(context.Background(), w.tgt, w.open(), o); !out.Verified {
			t.Fatalf("remove %s: %+v", o.Name, out)
		}
	}
	w.assertPristine(before)
}

// TestTelemetryNotCollectedIsNeverPass: a run whose audit log was not read,
// or not read to the end, has not been verified. It must fail with a reason
// that says collection failed or was interrupted, not that events were late.
func TestTelemetryNotCollectedIsNeverPass(t *testing.T) {
	const tech = "fake.persistence.mfa-factor-register"
	check := func(t *testing.T, rec *report.Record, reason string) {
		t.Helper()
		if rec.Detonate.Status != report.DetonateOK || rec.Cleanup.Status != report.CleanupVerified {
			t.Fatalf("detonate %+v cleanup %+v", rec.Detonate, rec.Cleanup)
		}
		if rec.Verdict != report.VerdictTelemetryMissing || report.ExitCode(rec.Verdict) != report.ExitExpectationFailed {
			t.Fatalf("verdict %s, want %s: telemetry %+v", rec.Verdict, report.VerdictTelemetryMissing, rec.Telemetry)
		}
		if !strings.Contains(rec.Reason, "collection failed or was interrupted") || !strings.Contains(rec.Reason, reason) {
			t.Fatalf("reason %q, want it to mention %q", rec.Reason, reason)
		}
		if strings.Contains(rec.Reason, "deadline") {
			t.Fatalf("reason %q blames the deadline", rec.Reason)
		}
		if rec.Telemetry.Error == "" || rec.Telemetry.Missing != 0 || rec.Telemetry.Late != 0 {
			t.Fatalf("telemetry %+v", rec.Telemetry)
		}
	}

	t.Run("interrupt during cleanup after a completed detonation", func(t *testing.T) {
		w := newWorld(t, nil)
		before := w.snapshot()
		p := w.plan(tech)
		last := p.Cleanup[len(p.Cleanup)-1].Step
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e := w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterGone && s == last {
				cancel()
			}
		})
		rec, err := e.Apply(ctx, context.Background(), w.tgt, w.open(), p)
		if err != nil {
			t.Fatal(err)
		}
		check(t, rec, "telemetry collection was interrupted")
		if rec.Telemetry.Status != report.TelemetryIncomplete || rec.Telemetry.Observed != 0 {
			t.Fatalf("telemetry %+v", rec.Telemetry)
		}
		for _, o := range rec.Telemetry.Expectations {
			if o.Status != "not-run" {
				t.Fatalf("expectation %+v, want not-run", o)
			}
		}
		w.assertPristine(before)
	})

	t.Run("capabilities failure", func(t *testing.T) {
		w := newWorld(t, nil)
		p := w.plan(tech)
		last := p.Cleanup[len(p.Cleanup)-1].Step
		e := w.engine(func(pt engine.Point, s string) {
			if pt == engine.AfterGone && s == last {
				w.store.failReads = true
			}
		})
		rec := w.apply(e, p)
		check(t, rec, "capabilities: ")
		if rec.Telemetry.Status != report.TelemetryIncomplete {
			t.Fatalf("telemetry %+v", rec.Telemetry)
		}
	})

	t.Run("interrupt during the poll loop", func(t *testing.T) {
		// The second event is not readable yet when collection starts.
		w := newWorld(t, map[string]string{"audit_lag/user.mfa.factor.activate": "10s"})
		p := w.plan(tech)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e := w.engine(nil)
		e.Progress = func(ev engine.Event) {
			if ev.Stage == "telemetry" && strings.HasPrefix(ev.Msg, "polling ") {
				cancel()
			}
		}
		rec, err := e.Apply(ctx, context.Background(), w.tgt, w.open(), p)
		if err != nil {
			t.Fatal(err)
		}
		check(t, rec, "telemetry collection was interrupted")
		for _, o := range rec.Telemetry.Expectations {
			if o.Status == "missing" {
				t.Fatalf("an interrupted collection reported %s as missing", o.Type)
			}
		}
	})
}

// TestSlowCleanupDoesNotMakeEventsLate: collection starts after cleanup, so
// when cleanup outlasts a deadline the platform's own timestamp decides.
func TestSlowCleanupDoesNotMakeEventsLate(t *testing.T) {
	w := newWorld(t, nil)
	p := w.plan("fake.persistence.mfa-factor-register")
	e := w.engine(func(pt engine.Point, _ string) {
		if pt == engine.AfterGone {
			w.clk.Advance(45 * time.Second)
		}
	})
	rec := w.apply(e, p)
	if rec.Verdict != report.VerdictPass || rec.Telemetry.Status != "observed" {
		t.Fatalf("verdict %s (%s): telemetry %+v", rec.Verdict, rec.Reason, rec.Telemetry)
	}
}

// recordingTenant records the User-Agent of every collection request.
type recordingTenant struct {
	provider.Tenant
	uas *[]string
}

func (r recordingTenant) Capabilities(ctx context.Context) (provider.Caps, error) {
	*r.uas = append(*r.uas, provider.UserAgent(ctx))
	return r.Tenant.Capabilities(ctx)
}

func (r recordingTenant) AuditSource() provider.AuditSource {
	return recordingSource{r.Tenant.AuditSource(), r.uas}
}

type recordingSource struct {
	provider.AuditSource
	uas *[]string
}

func (r recordingSource) Poll(ctx context.Context, q provider.AuditQuery) ([]provider.Event, error) {
	*r.uas = append(*r.uas, provider.UserAgent(ctx))
	return r.AuditSource.Poll(ctx, q)
}

// TestCollectionCarriesTheRunMarker: the audit-log reads are the tool's own
// activity too, so they carry the run's User-Agent with the collect phase,
// while expectations still match detonation-phase events only.
func TestCollectionCarriesTheRunMarker(t *testing.T) {
	w := newWorld(t, nil)
	p := w.plan("fake.persistence.mfa-factor-register")
	e := w.engine(nil)
	rec := w.apply(e, p)
	if rec.Verdict != report.VerdictPass {
		t.Fatalf("verdict %s", rec.Verdict)
	}
	var uas []string
	tel, err := e.Observe(context.Background(), recordingTenant{w.open(), &uas}, p, rec.Started)
	if err != nil {
		t.Fatal(err)
	}
	want := marker.UserAgent("test", p.Run, marker.PhaseCollect)
	if len(uas) < 2 {
		t.Fatalf("recorded %d collection requests; want the capabilities call and at least one poll", len(uas))
	}
	for _, ua := range uas {
		if ua != want {
			t.Errorf("collection request sent %q, want %q", ua, want)
		}
	}
	if tel.Observed != len(p.Expect) {
		t.Fatalf("telemetry %+v", tel)
	}
	evs, err := os.ReadFile(w.st.Root + "/" + tel.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range tel.Expectations {
		for _, line := range strings.Split(strings.TrimSpace(string(evs)), "\n") {
			if strings.Contains(line, `"`+o.EventID+`"`) && !strings.Contains(line, "phase=detonate") {
				t.Errorf("expectation %s matched a non-detonation event: %s", o.Type, line)
			}
		}
	}
}
