package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/journal"
)

func TestRunDirsAndStates(t *testing.T) {
	d := Dir{Root: t.TempDir()}
	if _, err := d.RunDir("../../etc"); err == nil {
		t.Fatal("a path must never be accepted as a run id")
	}
	if _, err := d.CreateRun("k3v9q2"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateRun("k3v9q2"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("re-creating a run = %v", err)
	}
	p, _ := d.File("k3v9q2", PlanFile)
	_ = os.WriteFile(p, []byte(`{"target":"lab","technique":"fake.persistence.x"}`), 0o600)
	if in := d.Info("k3v9q2"); in.State != StateNotStarted || in.Target != "lab" {
		t.Fatalf("planned-only run = %+v", in)
	}

	clk := clock.NewFake(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC))
	jp, _ := d.File("k3v9q2", JournalFile)
	w, err := journal.Create(jp, journal.Header{Run: "k3v9q2", Target: "lab", Technique: "fake.persistence.x",
		Steps: []journal.HeaderStep{{ID: "a", Name: "saashound-k3v9q2-a"}}, Cleanup: []string{"a"}}, clk)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Append(journal.Record{Kind: journal.KindIntent, Step: "a"})
	if in := d.Info("k3v9q2"); in.State != StateCleanupPending || in.Pending != 1 {
		t.Fatalf("intent only = %+v", in)
	}
	l, err := d.LockRun("k3v9q2")
	if err != nil {
		t.Fatal(err)
	}
	if in := d.Info("k3v9q2"); in.State != StateRunning {
		t.Fatalf("locked run = %+v", in)
	}
	if _, err := d.LockRun("k3v9q2"); err == nil {
		t.Fatal("a run can be locked once")
	}
	_ = l.Unlock()
	_ = w.Append(journal.Record{Kind: journal.KindPhase, Phase: journal.PhaseCleanupFailed})
	_ = w.Append(journal.Record{Kind: journal.KindPhase, Phase: journal.PhaseComplete})
	if in := d.Info("k3v9q2"); in.State != StateCleanupUnverified {
		t.Fatalf("failed cleanup = %+v", in)
	}
	_ = w.Append(journal.Record{Kind: journal.KindGone, Step: "a", Verified: journal.Bool(true)})
	_ = w.Close()
	if in := d.Info("k3v9q2"); in.State != StateComplete || in.Pending != 0 {
		t.Fatalf("verified = %+v", in)
	}
	runs, err := d.Runs()
	if err != nil || len(runs) != 1 || runs[0].Run != "k3v9q2" {
		t.Fatalf("Runs = %+v %v", runs, err)
	}
	if fi, _ := os.Stat(filepath.Join(d.Root, "runs", "k3v9q2")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Fatalf("run dir mode %v", fi.Mode().Perm())
	}
	l1, err := d.LockTarget("lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.LockTarget("lab"); err == nil {
		t.Fatal("one run per target at a time")
	}
	_ = l1.Unlock()
}

// TestPreviousLastMutation: the previous run's last mutation is the latest
// step or undo record, not after this run's start, of the other runs in the
// state directory on that target.
func TestPreviousLastMutation(t *testing.T) {
	d := Dir{Root: t.TempDir()}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if got := d.PreviousLastMutation("k3v9q2", "lab", t0); !got.IsZero() {
		t.Fatalf("no state directory yet: %v, want zero", got)
	}
	// write journals a run on target: its header at the first time, then one
	// record of each kind at each following time, and a complete phase
	// record at done.
	write := func(run, target string, done time.Time, kinds []journal.Kind, at ...time.Time) {
		t.Helper()
		if _, err := d.CreateRun(run); err != nil {
			t.Fatal(err)
		}
		clk := clock.NewFake(at[0])
		jp, _ := d.File(run, JournalFile)
		w, err := journal.Create(jp, journal.Header{Run: run, Target: target, Technique: "fake.persistence.x"}, clk)
		if err != nil {
			t.Fatal(err)
		}
		add := func(ts time.Time, r journal.Record) {
			clk.Advance(ts.Sub(clk.Now()))
			if err := w.Append(r); err != nil {
				t.Fatal(err)
			}
		}
		for i, k := range kinds {
			add(at[i+1], journal.Record{Kind: k, Step: "a"})
		}
		add(done, journal.Record{Kind: journal.KindPhase, Phase: journal.PhaseComplete})
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	step := []journal.Kind{journal.KindIntent, journal.KindResult, journal.KindUndo, journal.KindGone}
	const this = "k3v9q2"
	start := t0.Add(time.Hour)
	write(this, "lab", start.Add(time.Minute), step, start, start, start, start, start)
	if got := d.PreviousLastMutation(this, "lab", start); !got.IsZero() {
		t.Fatalf("only this run itself: %v, want zero", got)
	}

	// The run before: its undo is its last mutation; the check that the
	// object is gone and the complete record, written after collection just
	// before this run starts, are not.
	undone := start.Add(-30 * time.Second)
	write("x4b8nd", "lab", start.Add(-time.Millisecond), step,
		t0.Add(20*time.Minute), t0.Add(21*time.Minute), t0.Add(22*time.Minute), undone, undone.Add(time.Second))
	write("p7m2xw", "lab", t0.Add(10*time.Minute), step, t0, t0, t0, t0.Add(time.Minute), t0.Add(time.Minute))
	// Later than x4b8nd's undo, but none of them the previous run's last
	// mutation: another target, a run that never started a step, a run that
	// mutated only after this one started, and a journal that cannot be read.
	write("m9nq4z", "other", start, []journal.Kind{journal.KindIntent, journal.KindError}, t0, start.Add(-2*time.Second), start.Add(-time.Second))
	write("r5tw8c", "lab", start.Add(-2*time.Second), nil, t0)
	write("h2jk6e", "lab", start.Add(time.Minute), []journal.Kind{journal.KindIntent}, start.Add(-10*time.Second), start.Add(time.Second))
	if _, err := d.CreateRun("q8wd3f"); err != nil {
		t.Fatal(err)
	}
	jp, _ := d.File("q8wd3f", JournalFile)
	if err := os.WriteFile(jp, []byte("not a journal\nat all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateRun("w6yz2a"); err != nil { // planned, never journalled
		t.Fatal(err)
	}

	if got := d.PreviousLastMutation(this, "lab", start); !got.Equal(undone) {
		t.Fatalf("PreviousLastMutation = %v, want the previous run's undo, %v", got, undone)
	}
	// A mutation exactly when this run started still went before it, and a
	// run that straddles the start counts up to it.
	if got := d.PreviousLastMutation(this, "lab", undone); !got.Equal(undone) {
		t.Fatalf("PreviousLastMutation at the boundary = %v, want %v", got, undone)
	}
	if got := d.PreviousLastMutation(this, "lab", undone.Add(-time.Second)); !got.Equal(t0.Add(22 * time.Minute)) {
		t.Fatalf("PreviousLastMutation before the undo = %v, want the step's result", got)
	}
	if got := d.PreviousLastMutation(this, "other", start); !got.Equal(start.Add(-time.Second)) {
		t.Fatalf("PreviousLastMutation on the other target = %v, want its error record", got)
	}
	if got := d.PreviousLastMutation(this, "nowhere", start); !got.IsZero() {
		t.Fatalf("a target with no runs: %v, want zero", got)
	}
}
