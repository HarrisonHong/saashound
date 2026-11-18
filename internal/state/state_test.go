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
