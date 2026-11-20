package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
)

func header() Header {
	return Header{
		Run: "k3v9q2", Technique: "fake.persistence.x", Target: "lab", Platform: "fake", Tenant: "sim-lab",
		Steps:   []HeaderStep{{ID: "a", Op: "fake.user.create", Kind: "create", Name: "saashound-k3v9q2-a"}, {ID: "b", Op: "fake.factor.enroll", Kind: "create", Name: "saashound-k3v9q2-b"}},
		Cleanup: []string{"b", "a"},
	}
}

func TestJournalRoundTrip(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, err := Create(p, header(), clk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(p, header(), clk); err == nil {
		t.Fatal("Create must never overwrite a journal")
	}
	must(t, w.Append(Record{Kind: KindIntent, Step: "a", Op: "fake.user.create", Name: "saashound-k3v9q2-a"}))
	clk.Advance(time.Second)
	must(t, w.Append(Record{Kind: KindResult, Step: "a", ID: "00u1", Outputs: map[string]string{"login": "x@y"}}))
	must(t, w.Append(Record{Kind: KindIntent, Step: "b", Params: map[string]string{"user": "00u1"}, Prior: json.RawMessage(`{"status":"ACTIVE"}`)}))
	must(t, w.Close())

	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("journal mode %v, want 0600", fi.Mode().Perm())
		}
	}
	j, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if j.Header.Run != "k3v9q2" || len(j.Records) != 4 {
		t.Fatalf("loaded %+v", j)
	}
	steps := j.Steps()
	if steps[0].Result == nil || steps[0].Result.ID != "00u1" || !steps[0].Result.Time.Equal(clk.Now()) {
		t.Fatalf("step a = %+v", steps[0])
	}
	if !steps[1].Started() || steps[1].Result != nil || string(steps[1].Intent.Prior) != `{"status":"ACTIVE"}` {
		t.Fatalf("step b = %+v", steps[1])
	}
	if n := len(j.Pending()); n != 2 {
		t.Fatalf("pending = %d, want 2", n)
	}

	w, j2, err := OpenAppend(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	if len(j2.Records) != 4 {
		t.Fatal("OpenAppend must return the contents")
	}
	must(t, w.Append(Record{Kind: KindGone, Step: "b", Verified: Bool(true)}))
	must(t, w.Close())
	j, _ = Load(p)
	if got := j.Records[len(j.Records)-1].Seq; got != 5 {
		t.Fatalf("seq continues across appends: got %d", got)
	}
	if n := len(j.Pending()); n != 1 {
		t.Fatalf("pending after gone = %d", n)
	}
}

func TestTornTailIsIgnoredThenRepaired(t *testing.T) {
	clk := clock.NewFake(time.Now())
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, err := Create(p, header(), clk)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Append(Record{Kind: KindIntent, Step: "a"}))
	must(t, w.Close())
	// A crash mid-write leaves half a record with no newline.
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"v":1,"seq":3,"kind":"res`)
	_ = f.Close()

	j, err := Load(p)
	if err != nil {
		t.Fatalf("a torn tail must not make the journal unreadable: %v", err)
	}
	if j.TornBytes == 0 || len(j.Records) != 2 {
		t.Fatalf("torn=%d records=%d", j.TornBytes, len(j.Records))
	}
	w, _, err = OpenAppend(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Append(Record{Kind: KindResult, Step: "a", ID: "00u1"}))
	must(t, w.Close())
	j, err = Load(p)
	if err != nil {
		t.Fatalf("after repair: %v", err)
	}
	if j.TornBytes != 0 || len(j.Records) != 3 || j.Records[2].ID != "00u1" {
		t.Fatalf("repair failed: torn=%d records=%+v", j.TornBytes, j.Records)
	}
}

func TestCorruptionIsAnError(t *testing.T) {
	clk := clock.NewFake(time.Now())
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, _ := Create(p, header(), clk)
	must(t, w.Append(Record{Kind: KindIntent, Step: "a"}))
	must(t, w.Close())
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")
	bad := lines[0] + "garbage\n" + lines[1]
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("a corrupt middle line must be an error, got %v", err)
	}
	if _, err := Parse([]byte(lines[1])); err != ErrNoHeader {
		t.Fatalf("missing header = %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(lines[0], `"v":1`, `"v":9`, 1))); err == nil {
		t.Fatal("unknown record version accepted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// faultyFile fails the next writes after letting part of each through, the
// way a full disk does.
type faultyFile struct {
	*os.File
	failWrites   int
	failTruncate bool
	failSync     bool
}

var errDiskFull = errors.New("no space left on device")

func (f *faultyFile) Write(b []byte) (int, error) {
	if f.failWrites > 0 {
		f.failWrites--
		n, _ := f.File.Write(b[:len(b)/2])
		return n, errDiskFull
	}
	return f.File.Write(b)
}

func (f *faultyFile) Sync() error {
	if f.failSync {
		f.failSync = false
		return errDiskFull
	}
	return f.File.Sync()
}

func (f *faultyFile) Truncate(size int64) error {
	if f.failTruncate {
		return errors.New("truncate: input/output error")
	}
	return f.File.Truncate(size)
}

func faulty(t *testing.T, w *Writer) *faultyFile {
	t.Helper()
	ff := &faultyFile{File: w.f.(*os.File)}
	w.f = ff
	return ff
}

// TestFailedWriteIsRolledBack: a short write must not leave a torn line in
// the middle of the journal once later appends succeed.
func TestFailedWriteIsRolledBack(t *testing.T) {
	clk := clock.NewFake(time.Now())
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, err := Create(p, header(), clk)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Append(Record{Kind: KindIntent, Step: "a"}))
	good, _ := os.ReadFile(p)

	ff := faulty(t, w)
	ff.failWrites = 1
	if err := w.Append(Record{Kind: KindResult, Step: "a", ID: "torn"}); !errors.Is(err, errDiskFull) {
		t.Fatalf("Append = %v, want the write error", err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(good) {
		t.Fatalf("a failed write left bytes behind:\n%s", b)
	}
	ff.failSync = true
	if err := w.Append(Record{Kind: KindResult, Step: "a", ID: "unsynced"}); !errors.Is(err, errDiskFull) {
		t.Fatalf("Append = %v, want the fsync error", err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(good) {
		t.Fatalf("a record that was not fsynced stayed in the journal:\n%s", b)
	}

	// The callers keep appending after an error (the phase record, the gone
	// record): those must land after the last good record.
	must(t, w.Append(Record{Kind: KindError, Step: "a", Error: "boom"}))
	must(t, w.Append(Record{Kind: KindPhase, Phase: PhaseDetonateFailed}))
	must(t, w.Close())
	j, err := Load(p)
	if err != nil {
		t.Fatalf("journal unreadable after a failed write: %v", err)
	}
	if j.TornBytes != 0 || len(j.Records) != 4 {
		t.Fatalf("torn=%d records=%d, want 0 and 4", j.TornBytes, len(j.Records))
	}
	for i, r := range j.Records {
		if r.Seq != i+1 {
			t.Fatalf("record %d has seq %d: the failed writes must not consume sequence numbers", i, r.Seq)
		}
	}
}

// TestWriterRefusesAfterFailedRollback: when the torn bytes cannot be
// removed, nothing more is written, so the torn record stays the final line
// and the next OpenAppend repairs it.
func TestWriterRefusesAfterFailedRollback(t *testing.T) {
	clk := clock.NewFake(time.Now())
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, err := Create(p, header(), clk)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Append(Record{Kind: KindIntent, Step: "a"}))

	ff := faulty(t, w)
	ff.failWrites, ff.failTruncate = 1, true
	first := w.Append(Record{Kind: KindResult, Step: "a", ID: "torn"})
	if !errors.Is(first, errDiskFull) {
		t.Fatalf("Append = %v, want the write error", first)
	}
	torn, _ := os.ReadFile(p)
	ff.failTruncate = false
	for i := 0; i < 2; i++ {
		if err := w.Append(Record{Kind: KindPhase, Phase: PhaseDetonateFailed}); !errors.Is(err, errDiskFull) {
			t.Fatalf("Append after a failed rollback = %v, want the original error", err)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != string(torn) {
		t.Fatalf("a failed Writer wrote again:\n%s", b)
	}
	must(t, w.Close())
	if err := w.Append(Record{Kind: KindPhase, Phase: PhaseDetonateFailed}); err == nil {
		t.Fatal("Append on a closed Writer succeeded")
	}

	j, err := Load(p)
	if err != nil {
		t.Fatalf("a torn record must only ever be the final line: %v", err)
	}
	if j.TornBytes == 0 || len(j.Records) != 2 {
		t.Fatalf("torn=%d records=%d", j.TornBytes, len(j.Records))
	}
	w, _, err = OpenAppend(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Append(Record{Kind: KindResult, Step: "a", ID: "00u1"}))
	must(t, w.Close())
	j, err = Load(p)
	if err != nil || j.TornBytes != 0 || len(j.Records) != 3 || j.Records[2].ID != "00u1" || j.Records[2].Seq != 3 {
		t.Fatalf("after repair: %v %+v", err, j)
	}
}

// TestSpan: the run's span runs from its first intent to its last record, and
// detonation ends at its last detonation record, before any cleanup record.
func TestSpan(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	p := filepath.Join(t.TempDir(), "journal.jsonl")
	w, err := Create(p, header(), clk)
	if err != nil {
		t.Fatal(err)
	}
	j, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := j.Span(); ok {
		t.Fatal("a journal with no intent has no span: nothing can have changed")
	}
	step := func(d time.Duration, r Record) {
		clk.Advance(d)
		must(t, w.Append(r))
	}
	step(time.Second, Record{Kind: KindIntent, Step: "a"})
	step(time.Second, Record{Kind: KindResult, Step: "a", ID: "00u1"})
	step(time.Second, Record{Kind: KindIntent, Step: "b"})
	step(time.Second, Record{Kind: KindError, Step: "b", Error: "boom"})
	step(time.Second, Record{Kind: KindPhase, Phase: PhaseDetonateFailed})
	step(time.Second, Record{Kind: KindUndo, Step: "b", Outcome: OutcomeRemoved})
	step(time.Second, Record{Kind: KindGone, Step: "b", Verified: Bool(true)})
	step(time.Second, Record{Kind: KindPhase, Phase: PhaseCleanupVerified})
	must(t, w.Close())

	j, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sp, ok := j.Span()
	if !ok {
		t.Fatal("no span")
	}
	want := Span{Start: t0.Add(time.Second), DetonateEnd: t0.Add(5 * time.Second), End: t0.Add(8 * time.Second)}
	if !sp.Start.Equal(want.Start) || !sp.DetonateEnd.Equal(want.DetonateEnd) || !sp.End.Equal(want.End) {
		t.Fatalf("Span() = %+v, want %+v", sp, want)
	}
}
