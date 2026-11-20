// Package journal is the run's write-ahead log.
//
// Before every mutating call the executor appends an intent and fsyncs it;
// after the call it appends the result (resource ID, outputs, and for modify
// ops the prior value, which is already in the intent). The cleaner appends
// undo and gone records. Cleanup is a pure function of this file: whatever
// happened to the process, the journal says what may exist and how to remove
// it.
//
// The file is JSON lines, mode 0600, one record per line. A crash can tear
// only the last line; readers ignore a torn tail and writers truncate it
// before appending. Records never hold secrets: ops never take secret
// parameters and never output them.
package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/fsutil"
)

// Version is the journal record format version.
const Version = 1

// Kind is the kind of a journal record.
type Kind string

// Record kinds.
const (
	KindRun    Kind = "run"    // the header, always first
	KindIntent Kind = "intent" // written and fsynced before op.Do
	KindResult Kind = "result" // written after op.Do succeeded
	KindError  Kind = "error"  // op.Do failed; the object may still exist
	KindUndo   Kind = "undo"   // op.Undo returned
	KindGone   Kind = "gone"   // op.Gone (or an exact Locate miss) was checked
	KindPhase  Kind = "phase"  // run phase transitions
)

// Undo outcomes.
const (
	OutcomeRemoved     = "removed"
	OutcomeRestored    = "restored" // a modify op's prior value was put back
	OutcomeAlreadyGone = "already-gone"
	OutcomeFailed      = "failed"
	// OutcomeAbsent: the journal had an intent but no ID, and an exact
	// lookup by the deterministic name found nothing, so nothing exists.
	OutcomeAbsent = "absent"
)

// Phases.
const (
	PhaseDetonateDone     = "detonate-done"
	PhaseDetonateFailed   = "detonate-failed"
	PhaseDetonateAborted  = "detonate-interrupted"
	PhaseCleanupVerified  = "cleanup-verified"
	PhaseCleanupFailed    = "cleanup-unverified"
	PhaseCleanupAbandoned = "cleanup-abandoned"
	PhaseComplete         = "complete"
)

// Header is the first record of every journal: everything cleanup needs to
// reconnect to the same tenant and undo the run without the plan.
type Header struct {
	Run             string       `json:"run"`
	Technique       string       `json:"technique"`
	TechniqueDigest string       `json:"technique_digest"`
	Corpus          string       `json:"corpus"`
	Target          string       `json:"target"`
	Platform        string       `json:"platform"`
	Tenant          string       `json:"tenant"`
	Principal       string       `json:"principal"`
	Environment     string       `json:"environment"`
	Ticket          string       `json:"ticket,omitempty"`
	Tool            string       `json:"tool"`
	Started         time.Time    `json:"started"`
	Steps           []HeaderStep `json:"steps"`
	// Cleanup is the order steps are undone in.
	Cleanup []string `json:"cleanup"`
}

// HeaderStep describes one planned step.
type HeaderStep struct {
	ID   string `json:"id"`
	Op   string `json:"op"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Record is one journal line.
type Record struct {
	V    int       `json:"v"`
	Seq  int       `json:"seq"`
	Time time.Time `json:"ts"`
	Kind Kind      `json:"kind"`

	Header *Header `json:"header,omitempty"`

	Step    string            `json:"step,omitempty"`
	Op      string            `json:"op,omitempty"`
	Name    string            `json:"name,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Prior   json.RawMessage   `json:"prior,omitempty"`
	ID      string            `json:"id,omitempty"`
	Outputs map[string]string `json:"outputs,omitempty"`
	Error   string            `json:"error,omitempty"`
	Outcome string            `json:"outcome,omitempty"`
	// Verified is set on gone records.
	Verified *bool  `json:"verified,omitempty"`
	Phase    string `json:"phase,omitempty"`
	// By names the command that wrote the record: apply, cleanup or sweep.
	By string `json:"by,omitempty"`
}

// Writer appends to a journal.
type Writer struct {
	f    file
	seq  int
	clk  clock.Clock
	path string
	// size is the length of the journal up to its last durable record.
	size int64
	// failed is set once a failed write could not be rolled back; every
	// later Append returns it without writing.
	failed error
}

// file is the part of *os.File the Writer uses.
type file interface {
	Write(b []byte) (int, error)
	Sync() error
	Truncate(size int64) error
	Close() error
}

// Create starts a new journal at path with its header. It refuses to
// overwrite an existing journal.
func Create(path string, h Header, clk clock.Clock) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, fsutil.FileMode)
	if err != nil {
		return nil, fmt.Errorf("create journal: %w", err)
	}
	if err := fsutil.SyncDir(filepath.Dir(path)); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("create journal: %w", err)
	}
	w := &Writer{f: f, clk: clk, path: path}
	if err := w.Append(Record{Kind: KindRun, Header: &h}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// OpenAppend opens an existing journal for appending, after truncating a
// torn final line left by a crash. It returns the journal's contents.
func OpenAppend(path string, clk clock.Clock) (*Writer, *Journal, error) {
	j, err := Load(path)
	if err != nil {
		return nil, nil, err
	}
	if j.TornBytes > 0 {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		if err := os.Truncate(path, fi.Size()-int64(j.TornBytes)); err != nil {
			return nil, nil, fmt.Errorf("repair journal: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, fsutil.FileMode)
	if err != nil {
		return nil, nil, fmt.Errorf("open journal: %w", err)
	}
	if j.TornBytes > 0 {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, nil, err
		}
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("open journal: %w", err)
	}
	seq := 0
	if n := len(j.Records); n > 0 {
		seq = j.Records[n-1].Seq
	}
	return &Writer{f: f, seq: seq, clk: clk, path: path, size: fi.Size()}, j, nil
}

// Append writes r and fsyncs it. When Append returns nil, the record
// survives a crash.
//
// A failed write is rolled back by truncating the journal to its last
// durable record, so a torn record can only ever be the final line. If the
// rollback fails too, the Writer refuses every later Append: nothing may be
// written after a line that might be torn.
func (w *Writer) Append(r Record) error {
	if w.failed != nil {
		return w.failed
	}
	if w.f == nil {
		return errors.New("journal: closed")
	}
	r.V = Version
	r.Seq = w.seq + 1
	r.Time = w.clk.Now().UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	b = append(b, '\n')
	if _, err = w.f.Write(b); err != nil {
		err = fmt.Errorf("journal: %w", err)
	} else if err = w.f.Sync(); err != nil {
		err = fmt.Errorf("journal: fsync: %w", err)
	}
	if err != nil {
		if rerr := w.rollback(); rerr != nil {
			w.failed = fmt.Errorf("%w; the journal accepts no further records because the failed write could not be rolled back: %v", err, rerr)
			return w.failed
		}
		return err
	}
	w.seq++
	w.size += int64(len(b))
	return nil
}

// rollback removes whatever a failed Append left after the last durable
// record.
func (w *Writer) rollback() error {
	if err := w.f.Truncate(w.size); err != nil {
		return err
	}
	return w.f.Sync()
}

// Close closes the journal.
func (w *Writer) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// Journal is a journal's parsed contents.
type Journal struct {
	Header  Header
	Records []Record
	// TornBytes is the length of a torn final line that was ignored.
	TornBytes int
}

// ErrNoHeader is returned for a journal that does not start with a header.
var ErrNoHeader = errors.New("journal has no run header")

// Load reads a journal. A torn final line is ignored and reported in
// TornBytes; a malformed line anywhere else is corruption and an error.
func Load(path string) (*Journal, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read journal: %w", err)
	}
	return Parse(b)
}

// Parse parses journal bytes; see Load.
func Parse(b []byte) (*Journal, error) {
	j := &Journal{}
	off, line := 0, 0
	for off < len(b) {
		end := bytes.IndexByte(b[off:], '\n')
		if end < 0 {
			// No trailing newline: the process died mid-write.
			j.TornBytes = len(b) - off
			break
		}
		raw := b[off : off+end+1]
		off += end + 1
		line++
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			if off == len(b) {
				// A garbled final line is a torn write too.
				j.TornBytes = len(raw)
				break
			}
			return nil, fmt.Errorf("journal line %d is corrupt: %w", line, err)
		}
		if rec.V != Version {
			return nil, fmt.Errorf("journal line %d: unsupported record version %d", line, rec.V)
		}
		j.Records = append(j.Records, rec)
	}
	if len(j.Records) == 0 || j.Records[0].Kind != KindRun || j.Records[0].Header == nil {
		return nil, ErrNoHeader
	}
	j.Header = *j.Records[0].Header
	return j, nil
}

// StepState is everything the journal says about one step.
type StepState struct {
	HeaderStep
	Intent *Record
	Result *Record
	Error  *Record
	Undo   *Record // latest
	Gone   *Record // latest
}

// Started reports whether the step's intent was written: from then on, the
// object may exist.
func (s *StepState) Started() bool { return s.Intent != nil }

// Verified reports whether the latest gone check proved the step undone.
func (s *StepState) Verified() bool {
	return s.Gone != nil && s.Gone.Verified != nil && *s.Gone.Verified
}

// Steps returns the state of every planned step, in plan order.
func (j *Journal) Steps() []*StepState {
	byID := map[string]*StepState{}
	out := make([]*StepState, 0, len(j.Header.Steps))
	for _, hs := range j.Header.Steps {
		s := &StepState{HeaderStep: hs}
		byID[hs.ID] = s
		out = append(out, s)
	}
	for i := range j.Records {
		r := &j.Records[i]
		s, ok := byID[r.Step]
		if !ok {
			continue
		}
		switch r.Kind {
		case KindIntent:
			s.Intent = r
		case KindResult:
			s.Result = r
		case KindError:
			s.Error = r
		case KindUndo:
			s.Undo = r
		case KindGone:
			s.Gone = r
		}
	}
	return out
}

// Phases returns the run's phase records, in order.
func (j *Journal) Phases() []string {
	var out []string
	for _, r := range j.Records {
		if r.Kind == KindPhase {
			out = append(out, r.Phase)
		}
	}
	return out
}

// LastPhase returns the latest phase, or "".
func (j *Journal) LastPhase() string {
	p := j.Phases()
	if len(p) == 0 {
		return ""
	}
	return p[len(p)-1]
}

// Span is when, by this machine's clock, the run could have changed the
// tenant: from its first intent to the journal's last record.
type Span struct {
	// Start is the first intent. No op runs before its intent is durable,
	// so nothing the run did can precede it.
	Start time.Time
	// DetonateEnd is the last detonation record (an intent, result or error,
	// or the detonation's phase record). Every detonation call had returned
	// by then; cleanup calls come after it.
	DetonateEnd time.Time
	// End is the last record. Read after cleanup, every cleanup call had
	// returned by then.
	End time.Time
}

// Span returns the run's span. It returns false when no step was ever
// started, so the run cannot have changed anything.
func (j *Journal) Span() (Span, bool) {
	var sp Span
	later := func(t *time.Time, ts time.Time) {
		if ts.After(*t) {
			*t = ts
		}
	}
	for _, r := range j.Records {
		switch r.Kind {
		case KindIntent:
			if sp.Start.IsZero() || r.Time.Before(sp.Start) {
				sp.Start = r.Time
			}
			later(&sp.DetonateEnd, r.Time)
		case KindResult, KindError:
			later(&sp.DetonateEnd, r.Time)
		case KindPhase:
			switch r.Phase {
			case PhaseDetonateDone, PhaseDetonateFailed, PhaseDetonateAborted:
				later(&sp.DetonateEnd, r.Time)
			}
		}
		later(&sp.End, r.Time)
	}
	if sp.Start.IsZero() {
		return Span{}, false
	}
	return sp, true
}

// Pending returns the steps that were started and are not yet proven undone.
func (j *Journal) Pending() []*StepState {
	var out []*StepState
	for _, s := range j.Steps() {
		if s.Started() && !s.Verified() {
			out = append(out, s)
		}
	}
	return out
}

// Bool returns a pointer to b, for Record.Verified.
func Bool(b bool) *bool { return &b }
