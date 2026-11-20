// Package state lays out the tool's local state: one private directory per
// run holding its plan, write-ahead journal, raw events and result, plus the
// per-target and per-run locks.
//
//	<root>/runs/<run-id>/plan.json      the plan that was executed
//	<root>/runs/<run-id>/journal.jsonl  the write-ahead journal
//	<root>/runs/<run-id>/events.jsonl   the run's raw audit events, verbatim
//	<root>/runs/<run-id>/result.json    the result record
//	<root>/runs/<run-id>/run.lock       held while a process works on the run
//	<root>/locks/<target>.lock          one run per target at a time
//	<root>/providers/<platform>/        provider-private state (the simulated tenant)
//
// Directories are mode 0700 and files 0600. Nothing here holds a credential.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/target"
)

// File names inside a run directory.
const (
	PlanFile    = "plan.json"
	JournalFile = "journal.jsonl"
	EventsFile  = "events.jsonl"
	ResultFile  = "result.json"
	runLockFile = "run.lock"
)

// Run states, derived from the journal.
const (
	StateRunning           = "running"
	StateCleanupPending    = "cleanup-pending"
	StateCleanupUnverified = "cleanup-unverified"
	StateCleaned           = "cleaned"
	StateNotStarted        = "not-started" // planned, journal never created
	StateComplete          = "complete"
)

// DefaultRoot returns the state directory: $SAASHOUND_STATE_DIR, else
// $XDG_STATE_HOME/saashound, else ~/.local/state/saashound (on Windows,
// %LocalAppData%\saashound\state).
func DefaultRoot(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if d := getenv("SAASHOUND_STATE_DIR"); d != "" {
		return filepath.Abs(d)
	}
	if d := getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "saashound"), nil
	}
	if runtime.GOOS == "windows" {
		if d := getenv("LocalAppData"); d != "" {
			return filepath.Join(d, "saashound", "state"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("state directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "saashound"), nil
}

// Dir is the state root.
type Dir struct {
	Root string
}

// RunDir returns the directory of a run, refusing malformed run IDs so a
// command-line argument can never name a path outside the state directory.
func (d Dir) RunDir(run string) (string, error) {
	if !marker.ValidRunID(run) {
		return "", fmt.Errorf("%q is not a run id", run)
	}
	return filepath.Join(d.Root, "runs", run), nil
}

// CreateRun creates a new, private run directory.
func (d Dir) CreateRun(run string) (string, error) {
	dir, err := d.RunDir(run)
	if err != nil {
		return "", err
	}
	if err := fsutil.MkdirPrivate(filepath.Join(d.Root, "runs")); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, fsutil.DirMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("run %s already exists (a saved plan can be applied once; plan again)", run)
		}
		return "", fmt.Errorf("create run directory: %w", err)
	}
	if err := fsutil.SyncDir(filepath.Dir(dir)); err != nil {
		return "", err
	}
	return dir, nil
}

// File returns the path of a file inside a run directory.
func (d Dir) File(run, name string) (string, error) {
	dir, err := d.RunDir(run)
	if err != nil {
		return "", err
	}
	return fsutil.Contain(dir, name)
}

// ProviderDir is where a provider may keep private local state.
func (d Dir) ProviderDir(platform string) string {
	return filepath.Join(d.Root, "providers", platform)
}

// ErrBusy is returned when a target or run is locked by another process.
var ErrBusy = errors.New("busy")

// LockTarget takes the per-target lock: one run per target at a time.
func (d Dir) LockTarget(name string) (*fsutil.Lock, error) {
	if !target.ValidName(name) {
		return nil, fmt.Errorf("%q is not a target name", name)
	}
	dir := filepath.Join(d.Root, "locks")
	if err := fsutil.MkdirPrivate(dir); err != nil {
		return nil, err
	}
	l, err := fsutil.TryLock(filepath.Join(dir, name+".lock"))
	if errors.Is(err, fsutil.ErrLocked) {
		return nil, fmt.Errorf("target %s is %w: another saashound process is running against it", name, ErrBusy)
	}
	return l, err
}

// LockRun takes a run's own lock, held by whichever process is working on
// it, so `status` can tell a live run from an abandoned one.
func (d Dir) LockRun(run string) (*fsutil.Lock, error) {
	p, err := d.File(run, runLockFile)
	if err != nil {
		return nil, err
	}
	l, err := fsutil.TryLock(p)
	if errors.Is(err, fsutil.ErrLocked) {
		return nil, fmt.Errorf("run %s is %w: another saashound process is working on it", run, ErrBusy)
	}
	return l, err
}

// RunInfo summarises one run for `status`.
type RunInfo struct {
	Run       string    `json:"run"`
	Target    string    `json:"target"`
	Technique string    `json:"technique"`
	State     string    `json:"state"`
	Started   time.Time `json:"started"`
	// Pending counts steps that may still have left an object behind.
	Pending int    `json:"pending"`
	Error   string `json:"error,omitempty"`
}

// Runs lists every run with its derived state, oldest first.
func (d Dir) Runs() ([]RunInfo, error) {
	entries, err := os.ReadDir(filepath.Join(d.Root, "runs"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []RunInfo
	for _, e := range entries {
		if !e.IsDir() || !marker.ValidRunID(e.Name()) {
			continue
		}
		out = append(out, d.Info(e.Name()))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.Before(out[j].Started)
		}
		return out[i].Run < out[j].Run
	})
	return out, nil
}

// PreviousLastMutation is when the run that went before run on the same
// target last changed the tenant: among the other runs here whose journal
// names target, the latest record of a call that can change the tenant (an
// intent, result or error of a step, or an undo of its cleanup) that is not
// after start, run's own first mutation. Phase records, such as the complete
// record written after telemetry collection, are not mutations and never
// count. The target lock keeps runs on one target from one state directory
// from overlapping, so that is the run immediately before it. It is the zero
// time when there is none; a run whose journal cannot be read, or that never
// started a step, is skipped.
func (d Dir) PreviousLastMutation(run, target string, start time.Time) time.Time {
	entries, err := os.ReadDir(filepath.Join(d.Root, "runs"))
	if err != nil {
		return time.Time{}
	}
	var last time.Time
	for _, e := range entries {
		if !e.IsDir() || e.Name() == run || !marker.ValidRunID(e.Name()) {
			continue
		}
		p, err := d.File(e.Name(), JournalFile)
		if err != nil {
			continue
		}
		j, err := journal.Load(p)
		if err != nil || j.Header.Target != target {
			continue
		}
		for _, r := range j.Records {
			switch r.Kind {
			case journal.KindIntent, journal.KindResult, journal.KindError, journal.KindUndo:
				if !r.Time.After(start) && r.Time.After(last) {
					last = r.Time
				}
			}
		}
	}
	return last
}

// Info derives one run's state from its journal and its lock.
func (d Dir) Info(run string) RunInfo {
	info := RunInfo{Run: run}
	p, err := d.File(run, JournalFile)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	j, err := journal.Load(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Planned, but stopped before the journal existed: nothing was
			// touched. Show what was planned.
			info.State = StateNotStarted
			if pp, perr := d.File(run, PlanFile); perr == nil {
				var pl struct {
					Target    string `json:"target"`
					Technique string `json:"technique"`
				}
				if b, rerr := os.ReadFile(pp); rerr == nil && json.Unmarshal(b, &pl) == nil {
					info.Target, info.Technique = pl.Target, pl.Technique
				}
			}
			return info
		}
		info.Error = err.Error()
		return info
	}
	info.Target = j.Header.Target
	info.Technique = j.Header.Technique
	info.Started = j.Header.Started
	info.Pending = len(j.Pending())
	lockPath, _ := d.File(run, runLockFile)
	info.State = DeriveState(j, fsutil.IsLocked(lockPath))
	return info
}

// DeriveState is the run's state as a pure function of its journal and
// whether a live process holds the run lock.
func DeriveState(j *journal.Journal, locked bool) string {
	last := j.LastPhase()
	lastCleanup := ""
	for _, p := range j.Phases() {
		switch p {
		case journal.PhaseCleanupVerified, journal.PhaseCleanupFailed, journal.PhaseCleanupAbandoned:
			lastCleanup = p
		}
	}
	switch {
	case locked && last != journal.PhaseComplete:
		return StateRunning
	case len(j.Pending()) > 0 && lastCleanup == journal.PhaseCleanupFailed:
		return StateCleanupUnverified
	case len(j.Pending()) > 0:
		return StateCleanupPending
	case last == journal.PhaseComplete:
		return StateComplete
	default:
		return StateCleaned
	}
}
