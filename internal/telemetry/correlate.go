package telemetry

import (
	"fmt"
	"time"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Signal is how an event was attributed to the run.
type Signal string

// Correlation signals, strongest first.
const (
	// SignalUserAgent: the User-Agent the platform recorded carries this
	// run's marker. It is the primary signal, and the only one that says
	// which phase of the run made the request.
	SignalUserAgent Signal = "user-agent"
	// SignalNamePrefix: the User-Agent did not survive, and the event names
	// an object of this run (saashound-<run>-<step>).
	SignalNamePrefix Signal = "name-prefix"
	// SignalHashedToken: the User-Agent did not survive, and the platform
	// recorded this run's own credential for the request (GitHub's
	// hashed_token).
	SignalHashedToken Signal = "hashed-token"
)

// Window is the run's span from its journal, by this machine's clock (see
// journal.Span). Every correlation is bounded by it, widened by the
// collector's Skew: an event the platform stamped outside it is never the
// run's, whatever it carries. The window narrows; it never correlates an
// event on its own. A zero Window bounds nothing, and then only the
// User-Agent can correlate.
type Window struct {
	// Start is the run's first mutation (its first journalled intent).
	Start time.Time
	// DetonateEnd is when detonation ended; cleanup calls come after it.
	DetonateEnd time.Time
	// End is when cleanup ended.
	End time.Time
	// PreviousMutation is the last mutation of the latest earlier run on the
	// same target, by its journal. Consecutive runs on one target
	// authenticate with the same credential, so the credential alone cannot
	// tell this run's events from that run's inside the skew before Start,
	// and the platform's clock may lead or lag this machine's. An event
	// correlated by the credential only must therefore be stamped after the
	// midpoint between PreviousMutation and Start, which leaves half the gap
	// between the two runs as clock tolerance each way; once the gap exceeds
	// twice the skew the midpoint lies outside the window and no longer
	// binds. A zero PreviousMutation bounds nothing (no earlier run is known
	// locally).
	PreviousMutation time.Time
}

// correlation is how one event was attributed to the run.
type correlation struct {
	phase  marker.Phase
	signal Signal
	// phaseNote says how a fallback match's phase was read, for -vv.
	phaseNote string
}

// String describes the correlation for -vv.
func (m correlation) String() string {
	if m.phaseNote == "" {
		return fmt.Sprintf("phase=%s by %s", m.phase, m.signal)
	}
	return fmt.Sprintf("by %s, phase=%s %s", m.signal, m.phase, m.phaseNote)
}

// correlator decides, event by event, which events are the run's.
//
// The User-Agent marker is authoritative: a marker naming this run
// correlates the event (with the phase it names), and a marker naming
// another run rules the event out. When the platform recorded no
// User-Agent, or only a truncated one, a run-specific signal stands in: the
// event names one of this run's objects, or the platform recorded this
// run's credential for it. That fallback never correlates an event that
//
//   - was recorded with another client's User-Agent (a person, the platform
//     itself or another tool made the request),
//   - names another run's object, or keeps enough of a marker to name
//     another run,
//   - carries no run-specific signal at all (the window alone is never
//     enough, and neither is a truncated marker that still names this run:
//     it is only explained as a near miss), or
//   - has no platform timestamp, or one outside the run window, or
//   - carries this run's credential as its only signal and is stamped
//     closer to the previous run on the same target than to this one (see
//     Window.PreviousMutation): that run used the same credential.
//
// A fallback match has no marker to say which phase made it, so the phase
// is read off the platform's timestamp: more than the skew before the end of
// detonation it is detonate, more than the skew after it cleanup. In between
// a cleanup call cannot be told from the last detonation call by time alone,
// and the event is assumed to be detonate, so it can still meet the
// expectation of the step that caused it; the collector takes the earliest
// matching event for an expectation, and on the platform's clock a step's
// own event comes before the one its undo causes.
type correlator struct {
	run        string
	window     Window
	skew       time.Duration
	credential string
}

// judge correlates ev to the run. When it does not, nearMiss explains why if
// ev carried a run-specific signal, so -vv can show an operator an event
// that looked like the run's but was ruled out.
func (k correlator) judge(ev provider.Event) (m correlation, ok bool, nearMiss string) {
	ua, kind := marker.InspectUserAgent(ev.UserAgent)
	switch kind {
	case marker.UAMarker:
		if ua.Run != k.run {
			return m, false, "" // another run's
		}
		// An event the platform did not stamp cannot be placed in the
		// window, but its marker alone identifies it exactly.
		if !ev.Time.IsZero() && !k.inWindow(ev.Time) {
			return m, false, "carries this run's User-Agent but is stamped outside the run window"
		}
		return correlation{phase: ua.Phase, signal: SignalUserAgent}, true, ""
	case marker.UAForeign:
		ours, _ := k.names(ev)
		if sig := k.signal(ev, ours); sig != "" {
			return m, false, "matches this run by " + string(sig) + " but was recorded with another client's User-Agent"
		}
		return m, false, ""
	case marker.UADamaged:
		if ua.Run != "" && ua.Run != k.run {
			return m, false, "" // what is left of the marker names another run
		}
	}

	// The User-Agent did not survive: fall back to a run-specific signal,
	// bounded by the run window. Ops only ever touch their own run's
	// objects, so an event naming another run's is not this run's, whatever
	// else it carries.
	ours, others := k.names(ev)
	sig := k.signal(ev, ours)
	switch {
	case others && ours:
		return m, false, "names objects of this run and of another run"
	case others:
		return m, false, ""
	case sig == "" && kind == marker.UADamaged && ua.Run == k.run:
		return m, false, "carries a truncated User-Agent naming this run but no object name or credential to correlate it"
	case sig == "":
		return m, false, ""
	case k.window.Start.IsZero():
		return m, false, "matches this run by " + string(sig) + " but its User-Agent did not survive and there is no run window to bound it"
	case ev.Time.IsZero():
		return m, false, "matches this run by " + string(sig) + " but its User-Agent did not survive and it has no platform timestamp to place in the run window"
	case !k.inWindow(ev.Time):
		return m, false, "matches this run by " + string(sig) + " but its User-Agent did not survive and it is stamped outside the run window"
	case sig == SignalHashedToken && k.nearerPreviousRun(ev.Time):
		return m, false, "carries this run's credential but its User-Agent did not survive and it is stamped closer to the previous run on this target than to this one"
	}
	m = correlation{phase: marker.PhaseDetonate, signal: sig, phaseNote: "from its timestamp"}
	switch end := k.window.DetonateEnd; {
	case ev.Time.After(end.Add(k.skew)):
		m.phase = marker.PhaseCleanup
	case !ev.Time.Before(end.Add(-k.skew)):
		m.phaseNote = "assumed: stamped too close to the end of detonation to tell from cleanup"
	}
	return m, true, ""
}

// names reports whether ev names one of this run's objects, and whether it
// names another run's.
func (k correlator) names(ev provider.Event) (ours, others bool) {
	for _, v := range ev.Objects {
		for _, name := range marker.FindObjectNames(v) {
			if run, _, _ := marker.ParseObjectName(name); run == k.run {
				ours = true
			} else {
				others = true
			}
		}
	}
	return ours, others
}

// signal returns the run-specific signal ev carries besides its User-Agent:
// one of this run's object names (ours, from names), else this run's
// credential.
func (k correlator) signal(ev provider.Event, ours bool) Signal {
	switch {
	case ours:
		return SignalNamePrefix
	case k.credential != "" && ev.Credential == k.credential:
		return SignalHashedToken
	}
	return ""
}

// inWindow reports whether a platform timestamp falls in the run window,
// widened by the skew on both sides. A zero window bounds nothing.
func (k correlator) inWindow(t time.Time) bool {
	if k.window.Start.IsZero() {
		return true
	}
	return !t.Before(k.window.Start.Add(-k.skew)) && !t.After(k.window.End.Add(k.skew))
}

// nearerPreviousRun reports whether a platform timestamp is no later than
// the midpoint between the previous run's last mutation on the same target
// and this run's first. A zero PreviousMutation bounds nothing.
func (k correlator) nearerPreviousRun(t time.Time) bool {
	prev := k.window.PreviousMutation
	if prev.IsZero() || prev.After(k.window.Start) {
		return false
	}
	return !t.After(prev.Add(k.window.Start.Sub(prev) / 2))
}
