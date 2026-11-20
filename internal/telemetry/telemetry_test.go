package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

func TestValues(t *testing.T) {
	doc, err := Decode(json.RawMessage(`{"eventType":"x","n":7,"ok":true,"target":[{"id":"a","type":"User"},{"id":"b"},"junk",{"id":{"nested":1}}],"actor":{"id":"p"},"nil":null}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"eventType":   {"x"},
		"n":           {"7"},
		"ok":          {"true"},
		"target[].id": {"a", "b"},
		"actor.id":    {"p"},
		"actor[].id":  nil, // not an array
		"target.id":   nil, // an array without []
		"missing.x":   nil,
		"nil":         nil,
	}
	for path, want := range cases {
		got := Values(doc, path)
		if fmt.Sprint(got) != fmt.Sprint(want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("Values(%q) = %v, want %v", path, got, want)
		}
	}
	if !Matches(doc, map[string]string{"eventType": "x", "target[].id": "b"}) {
		t.Error("expected match")
	}
	if Matches(doc, map[string]string{"eventType": "x", "target[].id": "c"}) {
		t.Error("unexpected match")
	}
}

// source is a scripted audit log: events become visible at their time.
type source struct {
	mu     sync.Mutex
	clk    clock.Clock
	events []timed
	polls  int
	onPoll func(n int)
	// fail, if set, makes poll n fail with the error it returns.
	fail func(n int) error
}

type timed struct {
	visible time.Time
	ev      provider.Event
}

func (s *source) add(visible time.Time, id, typ, ua, target string) {
	s.addAt(visible, visible, id, typ, ua, target)
}

// addAt adds an event the platform stamped published and made readable at
// visible.
func (s *source) addAt(published, visible time.Time, id, typ, ua, target string) {
	raw, _ := json.Marshal(map[string]any{"uuid": id, "eventType": typ, "target": []map[string]string{{"id": target}}})
	s.events = append(s.events, timed{visible, provider.Event{ID: id, Time: published, Type: typ, UserAgent: ua, Raw: raw}})
}

func (s *source) Poll(_ context.Context, q provider.AuditQuery) ([]provider.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.polls++
	if s.onPoll != nil {
		s.onPoll(s.polls)
	}
	if s.fail != nil {
		if err := s.fail(s.polls); err != nil {
			return nil, err
		}
	}
	var out []provider.Event
	for _, e := range s.events {
		if !e.visible.After(s.clk.Now()) {
			out = append(out, e.ev)
		}
	}
	return out, nil
}

func TestCollectorCorrelatesAndClassifies(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	run := "k3v9q2"
	det := marker.UserAgent("1", run, marker.PhaseDetonate)
	cln := marker.UserAgent("1", run, marker.PhaseCleanup)
	other := marker.UserAgent("1", "p7m2xw", marker.PhaseDetonate)

	src.add(t0, "e1", "user.lifecycle.create", det, "u1")                        // observed at once
	src.add(t0, "e1", "user.lifecycle.create", det, "u1")                        // duplicate delivery
	src.add(t0, "e2", "user.mfa.factor.activate", other, "u1")                   // another run: never ours
	src.add(t0, "e3", "user.mfa.factor.activate", "Mozilla/5.0", "u1")           // a person
	src.add(t0, "e4", "user.mfa.factor.activate", cln, "u1")                     // our cleanup: never matches
	src.add(t0.Add(40*time.Second), "e5", "user.mfa.factor.activate", det, "u1") // late: deadline 30s
	src.add(t0.Add(10*time.Second), "e6", "user.account.privilege.grant", det, "u2")

	exps := []Expectation{
		{After: "victim", Type: "user.lifecycle.create", Match: map[string]string{"eventType": "user.lifecycle.create", "target[].id": "u1"}, Deadline: 30 * time.Second, ActionAt: t0},
		{After: "factor", Type: "user.mfa.factor.activate", Match: map[string]string{"eventType": "user.mfa.factor.activate"}, Deadline: 30 * time.Second, ActionAt: t0},
		{After: "grant", Type: "user.account.privilege.grant", Match: map[string]string{"eventType": "user.account.privilege.grant", "target[].id": "u2"}, Deadline: 60 * time.Second, ActionAt: t0},
		{After: "reset", Type: "user.mfa.factor.reset_all", Match: map[string]string{"eventType": "user.mfa.factor.reset_all"}, Deadline: 45 * time.Second, ActionAt: t0},
		{After: "never", Type: "x", Match: map[string]string{"eventType": "x"}, Deadline: time.Minute},
	}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk}
	res := c.Collect(context.Background(), run, t0, exps)

	want := []string{StatusObserved, StatusLate, StatusObserved, StatusMissing, StatusNotRun}
	for i, o := range res.Outcomes {
		if o.Status != want[i] {
			t.Errorf("expect[%d] %s = %s, want %s", i, o.Type, o.Status, want[i])
		}
	}
	if res.Outcomes[0].EventID != "e1" || *res.Outcomes[0].LatencyS != 0 {
		t.Errorf("observed outcome = %+v", res.Outcomes[0])
	}
	if res.Outcomes[1].EventID != "e5" || *res.Outcomes[1].LatencyS != 40 {
		t.Errorf("late outcome = %+v (cleanup and foreign events must not match)", res.Outcomes[1])
	}
	if res.Outcomes[2].LatencyS == nil || *res.Outcomes[2].LatencyS != 10 {
		t.Errorf("latency is measured to the poll that first saw the event: %+v", res.Outcomes[2])
	}
	ids := map[string]bool{}
	for _, e := range res.Events {
		if ids[e.ID] {
			t.Errorf("event %s kept twice", e.ID)
		}
		ids[e.ID] = true
	}
	if ids["e2"] || ids["e3"] || !ids["e4"] || !ids["e1"] || !ids["e5"] {
		t.Errorf("kept events %v: want exactly this run's, both phases", ids)
	}
	// The collector stops at the last deadline, not later.
	if got := clk.Now().Sub(t0); got != 60*time.Second {
		t.Errorf("collector ran until +%s; want +60s, the last deadline", got)
	}
}

func TestCollectorStopsWhenAllMet(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	run := "k3v9q2"
	src.add(t0, "e1", "a", marker.UserAgent("1", run, marker.PhaseDetonate), "u")
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: time.Second}, Clock: clk}
	res := c.Collect(context.Background(), run, t0, []Expectation{{Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: time.Hour, ActionAt: t0}})
	if res.Outcomes[0].Status != StatusObserved || src.polls != 1 || !clk.Now().Equal(t0) {
		t.Fatalf("status=%s polls=%d elapsed=%s; want one poll", res.Outcomes[0].Status, src.polls, clk.Now().Sub(t0))
	}
	if u := Unsupported([]Expectation{{Type: "a", ActionAt: t0}}); u[0].Status != StatusUnsupported {
		t.Fatalf("Unsupported = %+v", u)
	}
}

// TestCollectorFirstPollAfterDeadline: collection starts after cleanup. When
// that is already past a deadline, when the collector first saw an event
// says nothing about when the platform logged it, so the platform's own
// timestamp decides.
func TestCollectorFirstPollAfterDeadline(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0.Add(50 * time.Second)) // cleanup took 50s
	src := &source{clk: clk}
	run := "k3v9q2"
	det := marker.UserAgent("1", run, marker.PhaseDetonate)
	src.addAt(t0.Add(5*time.Second), t0.Add(5*time.Second), "e1", "a", det, "u")
	src.addAt(t0.Add(30*time.Second), t0.Add(31*time.Second), "e2", "b", det, "u") // stamped exactly at the deadline
	src.addAt(t0.Add(40*time.Second), t0.Add(40*time.Second), "e3", "c", det, "u") // stamped past it
	src.addAt(time.Time{}, t0, "e4", "d", det, "u")                                // no platform timestamp: no proof it was on time
	src.addAt(t0.Add(5*time.Second), t0.Add(70*time.Second), "e5", "e", det, "u")  // polled in time, readable only after

	exp := func(typ string, deadline time.Duration) Expectation {
		return Expectation{After: typ, Type: typ, Match: map[string]string{"eventType": typ}, Deadline: deadline, ActionAt: t0}
	}
	exps := []Expectation{exp("a", 30*time.Second), exp("b", 30*time.Second), exp("c", 30*time.Second), exp("d", 30*time.Second), exp("e", 60*time.Second), exp("f", 80*time.Second)}
	src.add(t0.Add(70*time.Second), "e6", "f", det, "u")
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk}
	res := c.Collect(context.Background(), run, t0, exps)

	want := []string{StatusObserved, StatusObserved, StatusLate, StatusLate, StatusLate, StatusObserved}
	for i, o := range res.Outcomes {
		if o.Status != want[i] {
			t.Errorf("expect[%d] %s = %s, want %s", i, o.Type, o.Status, want[i])
		}
	}
	if res.Error != "" {
		t.Errorf("error %q", res.Error)
	}
	// Latency stays what the collector measured: an upper bound.
	if l := res.Outcomes[0].LatencyS; l == nil || *l != 50 {
		t.Errorf("latency = %v, want 50", l)
	}
}

// TestCollectorInterrupted: a cancelled collection has not checked the
// expectations still pending, so they are not-run, never missing.
func TestCollectorInterrupted(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	run := "k3v9q2"
	det := marker.UserAgent("1", run, marker.PhaseDetonate)
	src.add(t0, "e1", "a", det, "u")
	src.add(t0.Add(20*time.Second), "e2", "b", det, "u")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onPoll = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	exps := []Expectation{
		{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: time.Minute, ActionAt: t0},
		{After: "b", Type: "b", Match: map[string]string{"eventType": "b"}, Deadline: time.Minute, ActionAt: t0},
		{After: "c", Type: "c", Match: map[string]string{"eventType": "c"}, Deadline: time.Minute, ActionAt: t0},
	}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk}
	res := c.Collect(ctx, run, t0, exps)
	want := []string{StatusObserved, StatusNotRun, StatusNotRun}
	for i, o := range res.Outcomes {
		if o.Status != want[i] {
			t.Errorf("expect[%d] %s = %s, want %s", i, o.Type, o.Status, want[i])
		}
	}
	if !strings.HasPrefix(res.Error, Interrupted) {
		t.Errorf("error %q, want it to say collection was interrupted", res.Error)
	}
	if src.polls != 2 {
		t.Errorf("%d polls after the interrupt; want none", src.polls-2)
	}
}

// waitingFor is a drain predicate standing in for a detection checker: it
// waits until an event of type typ has been collected.
func waitingFor(typ string, calls *int) func([]Seen) bool {
	return func(evs []Seen) bool {
		*calls++
		for _, e := range evs {
			if e.Type == typ {
				return false
			}
		}
		return true
	}
}

// TestCollectorDrainsForAWaitingDetection is the false not-fired trap: the
// expectation is met at once, but the event a detection keys on, which no
// expectation asked for, lands 600ms later. The collector keeps polling for
// it, stops as soon as it is read, and leaves the outcomes as they were.
func TestCollectorDrainsForAWaitingDetection(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	run := "k3v9q2"
	det := marker.UserAgent("1", run, marker.PhaseDetonate)
	src.add(t0, "e1", "a", det, "u")
	src.add(t0.Add(600*time.Millisecond), "e2", "b", det, "u")
	calls := 0
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 250 * time.Millisecond}, Clock: clk, Await: waitingFor("b", &calls)}
	res := c.Collect(context.Background(), run, t0, []Expectation{{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: 30 * time.Second, ActionAt: t0}})

	if o := res.Outcomes[0]; o.Status != StatusObserved || o.EventID != "e1" || *o.LatencyS != 0 {
		t.Fatalf("the drain must not change the outcome: %+v", o)
	}
	if len(res.Events) != 2 || res.Events[1].ID != "e2" || !res.Events[1].FirstSeen.Equal(t0.Add(750*time.Millisecond)) {
		t.Fatalf("events %+v; want e2 read by the third drain poll", res.Events)
	}
	if src.polls != 4 || !clk.Now().Equal(t0.Add(750*time.Millisecond)) {
		t.Fatalf("polls=%d elapsed=%s; want the drain to stop as soon as nothing waits (4 polls, 750ms)", src.polls, clk.Now().Sub(t0))
	}
	if calls != 2 {
		t.Errorf("Await called %d times; want once at the start and once when new events arrived", calls)
	}
	if res.Error != "" || res.Unsettled != Settled {
		t.Errorf("error %q unsettled %q", res.Error, res.Unsettled)
	}
}

// TestCollectorDrainIsBounded: an event a detection waits for that never
// arrives cannot hold a run: the drain stops after DrainPolls polls, one
// interval apart. A failed drain poll is retried, never reported as a
// telemetry error, since every expectation was already resolved, and the
// successful polls after it re-read the whole window, so the end is settled.
func TestCollectorDrainIsBounded(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	src.fail = func(n int) error {
		if n == 2 || n == DrainPolls {
			return errors.New("503 service unavailable")
		}
		return nil
	}
	run := "k3v9q2"
	src.add(t0, "e1", "a", marker.UserAgent("1", run, marker.PhaseDetonate), "u")
	const interval = 2 * time.Second
	calls := 0
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: interval}, Clock: clk, Await: waitingFor("never", &calls)}
	res := c.Collect(context.Background(), run, t0, []Expectation{{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: time.Hour, ActionAt: t0}})

	if src.polls != 1+DrainPolls {
		t.Fatalf("%d polls; want 1 plus %d drain polls", src.polls, DrainPolls)
	}
	if got, want := clk.Now().Sub(t0), DrainPolls*interval; got != want {
		t.Fatalf("collection took %s; the drain is bounded at %s, well inside the 1h deadline", got, want)
	}
	if res.Outcomes[0].Status != StatusObserved || res.Error != "" || res.Unsettled != Settled || res.DrainError != "" {
		t.Fatalf("outcome %+v error %q unsettled %q (%q); a spent drain whose last poll read the log is an honest end, not an error", res.Outcomes[0], res.Error, res.Unsettled, res.DrainError)
	}
}

// TestCollectorDrainEndingOnAFailedPoll: a drain that spends its polls and
// whose last one failed did not read the audit log to its end, so the result
// says a detection was still waiting on an audit API failure and carries the
// error. An earlier successful poll does not cover the failed last one. The
// drain stays bounded and the telemetry stays as it was resolved.
func TestCollectorDrainEndingOnAFailedPoll(t *testing.T) {
	cases := []struct {
		name string
		fail func(n int) bool
	}{
		{"every drain poll fails", func(n int) bool { return n > 1 }},
		{"only the last drain poll fails", func(n int) bool { return n == 1+DrainPolls }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			clk := clock.NewFake(t0)
			src := &source{clk: clk}
			src.fail = func(n int) error {
				if tc.fail(n) {
					return fmt.Errorf("503 service unavailable (poll %d)", n)
				}
				return nil
			}
			run := "k3v9q2"
			src.add(t0, "e1", "a", marker.UserAgent("1", run, marker.PhaseDetonate), "u")
			const interval = 2 * time.Second
			calls := 0
			c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: interval}, Clock: clk, Await: waitingFor("never", &calls)}
			res := c.Collect(context.Background(), run, t0, []Expectation{{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: time.Hour, ActionAt: t0}})

			if src.polls != 1+DrainPolls {
				t.Fatalf("%d polls; want 1 plus %d drain polls", src.polls, DrainPolls)
			}
			if got, want := clk.Now().Sub(t0), DrainPolls*interval; got != want {
				t.Fatalf("collection took %s; the drain is bounded at %s", got, want)
			}
			if want := fmt.Sprintf("503 service unavailable (poll %d)", 1+DrainPolls); res.Unsettled != UnsettledAuditFailure || res.DrainError != want {
				t.Fatalf("unsettled %q (%q); want %q with the last poll's error %q", res.Unsettled, res.DrainError, UnsettledAuditFailure, want)
			}
			if o := res.Outcomes[0]; o.Status != StatusObserved || o.EventID != "e1" || res.Error != "" {
				t.Fatalf("outcome %+v error %q; a failed drain poll must not touch the telemetry", o, res.Error)
			}
		})
	}
}

// TestCollectorDrainFollowsOnlyACompleteCollection: the drain widens the
// events of a collection that saw every expected event, and nothing else.
func TestCollectorDrainFollowsOnlyACompleteCollection(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	run := "k3v9q2"
	det := marker.UserAgent("1", run, marker.PhaseDetonate)
	exp := func(typ string, at time.Time) Expectation {
		return Expectation{After: typ, Type: typ, Match: map[string]string{"eventType": typ}, Deadline: 10 * time.Second, ActionAt: at}
	}
	cases := []struct {
		name  string
		exps  []Expectation
		await func([]Seen) bool
		polls int
		took  time.Duration
	}{
		// Polled every second up to the deadline; the verdict is
		// telemetry-missing, so no drain follows.
		{"an expectation missing", []Expectation{exp("a", t0), exp("b", t0)}, func([]Seen) bool { return true }, 11, 10 * time.Second},
		// The step for b never completed (detonation stopped): no drain.
		{"an expectation not-run", []Expectation{exp("a", t0), exp("b", time.Time{})}, func([]Seen) bool { return true }, 1, 0},
		// Every detection already decided: nothing to wait for.
		{"nothing waiting", []Expectation{exp("a", t0)}, func([]Seen) bool { return false }, 1, 0},
		{"no checker awaits", []Expectation{exp("a", t0)}, nil, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := clock.NewFake(t0)
			src := &source{clk: clk}
			src.add(t0, "e1", "a", det, "u")
			c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: time.Second}, Clock: clk, Await: tc.await}
			res := c.Collect(context.Background(), run, t0, tc.exps)
			if src.polls != tc.polls || clk.Now().Sub(t0) != tc.took {
				t.Fatalf("polls=%d took %s; want %d polls, %s", src.polls, clk.Now().Sub(t0), tc.polls, tc.took)
			}
			if res.Unsettled != Settled {
				t.Fatal("unsettled without a drain")
			}
		})
	}
}

// TestCollectorDrainInterrupted: Ctrl-C during the drain stops it at once.
// The telemetry stays fully checked (no error, nothing not-run), and the
// result says a detection was still waiting, so its "did not fire" is
// unproven. An event read by the poll the interrupt cut short still counts:
// a fire is final.
func TestCollectorDrainInterrupted(t *testing.T) {
	for _, arrives := range []bool{false, true} {
		t.Run(fmt.Sprintf("awaited event read=%v", arrives), func(t *testing.T) {
			t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			clk := clock.NewFake(t0)
			src := &source{clk: clk}
			run := "k3v9q2"
			det := marker.UserAgent("1", run, marker.PhaseDetonate)
			src.add(t0, "e1", "a", det, "u")
			if arrives {
				src.add(t0.Add(time.Second), "e2", "b", det, "u")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			src.onPoll = func(n int) {
				if n == 2 {
					cancel()
				}
			}
			calls := 0
			c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: time.Second}, Clock: clk, Await: waitingFor("b", &calls)}
			res := c.Collect(ctx, run, t0, []Expectation{{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: time.Minute, ActionAt: t0}})
			want := UnsettledInterrupted
			if arrives {
				want = Settled
			}
			if res.Unsettled != want || res.DrainError != "" {
				t.Fatalf("unsettled=%q (%q); want %q", res.Unsettled, res.DrainError, want)
			}
			if src.polls != 2 {
				t.Fatalf("%d polls; want none after the interrupt", src.polls)
			}
			if res.Outcomes[0].Status != StatusObserved || res.Error != "" {
				t.Fatalf("outcome %+v error %q; an interrupted drain must not touch the telemetry", res.Outcomes[0], res.Error)
			}
		})
	}
}

// addEvent adds ev, readable from visible.
func (s *source) addEvent(visible time.Time, ev provider.Event) {
	s.events = append(s.events, timed{visible, ev})
}

// credSource is an audit source whose platform records the credential
// behind each event, as GitHub's hashed_token does.
type credSource struct {
	*source
	cred string
}

func (c credSource) RecordedCredential() string { return c.cred }

// oktaEvent is an Okta-shaped event: what the platform recorded, with the
// target ids the expectations match on and the target names the provider
// reports as Objects.
func oktaEvent(at time.Time, id, typ, ua, targetID string, names ...string) provider.Event {
	targets := []map[string]string{{"id": targetID}}
	for _, n := range names {
		targets = append(targets, map[string]string{"id": "x", "alternateId": n})
	}
	raw, _ := json.Marshal(map[string]any{"uuid": id, "eventType": typ, "target": targets})
	return provider.Event{ID: id, Time: at, Type: typ, UserAgent: ua, Objects: names, Raw: raw}
}

// githubEvent is a GitHub-shaped event: repo carries the owner and the name,
// hashed_token the credential.
func githubEvent(at time.Time, id, action, ua, repoID, repo, hashedToken string) provider.Event {
	raw, _ := json.Marshal(map[string]any{"_document_id": id, "action": action, "repo": repo, "repo_id": repoID, "hashed_token": hashedToken})
	ev := provider.Event{ID: id, Time: at, Type: action, UserAgent: ua, Credential: hashedToken, Raw: raw}
	if repo != "" {
		ev.Objects = []string{repo}
	}
	return ev
}

// runWindow is a run that mutated from t0+1s, ended detonation at t0+10s and
// finished cleanup at t0+20s.
func runWindow(t0 time.Time) Window {
	return Window{Start: t0.Add(time.Second), DetonateEnd: t0.Add(10 * time.Second), End: t0.Add(20 * time.Second)}
}

// TestCollectorCorrelatesWithoutUserAgent: a platform that records no
// User-Agent, or a truncated one, still yields the run's events, matched by
// the run's object names inside the run window, with the phase read off the
// platform's timestamp.
func TestCollectorCorrelatesWithoutUserAgent(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0.Add(25 * time.Second)) // collection starts after cleanup
	src := &source{clk: clk}
	run := "k3v9q2"
	victim := marker.ObjectName(run, "victim") + "@lab.example.com"
	truncated := marker.UserAgent("1", run, marker.PhaseDetonate)[:24]

	src.addEvent(t0, oktaEvent(t0.Add(2*time.Second), "e1", "user.lifecycle.create", "", "u1", victim))
	src.addEvent(t0, oktaEvent(t0.Add(4*time.Second), "e2", "user.mfa.factor.activate", truncated, "u1", victim))
	// The cleanup's own events, after detonation ended plus the skew: cleanup
	// phase, so they never satisfy an expectation.
	src.addEvent(t0, oktaEvent(t0.Add(18*time.Second), "e3", "user.lifecycle.delete", "", "u1", victim))

	exps := []Expectation{
		{After: "victim", Type: "user.lifecycle.create", Match: map[string]string{"eventType": "user.lifecycle.create", "target[].id": "u1"}, Deadline: 30 * time.Second, ActionAt: t0.Add(2 * time.Second)},
		{After: "factor", Type: "user.mfa.factor.activate", Match: map[string]string{"eventType": "user.mfa.factor.activate", "target[].id": "u1"}, Deadline: 30 * time.Second, ActionAt: t0.Add(4 * time.Second)},
		{After: "victim", Type: "user.lifecycle.delete", Match: map[string]string{"eventType": "user.lifecycle.delete"}, Deadline: 30 * time.Second, ActionAt: t0.Add(2 * time.Second)},
	}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk, Skew: 5 * time.Second, Window: runWindow(t0)}
	res := c.Collect(context.Background(), run, t0, exps)

	want := []struct {
		status string
		event  string
		by     Signal
	}{{StatusObserved, "e1", SignalNamePrefix}, {StatusObserved, "e2", SignalNamePrefix}, {StatusMissing, "", ""}}
	for i, w := range want {
		o := res.Outcomes[i]
		if o.Status != w.status || o.EventID != w.event || o.Correlation != w.by {
			t.Errorf("expect[%d] %s = %s by %q (%s); want %s by %q (%s)", i, o.Type, o.Status, o.Correlation, o.EventID, w.status, w.by, w.event)
		}
	}
	phases := map[string]marker.Phase{}
	for _, e := range res.Events {
		phases[e.ID] = e.Phase
		if e.Correlation != SignalNamePrefix {
			t.Errorf("event %s correlated by %q, want name-prefix", e.ID, e.Correlation)
		}
	}
	if len(phases) != 3 || phases["e1"] != marker.PhaseDetonate || phases["e2"] != marker.PhaseDetonate || phases["e3"] != marker.PhaseCleanup {
		t.Errorf("kept events with phases %v; want e1, e2 detonate and e3 cleanup", phases)
	}
}

// TestCollectorPrefersTheStepsOwnEvent: without a User-Agent, the event a
// step caused and the event its undo caused can both match the step's
// expectation and both lie within the skew of the end of detonation. The
// step's own event is the earlier one on the platform's clock, and it wins
// even when the audit API returns the undo's first.
func TestCollectorPrefersTheStepsOwnEvent(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0.Add(25 * time.Second))
	src := &source{clk: clk}
	run := "k3v9q2"
	rule := marker.ObjectName(run, "rule")
	src.addEvent(t0, oktaEvent(t0.Add(10*time.Second+50*time.Millisecond), "restore", "policy.rule.update", "", "r1", rule))
	src.addEvent(t0, oktaEvent(t0.Add(9*time.Second), "weaken", "policy.rule.update", "", "r1", rule))
	exps := []Expectation{{After: "weaken", Type: "policy.rule.update", Match: map[string]string{"eventType": "policy.rule.update", "target[].id": "r1"}, Deadline: 30 * time.Second, ActionAt: t0.Add(9 * time.Second)}}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk, Skew: 5 * time.Second, Window: runWindow(t0)}
	res := c.Collect(context.Background(), run, t0, exps)
	if o := res.Outcomes[0]; o.Status != StatusObserved || o.EventID != "weaken" {
		t.Fatalf("outcome %+v; want observed by the step's own event", o)
	}
}

// TestCollectorCorrelatesByHashedToken: on GitHub, an event that names no
// run object (an org membership change) still correlates by the run's own
// credential, and a repository event by the run's repository name.
func TestCollectorCorrelatesByHashedToken(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0.Add(25 * time.Second))
	base := &source{clk: clk}
	src := credSource{source: base, cred: "k1i0g7C2T0eMlSdYnfQTXlTj2p5j1/yPzVTqkn9KQ5w="}
	run := "k3v9q2"
	repo := "acme-labs/" + marker.ObjectName(run, "repo")
	promote, _ := json.Marshal(map[string]any{"_document_id": "g1", "action": "org.update_member", "user": "octo-second", "hashed_token": src.cred})
	base.addEvent(t0, provider.Event{ID: "g1", Time: t0.Add(3 * time.Second), Type: "org.update_member", Credential: src.cred, Raw: promote})
	base.addEvent(t0, githubEvent(t0.Add(4*time.Second), "g2", "hook.create", "", "42", repo, ""))
	exps := []Expectation{
		{After: "promote", Type: "org.update_member", Match: map[string]string{"action": "org.update_member", "user": "octo-second"}, Deadline: time.Minute, ActionAt: t0.Add(3 * time.Second)},
		{After: "hook", Type: "hook.create", Match: map[string]string{"action": "hook.create", "repo_id": "42"}, Deadline: time.Minute, ActionAt: t0.Add(4 * time.Second)},
	}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk, Skew: 5 * time.Second, Window: runWindow(t0)}
	res := c.Collect(context.Background(), run, t0, exps)
	if o := res.Outcomes[0]; o.Status != StatusObserved || o.Correlation != SignalHashedToken {
		t.Errorf("promote outcome %+v; want observed by hashed-token", o)
	}
	if o := res.Outcomes[1]; o.Status != StatusObserved || o.Correlation != SignalNamePrefix {
		t.Errorf("hook outcome %+v; want observed by name-prefix", o)
	}
}

// TestCollectorBoundsHashedTokenByThePreviousRun: consecutive runs on one
// target share a credential, so an event whose only signal is the credential
// must be stamped after the midpoint between the previous run's last
// mutation and this run's first, which tolerates a platform clock leading or
// lagging by less than half the gap. An event naming this run's object is
// this run's wherever it falls in the window.
func TestCollectorBoundsHashedTokenByThePreviousRun(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	cred := "k1i0g7C2T0eMlSdYnfQTXlTj2p5j1/yPzVTqkn9KQ5w="
	run := "k3v9q2"
	skew := 5 * time.Second
	member := func(at time.Time, id string) provider.Event {
		raw, _ := json.Marshal(map[string]any{"_document_id": id, "action": "org.update_member", "user": "octo-second", "hashed_token": cred})
		return provider.Event{ID: id, Time: at, Type: "org.update_member", Credential: cred, Raw: raw}
	}
	const nearer = " org.update_member not correlated: carries this run's credential but its User-Agent did not survive and it is stamped closer to the previous run on this target than to this one"
	// collect runs the collector over evs and returns the signal each kept
	// event was correlated by, the outcomes and the -vv trace.
	collect := func(w Window, evs ...provider.Event) (map[string]Signal, []Outcome, string) {
		clk := clock.NewFake(t0.Add(25 * time.Second))
		base := &source{clk: clk}
		for _, ev := range evs {
			base.addEvent(t0, ev)
		}
		var traces []string
		exps := []Expectation{
			{After: "promote", Type: "org.update_member", Match: map[string]string{"action": "org.update_member", "user": "octo-second"}, Deadline: time.Minute, ActionAt: w.Start},
			{After: "hook", Type: "hook.create", Match: map[string]string{"action": "hook.create", "repo_id": "42"}, Deadline: time.Minute, ActionAt: w.Start},
		}
		c := &Collector{Source: credSource{source: base, cred: cred}, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk, Skew: skew, Window: w,
			Trace: func(format string, a ...any) { traces = append(traces, fmt.Sprintf(format, a...)) }}
		res := c.Collect(context.Background(), run, t0, exps)
		kept := map[string]Signal{}
		for _, e := range res.Events {
			kept[e.ID] = e.Correlation
		}
		return kept, res.Outcomes, strings.Join(traces, "\n")
	}

	t.Run("inside the skew", func(t *testing.T) {
		w := runWindow(t0)
		w.PreviousMutation = w.Start.Add(-4 * time.Second)
		mid := w.Start.Add(-2 * time.Second)
		repo := "acme-labs/" + marker.ObjectName(run, "repo")
		kept, outcomes, trace := collect(w,
			member(w.PreviousMutation.Add(time.Second), "previous-clock-ahead"),
			member(mid, "midpoint"),
			member(w.Start.Add(-time.Second), "own-clock-behind"),
			githubEvent(w.PreviousMutation.Add(time.Second), "named", "hook.create", "", "42", repo, cred))
		if o := outcomes[0]; o.Status != StatusObserved || o.EventID != "own-clock-behind" || o.Correlation != SignalHashedToken {
			t.Errorf("promote outcome %+v; want observed by the event stamped after the midpoint, by hashed-token", o)
		}
		if o := outcomes[1]; o.Status != StatusObserved || o.EventID != "named" || o.Correlation != SignalNamePrefix {
			t.Errorf("hook outcome %+v; want observed by name-prefix though stamped before the midpoint", o)
		}
		if len(kept) != 2 || kept["own-clock-behind"] != SignalHashedToken || kept["named"] != SignalNamePrefix {
			t.Errorf("kept events %v; want only own-clock-behind (hashed-token) and named (name-prefix)", kept)
		}
		for _, id := range []string{"previous-clock-ahead", "midpoint"} {
			if n := strings.Count(trace, "event "+id+nearer); n != 1 {
				t.Errorf("near miss %s traced %d times, want once:\n%s", id, n, trace)
			}
		}
	})

	t.Run("a gap of more than twice the skew", func(t *testing.T) {
		w := runWindow(t0)
		w.PreviousMutation = w.Start.Add(-2*skew - 2*time.Second) // the midpoint is one second outside the window
		kept, outcomes, trace := collect(w,
			member(w.Start.Add(-skew-time.Millisecond), "outside"),
			member(w.Start.Add(-skew), "edge"))
		if o := outcomes[0]; o.Status != StatusObserved || o.EventID != "edge" || o.Correlation != SignalHashedToken {
			t.Errorf("promote outcome %+v; want observed by the event at the window's edge", o)
		}
		if len(kept) != 1 {
			t.Errorf("kept events %v; want only edge", kept)
		}
		if !strings.Contains(trace, "event outside org.update_member not correlated: matches this run by hashed-token but its User-Agent did not survive and it is stamped outside the run window") {
			t.Errorf("the event before the window is not ruled out by the window:\n%s", trace)
		}
	})

	t.Run("no previous run", func(t *testing.T) {
		w := runWindow(t0)
		_, outcomes, _ := collect(w, member(w.Start.Add(-skew), "edge"), member(w.Start, "later"))
		if o := outcomes[0]; o.Status != StatusObserved || o.EventID != "edge" {
			t.Errorf("promote outcome %+v; want the earliest event in the window", o)
		}
	})
}

// TestCollectorNeverMisattributes: no event from another run, another
// client, or outside the run window is ever the run's, and the window alone
// never correlates anything. Every decoy below would satisfy the
// expectation if it were attributed to the run.
func TestCollectorNeverMisattributes(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0.Add(25 * time.Second))
	base := &source{clk: clk}
	ours := "k3v9q2"
	cred := "k1i0g7C2T0eMlSdYnfQTXlTj2p5j1/yPzVTqkn9KQ5w="
	src := credSource{source: base, cred: cred}
	ourName := marker.ObjectName(ours, "victim") + "@lab.example.com"
	otherName := marker.ObjectName("p7m2xw", "victim") + "@lab.example.com"
	inside := t0.Add(5 * time.Second)
	skew := 5 * time.Second
	w := runWindow(t0)

	decoys := []struct {
		why string
		ev  provider.Event
	}{
		{"another run's object, no User-Agent", oktaEvent(inside, "d1", "x", "", "u1", otherName)},
		{"another run's marker naming our object", oktaEvent(inside, "d2", "x", marker.UserAgent("1", "p7m2xw", marker.PhaseDetonate), "u1", ourName)},
		{"a truncated marker of another run naming our object", oktaEvent(inside, "d3", "x", "saashound/1 (run=p7m2xw; pha", "u1", ourName)},
		{"our object and another run's", oktaEvent(inside, "d4", "x", "", "u1", ourName, otherName)},
		{"our object, recorded with a person's browser", oktaEvent(inside, "d5", "x", "Mozilla/5.0 (X11; Linux x86_64)", "u1", ourName)},
		{"our object, recorded with another tool", oktaEvent(inside, "d6", "x", "terraform-provider-okta/4.0", "u1", ourName)},
		{"our object, stamped before the run window", oktaEvent(w.Start.Add(-skew-time.Millisecond), "d7", "x", "", "u1", ourName)},
		{"our object, stamped after the run window", oktaEvent(w.End.Add(skew+time.Millisecond), "d8", "x", "", "u1", ourName)},
		{"our object, no platform timestamp", oktaEvent(time.Time{}, "d9", "x", "", "u1", ourName)},
		{"inside the window, nothing run-specific", oktaEvent(inside, "d10", "x", "", "u1")},
		{"inside the window, another credential", githubEvent(inside, "d11", "x", "", "u1", "", "c29tZW9uZSBlbHNlJ3MgdG9rZW4=")},
		{"our credential, recorded with another tool", githubEvent(inside, "d12", "x", "gh/2.40.0", "u1", "", cred)},
		{"our marker, stamped after the run window", oktaEvent(w.End.Add(skew+time.Second), "d13", "x", marker.UserAgent("1", ours, marker.PhaseDetonate), "u1", ourName)},
		{"another run's repository, no User-Agent", githubEvent(inside, "d14", "x", "", "u1", "acme-labs/"+marker.ObjectName("p7m2xw", "repo"), "")},
		{"another run's repository, our credential", githubEvent(inside, "d15", "x", "", "u1", "acme-labs/"+marker.ObjectName("p7m2xw", "repo"), cred)},
		{"a name that only contains ours", oktaEvent(inside, "d16", "x", "", "u1", "x"+marker.ObjectName(ours, "victim"))},
		{"a truncated marker of our run, nothing run-specific", oktaEvent(inside, "d17", "x", "saashound/1 (run="+ours+"; pha", "u1")},
	}
	for _, d := range decoys {
		base.addEvent(t0, d.ev)
	}
	// The positive control: one genuine, UA-less event of this run.
	base.addEvent(t0, oktaEvent(inside, "ok", "y", "", "u1", ourName))

	var traces []string
	exps := []Expectation{
		{After: "a", Type: "x", Match: map[string]string{"eventType": "x", "target[].id": "u1"}, Deadline: 10 * time.Second, ActionAt: inside},
		{After: "b", Type: "y", Match: map[string]string{"eventType": "y", "target[].id": "u1"}, Deadline: 10 * time.Second, ActionAt: inside},
	}
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk, Skew: skew, Window: w,
		Trace: func(format string, a ...any) { traces = append(traces, fmt.Sprintf(format, a...)) }}
	res := c.Collect(context.Background(), ours, t0, exps)

	if o := res.Outcomes[0]; o.Status != StatusMissing || o.EventID != "" {
		t.Errorf("a decoy satisfied the expectation: %+v", o)
	}
	if o := res.Outcomes[1]; o.Status != StatusObserved || o.EventID != "ok" {
		t.Errorf("the genuine event did not: %+v", o)
	}
	for _, e := range res.Events {
		if e.ID != "ok" {
			for _, d := range decoys {
				if d.ev.ID == e.ID {
					t.Errorf("decoy %s (%s) was attributed to the run by %s", e.ID, d.why, e.Correlation)
				}
			}
		}
	}
	// Near misses are explained once each at -vv; plain foreign events are not.
	joined := strings.Join(traces, "\n")
	for _, id := range []string{"d4", "d5", "d6", "d7", "d8", "d9", "d12", "d13", "d17"} {
		if n := strings.Count(joined, "event "+id+" x not correlated"); n != 1 {
			t.Errorf("near miss %s traced %d times, want once:\n%s", id, n, joined)
		}
	}
	if !strings.Contains(joined, "event d9 x not correlated: matches this run by name-prefix but its User-Agent did not survive and it has no platform timestamp") {
		t.Errorf("the near miss without a timestamp does not say so:\n%s", joined)
	}
	if !strings.Contains(joined, "event d17 x not correlated: carries a truncated User-Agent naming this run but no object name or credential to correlate it") {
		t.Errorf("the near miss with only a truncated marker of this run does not say so:\n%s", joined)
	}
	for _, id := range []string{"d1", "d2", "d3", "d10", "d11", "d14", "d15", "d16"} {
		if strings.Contains(joined, "event "+id+" ") {
			t.Errorf("event %s carries nothing of this run's but was traced:\n%s", id, joined)
		}
	}
}

// TestCollectorWithoutWindowNeedsTheUserAgent: with no run window to bound
// it, the fallback never correlates; only the marker does.
func TestCollectorWithoutWindowNeedsTheUserAgent(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	src := &source{clk: clk}
	run := "k3v9q2"
	src.addEvent(t0, oktaEvent(t0, "e1", "a", "", "u1", marker.ObjectName(run, "victim")))
	c := &Collector{Source: src, Info: provider.AuditInfo{PollInterval: 5 * time.Second}, Clock: clk}
	res := c.Collect(context.Background(), run, t0, []Expectation{{After: "a", Type: "a", Match: map[string]string{"eventType": "a"}, Deadline: 5 * time.Second, ActionAt: t0}})
	if res.Outcomes[0].Status != StatusMissing || len(res.Events) != 0 {
		t.Fatalf("outcome %+v, events %d; want nothing correlated without a window", res.Outcomes[0], len(res.Events))
	}
}
