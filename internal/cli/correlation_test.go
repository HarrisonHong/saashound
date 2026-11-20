package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/providers/github/mockgithub"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// recordings are the ways a platform's audit log can fail to keep the
// User-Agent of an API request whole.
var recordings = map[string]func(string) string{
	"dropped":   func(string) string { return "" },
	"truncated": func(ua string) string { return ua[:min(len(ua), 24)] },
}

// expectationsOf returns a record's telemetry expectations.
func expectationsOf(t *testing.T, rec map[string]any) []map[string]any {
	t.Helper()
	tel := rec["telemetry"].(map[string]any)
	var out []map[string]any
	for _, x := range tel["expectations"].([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

// eventIDs returns the IDs of the events a run wrote to events.jsonl, read
// with the platform's own ID field.
func eventIDs(t *testing.T, stateDir, run, idField string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "runs", run, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("events.jsonl line %q: %v", line, err)
		}
		id, _ := ev[idField].(string)
		ids[id] = true
	}
	return ids
}

// TestOktaCorrelatesWithoutUserAgent: on an org whose System Log drops or
// truncates the User-Agent of API requests, every okta technique still
// passes, its events matched by the run's object names inside the run
// window, and the record and -v output say so.
func TestOktaCorrelatesWithoutUserAgent(t *testing.T) {
	for name, record := range recordings {
		for _, id := range oktaTechniques {
			t.Run(name+"/"+id, func(t *testing.T) {
				lab := newOktaLab(t, true, mockokta.WithRecordedUserAgent(record))
				before := lab.srv.Snapshot()
				r := lab.run("apply", id, "--target", "okta", "--yes", "-v")
				if r.code != report.ExitOK {
					t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
				}
				rec := records(t, r.stdout)[0]
				if rec["verdict"] != "pass" {
					t.Fatalf("verdict %v (reason %v)", rec["verdict"], rec["reason"])
				}
				exps := expectationsOf(t, rec)
				for _, x := range exps {
					if x["status"] != "observed" || x["correlation"] != "name-prefix" {
						t.Errorf("expectation %v %v by %v; want observed by name-prefix", x["event_type"], x["status"], x["correlation"])
					}
				}
				if !strings.Contains(r.stderr, "matched without the User-Agent: ") || !strings.Contains(r.stderr, " by name-prefix") {
					t.Errorf("progress does not say the match did not rest on the User-Agent:\n%s", r.stderr)
				}
				if !strings.Contains(r.stderr, " without a usable User-Agent, matched inside the run window") {
					t.Errorf("-v does not explain the correlation:\n%s", r.stderr)
				}
				// The mock really did lose the marker on every event.
				lab.srv.State(func(st *mockokta.State) {
					for _, le := range st.Log {
						var ev struct {
							Client struct {
								UserAgent struct {
									RawUserAgent string `json:"rawUserAgent"`
								} `json:"userAgent"`
							} `json:"client"`
						}
						_ = json.Unmarshal(le.Event, &ev)
						if _, ok := marker.ParseUserAgent(ev.Client.UserAgent.RawUserAgent); ok {
							t.Fatalf("the log kept a whole marker: %s", le.Event)
						}
					}
				})
				if ids := eventIDs(t, filepath.Join(lab.dir, "state"), rec["run"].(string), "uuid"); len(ids) < len(exps) {
					t.Errorf("events.jsonl has %d events, fewer than the %d expected", len(ids), len(exps))
				}
				if after := lab.srv.Snapshot(); string(after) != string(before) {
					t.Fatalf("tenant changed:\nbefore %s\nafter  %s", before, after)
				}
			})
		}
	}
}

// TestGithubCorrelatesWithoutUserAgent: on an org whose audit log drops or
// truncates the User-Agent, every github technique still passes: repository
// events by the run's repository name, and the org membership change, which
// names no run object, by the run's own hashed_token. Without hashed_token
// that one has nothing left to tie it to the run and is missing, rather than
// attributed on the window alone.
func TestGithubCorrelatesWithoutUserAgent(t *testing.T) {
	const promote = "github.privilege-escalation.org-owner-promote"
	for name, record := range recordings {
		for _, id := range githubTechniques {
			t.Run(name+"/"+id, func(t *testing.T) {
				lab := newGithubLab(t, true, mockgithub.WithRecordedUserAgent(record))
				before := lab.srv.Snapshot()
				r := lab.run("apply", id, "--target", "github", "--yes", "-q")
				if r.code != report.ExitOK {
					t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
				}
				rec := records(t, r.stdout)[0]
				if rec["verdict"] != "pass" {
					t.Fatalf("verdict %v (reason %v)", rec["verdict"], rec["reason"])
				}
				want := "name-prefix"
				if id == promote {
					want = "hashed-token"
				}
				for _, x := range expectationsOf(t, rec) {
					if x["status"] != "observed" || x["correlation"] != want {
						t.Errorf("expectation %v %v by %v; want observed by %s", x["event_type"], x["status"], x["correlation"], want)
					}
				}
				if after := lab.srv.Snapshot(); string(after) != string(before) {
					t.Fatalf("org changed:\nbefore %s\nafter  %s", before, after)
				}
			})
		}
	}

	t.Run("without hashed_token", func(t *testing.T) {
		for _, id := range githubTechniques {
			lab := newGithubLab(t, true, mockgithub.WithRecordedUserAgent(recordings["dropped"]), mockgithub.WithoutHashedToken())
			r := lab.run("apply", id, "--target", "github", "--yes", "-q")
			rec := records(t, r.stdout)[0]
			exps := expectationsOf(t, rec)
			if id == promote {
				if r.code != report.ExitExpectationFailed || rec["verdict"] != "telemetry-missing" || exps[0]["status"] != "missing" {
					t.Errorf("%s: exit %d, verdict %v, expectation %v; want it missing: nothing but the window ties it to the run", id, r.code, rec["verdict"], exps[0]["status"])
				}
				continue
			}
			if r.code != report.ExitOK || rec["verdict"] != "pass" || exps[0]["correlation"] != "name-prefix" {
				t.Errorf("%s: exit %d, verdict %v, correlation %v; want a pass by name-prefix", id, r.code, rec["verdict"], exps[0]["correlation"])
			}
		}
	})
}

// TestOktaFallbackNeverMisattributes: with the User-Agent dropped and the
// expected zone.deactivate never logged, decoys that would satisfy the
// expectation (another run's zone, a person in the admin console, the right
// zone but outside the run window, nothing run-specific at all) must leave it
// missing and stay out of the run's events.
func TestOktaFallbackNeverMisattributes(t *testing.T) {
	lab := newOktaLab(t, true, mockokta.WithRecordedUserAgent(recordings["dropped"]), mockokta.WithDrop("zone.deactivate"))
	lab.runID = "k3v9q2"
	zoneName := marker.ObjectName(lab.runID, "zone")
	decoys := []string{"dec-other-run", "dec-other-marker", "dec-browser", "dec-anonymous", "dec-after-window"}
	lab.hook = func(p engine.Point, step string) {
		if p != engine.AfterResult || step != "deactivate" {
			return
		}
		lab.srv.State(func(st *mockokta.State) {
			zoneID := ""
			for _, z := range st.Zones {
				if z.Name == zoneName {
					zoneID = z.ID
				}
			}
			if zoneID == "" {
				t.Fatal("the run's zone is not in the org")
			}
			now := lab.clk.Now()
			add := func(uuid string, published, visible time.Time, ua, name string) {
				tgt := map[string]string{"id": zoneID, "type": "NetworkZone"}
				if name != "" {
					tgt["displayName"] = name
				}
				b, _ := json.Marshal(map[string]any{
					"uuid": uuid, "published": published.UTC().Format(time.RFC3339Nano), "eventType": "zone.deactivate",
					"client": map[string]any{"userAgent": map[string]string{"rawUserAgent": ua}},
					"target": []map[string]string{tgt},
				})
				st.Log = append(st.Log, mockokta.LogEntry{VisibleAt: visible, Event: b})
			}
			add("dec-other-run", now, now, "", marker.ObjectName("p7m2xw", "zone"))
			add("dec-other-marker", now, now, marker.UserAgent("0.0.0-test", "p7m2xw", marker.PhaseDetonate), zoneName)
			add("dec-browser", now, now, "Mozilla/5.0 (X11; Linux x86_64)", zoneName)
			add("dec-anonymous", now, now, "", "")
			// Inside the query window but outside the run window (one minute
			// of skew past cleanup): read while collection waits for the
			// deadline.
			add("dec-after-window", now.Add(3*time.Minute), now.Add(3*time.Minute), "", zoneName)
		})
	}
	r := lab.run("apply", "okta.defense-impairment.network-zone-deactivate", "--target", "okta", "--yes", "-vv")
	if r.code != report.ExitExpectationFailed {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	rec := records(t, r.stdout)[0]
	exps := expectationsOf(t, rec)
	if rec["verdict"] != "telemetry-missing" || exps[0]["status"] != "observed" || exps[0]["correlation"] != "name-prefix" || exps[1]["status"] != "missing" {
		t.Fatalf("verdict %v, expectations %v; want zone.create observed by name-prefix and zone.deactivate missing", rec["verdict"], exps)
	}
	ids := eventIDs(t, filepath.Join(lab.dir, "state"), lab.runID, "uuid")
	for _, d := range decoys {
		if ids[d] {
			t.Errorf("decoy %s was attributed to the run", d)
		}
	}
	// The near misses that named this run's zone are explained at -vv.
	for _, d := range []string{"dec-browser", "dec-after-window"} {
		if !strings.Contains(r.stderr, "event "+d+" zone.deactivate not correlated") {
			t.Errorf("-vv does not explain why %s was ruled out:\n%s", d, r.stderr)
		}
	}
}

// TestGithubFallbackNeverMisattributes: with the User-Agent dropped and the
// expected org.update_member never logged, decoys that would satisfy the
// expectation (another token, this token from another client, this token
// outside the run window, this token on another run's repository, no token
// at all) must leave it missing and stay out of the run's events.
func TestGithubFallbackNeverMisattributes(t *testing.T) {
	lab := newGithubLab(t, true, mockgithub.WithRecordedUserAgent(recordings["dropped"]), mockgithub.WithDrop("org.update_member"))
	lab.runID = "k3v9q2"
	ours := mockgithub.HashedToken(ghToken)
	decoys := []string{"gd-other-token", "gd-other-client", "gd-after-window", "gd-other-run", "gd-no-token"}
	lab.hook = func(p engine.Point, step string) {
		if p != engine.AfterResult || step != "promote" {
			return
		}
		lab.srv.State(func(st *mockgithub.State) {
			now := lab.clk.Now()
			add := func(id string, at time.Time, ua, token, repo string) {
				ev := map[string]any{"_document_id": id, "@timestamp": at.UnixMilli(), "action": "org.update_member", "user": ghSecond, "org": ghOrg, "user_agent": ua}
				if token != "" {
					ev["hashed_token"] = token
				}
				if repo != "" {
					ev["repo"] = repo
				}
				b, _ := json.Marshal(ev)
				st.Log = append(st.Log, mockgithub.LogEntry{VisibleAt: at, Event: b})
			}
			add("gd-other-token", now, "", mockgithub.HashedToken("someone-elses-token"), "")
			add("gd-other-client", now, "gh/2.40.0", ours, "")
			add("gd-after-window", now.Add(3*time.Minute), "", ours, "")
			add("gd-other-run", now, "", ours, ghOrg+"/"+marker.ObjectName("p7m2xw", "repo"))
			add("gd-no-token", now, "", "", "")
		})
	}
	r := lab.run("apply", "github.privilege-escalation.org-owner-promote", "--target", "github", "--yes", "-vv")
	if r.code != report.ExitExpectationFailed {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	rec := records(t, r.stdout)[0]
	if exps := expectationsOf(t, rec); rec["verdict"] != "telemetry-missing" || exps[0]["status"] != "missing" {
		t.Fatalf("verdict %v, expectations %v; want org.update_member missing", rec["verdict"], exps)
	}
	ids := eventIDs(t, filepath.Join(lab.dir, "state"), lab.runID, "_document_id")
	for _, d := range decoys {
		if ids[d] {
			t.Errorf("decoy %s was attributed to the run", d)
		}
	}
	for _, d := range []string{"gd-other-client", "gd-after-window"} {
		if !strings.Contains(r.stderr, "event "+d+" org.update_member not correlated") {
			t.Errorf("-vv does not explain why %s was ruled out:\n%s", d, r.stderr)
		}
	}
}

// TestGithubHashedTokenStopsAtThePreviousRun: consecutive runs on one target
// authenticate with the same token, and the skew before a run's start
// reaches back into the run before it. With the User-Agent dropped, the
// earlier run's org.update_member events (no run object, the same
// hashed_token) must stay out of the next run's events and expectations,
// while the next run's own event still correlates by hashed-token, whether
// the org's clock leads or lags this machine's by less than half the gap
// between the two runs.
func TestGithubHashedTokenStopsAtThePreviousRun(t *testing.T) {
	const (
		promote = "github.privilege-escalation.org-owner-promote"
		webhook = "github.persistence.repo-webhook-create"
		nearer  = " org.update_member not correlated: carries this run's credential but its User-Agent did not survive and it is stamped closer to the previous run on this target than to this one"
		// lag is how long the org takes to make an event readable: the first
		// run's collection waits for it, which is the gap between the runs.
		lag = 20 * time.Second
	)
	// memberEvents returns the IDs of the org.update_member events the org
	// has logged so far.
	memberEvents := func(t *testing.T, lab *githubLab) map[string]bool {
		ids := map[string]bool{}
		lab.srv.State(func(st *mockgithub.State) {
			for _, le := range st.Log {
				var ev struct {
					ID          string `json:"_document_id"`
					Action      string `json:"action"`
					HashedToken string `json:"hashed_token"`
				}
				if err := json.Unmarshal(le.Event, &ev); err != nil {
					t.Fatal(err)
				}
				if ev.Action == "org.update_member" {
					if ev.HashedToken != mockgithub.HashedToken(ghToken) {
						t.Fatalf("event %s does not carry the run's hashed_token", ev.ID)
					}
					ids[ev.ID] = true
				}
			}
		})
		return ids
	}
	// gap is the time between the first run's last mutation and the second
	// run's first, read from their journals.
	gap := func(t *testing.T, lab *githubLab, first, second string) time.Duration {
		load := func(run string) *journal.Journal {
			j, err := journal.Load(filepath.Join(lab.dir, "state", "runs", run, "journal.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			return j
		}
		var last time.Time
		for _, r := range load(first).Records {
			switch r.Kind {
			case journal.KindIntent, journal.KindResult, journal.KindError, journal.KindUndo:
				last = r.Time
			}
		}
		sp, ok := load(second).Span()
		if !ok || last.IsZero() {
			t.Fatal("a run journalled no step")
		}
		return sp.Start.Sub(last)
	}

	for name, offset := range map[string]time.Duration{"the org's clock lags": -3 * time.Second, "the org's clock leads": 3 * time.Second} {
		newLab := func(t *testing.T) *githubLab {
			return newGithubLab(t, true, mockgithub.WithRecordedUserAgent(recordings["dropped"]), mockgithub.WithLag(lag), mockgithub.WithClockOffset(offset))
		}
		// within fails unless the clock offset is less than half the gap
		// between the runs, the tolerance the midpoint rule gives.
		within := func(t *testing.T, lab *githubLab, first, second string) {
			if g := gap(t, lab, first, second); offset.Abs() >= g/2 || g >= 2*engine.AuditSkew {
				t.Fatalf("the runs are %v apart; the test needs a gap of more than %v and less than %v", g, 2*offset.Abs(), 2*engine.AuditSkew)
			}
		}

		t.Run(name+"/in one apply", func(t *testing.T) {
			lab := newLab(t)
			r := lab.run("apply", promote, webhook, "--target", "github", "--yes", "-vv")
			if r.code != report.ExitOK {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			recs := records(t, r.stdout)
			first, second := recs[0], recs[1]
			within(t, lab, first["run"].(string), second["run"].(string))
			if x := expectationsOf(t, first)[0]; x["status"] != "observed" || x["correlation"] != "hashed-token" {
				t.Fatalf("the first run's expectation %v by %v; want observed by hashed-token", x["status"], x["correlation"])
			}
			for _, x := range expectationsOf(t, second) {
				if x["status"] != "observed" || x["correlation"] != "name-prefix" {
					t.Errorf("the second run's expectation %v %v by %v; want observed by name-prefix", x["event_type"], x["status"], x["correlation"])
				}
			}
			earlier := memberEvents(t, lab)
			if len(earlier) != 2 {
				t.Fatalf("the first run logged %d org.update_member events, want its promotion and its demotion", len(earlier))
			}
			state := filepath.Join(lab.dir, "state")
			if ids := eventIDs(t, state, first["run"].(string), "_document_id"); len(ids) != len(earlier) {
				t.Errorf("the first run kept %d events, want its own %d", len(ids), len(earlier))
			}
			ids := eventIDs(t, state, second["run"].(string), "_document_id")
			for id := range earlier {
				if ids[id] {
					t.Errorf("the first run's event %s entered the second run's events", id)
				}
				// Ruled out by the midpoint, so it was inside the second
				// run's window.
				if !strings.Contains(r.stderr, "event "+id+nearer) {
					t.Errorf("-vv does not explain why %s was ruled out:\n%s", id, r.stderr)
				}
			}
		})

		t.Run(name+"/in consecutive applies of one technique", func(t *testing.T) {
			lab := newLab(t)
			r := lab.run("apply", promote, "--target", "github", "--yes", "-q")
			if r.code != report.ExitOK {
				t.Fatalf("first apply: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			first := records(t, r.stdout)[0]["run"].(string)
			earlier := memberEvents(t, lab)
			r = lab.run("apply", promote, "--target", "github", "--yes", "-vv")
			if r.code != report.ExitOK {
				t.Fatalf("second apply: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
			}
			rec := records(t, r.stdout)[0]
			within(t, lab, first, rec["run"].(string))
			x := expectationsOf(t, rec)[0]
			own, _ := x["event_id"].(string)
			if x["status"] != "observed" || x["correlation"] != "hashed-token" || own == "" || earlier[own] {
				t.Fatalf("expectation %v by %v (event %q); want observed by hashed-token on the second run's own event", x["status"], x["correlation"], own)
			}
			ids := eventIDs(t, filepath.Join(lab.dir, "state"), rec["run"].(string), "_document_id")
			if !ids[own] {
				t.Errorf("the second run's own event %s is not in its events", own)
			}
			if len(ids) != 2 {
				t.Errorf("the second run kept %d events, want its own promotion and demotion", len(ids))
			}
			for id := range earlier {
				if ids[id] {
					t.Errorf("the first run's event %s entered the second run's events", id)
				}
				if !strings.Contains(r.stderr, "event "+id+nearer) {
					t.Errorf("-vv does not explain why %s was ruled out:\n%s", id, r.stderr)
				}
			}
		})
	}
}
