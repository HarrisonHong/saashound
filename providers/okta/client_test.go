package okta_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// TestRateLimitBackoff proves the client backs off and retries Okta's 429
// rate limiting instead of failing.
func TestRateLimitBackoff(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	srv, cfg := newMock(t, mockokta.WithClock(clk.Now))
	cfg.Clock = clk
	srv.InjectRateLimit(2) // the first two calls answer 429
	ten := open(t, cfg)
	id, err := ten.Whoami(context.Background())
	if err != nil {
		t.Fatalf("Whoami did not survive rate limiting: %v", err)
	}
	if id.Principal != testPrincipal {
		t.Fatalf("principal %q", id.Principal)
	}
}

// TestRateLimitRetriesBounded proves a tenant that answers 429 forever fails
// the call with a bounded error instead of retrying without end, on both the
// single-request path and the paginated list path.
func TestRateLimitRetriesBounded(t *testing.T) {
	calls := map[string]func(provider.Tenant) error{
		"single request": func(ten provider.Tenant) error {
			_, err := ten.Whoami(context.Background())
			return err
		},
		"paginated list": func(ten provider.Tenant) error {
			_, err := ten.Sweep(context.Background(), marker.Prefix+"-")
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			clk := clock.NewFake(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
			srv, cfg := newMock(t, mockokta.WithClock(clk.Now))
			cfg.Clock = clk
			ten := open(t, cfg)
			srv.InjectRateLimit(1 << 30)
			done := make(chan error, 1)
			go func() { done <- call(ten) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "429") {
					t.Fatalf("persistent 429 returned %v, want a 429 API error", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("persistent 429 was retried without bound")
			}
		})
	}
}

// TestPaginationFollowed proves Sweep reads every page: the mock paginates two
// objects per page, so finding five run users requires following Link headers.
func TestPaginationFollowed(t *testing.T) {
	srv, cfg := newMock(t)
	run := "pppppp"
	steps := []string{"ua", "ub", "uc", "ud", "ue"}
	srv.State(func(s *mockokta.State) {
		for _, step := range steps {
			name := marker.ObjectName(run, step)
			s.AddUser(name + "@" + testDomain)
		}
	})
	ten := open(t, cfg)
	orphans, err := ten.Sweep(context.Background(), marker.RunPrefix(run)+"-")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range orphans {
		if o.Op == "okta.user.create" {
			n++
		}
	}
	if n != len(steps) {
		t.Fatalf("Sweep found %d run users across pages, want %d: %+v", n, len(steps), orphans)
	}
}

// TestSweepIgnoresNonRunObjects proves the sweeper never offers the token's own
// user or anything whose name is not a strict run-object name.
func TestSweepIgnoresNonRunObjects(t *testing.T) {
	srv, cfg := newMock(t)
	srv.State(func(s *mockokta.State) {
		s.AddUser("saashound-not-a-run@" + testDomain) // prefix only, not the grammar
		s.AddUser("regular@" + testDomain)
	})
	ten := open(t, cfg)
	orphans, err := ten.Sweep(context.Background(), marker.Prefix+"-")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range orphans {
		if _, _, ok := marker.ParseObjectName(o.Name); !ok {
			t.Fatalf("sweep offered a non-run object: %q", o.Name)
		}
	}
	// And the principal user is never swept.
	for _, o := range orphans {
		if o.Name == testPrincipal {
			t.Fatal("sweep offered the token's own user")
		}
	}
}
