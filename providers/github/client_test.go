package github_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/providers/github/mockgithub"
)

// TestRateLimitBackoff proves the client backs off and retries GitHub's
// primary rate limit instead of failing.
func TestRateLimitBackoff(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC))
	srv, cfg := newMock(t, mockgithub.WithClock(clk.Now))
	cfg.Clock = clk
	srv.InjectRateLimit(2) // the first two calls answer 403 rate-limited
	ten := open(t, cfg)
	id, err := ten.Whoami(context.Background())
	if err != nil {
		t.Fatalf("Whoami did not survive rate limiting: %v", err)
	}
	if id.Principal != testPrincipal {
		t.Fatalf("principal %q", id.Principal)
	}
}

// TestRateLimitRetriesBounded proves a tenant that rate-limits forever fails
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
			srv, cfg := newMock(t, mockgithub.WithClock(clk.Now))
			cfg.Clock = clk
			ten := open(t, cfg)
			srv.InjectRateLimit(1 << 30)
			done := make(chan error, 1)
			go func() { done <- call(ten) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "403") {
					t.Fatalf("persistent rate limit returned %v, want a 403 API error", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("persistent rate limit was retried without bound")
			}
		})
	}
}

// TestPaginationFollowed proves Sweep reads every page: the mock paginates two
// objects per page, so finding five run repos requires following Link headers.
func TestPaginationFollowed(t *testing.T) {
	srv, cfg := newMock(t)
	run := "pppppp"
	steps := []string{"ra", "rb", "rc", "rd", "re"}
	srv.State(func(s *mockgithub.State) {
		for _, step := range steps {
			s.AddRepo(marker.ObjectName(run, step))
		}
	})
	ten := open(t, cfg)
	orphans, err := ten.Sweep(context.Background(), marker.RunPrefix(run)+"-")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range orphans {
		if o.Op == "github.repo.create" {
			n++
		}
	}
	if n != len(steps) {
		t.Fatalf("Sweep found %d run repos across pages, want %d: %+v", n, len(steps), orphans)
	}
}

// TestSweepIgnoresNonRunObjects proves the sweeper never offers the ownership
// marker repo or anything whose name is not a strict run-object name.
func TestSweepIgnoresNonRunObjects(t *testing.T) {
	srv, cfg := newMock(t)
	srv.State(func(s *mockgithub.State) {
		s.AddRepo("saashound-not-a-run") // prefix only, not the grammar
		s.AddRepo("regular-repo")
	})
	srv.PlaceMarker("saashound-range", "saashound-authorized", "saashound-authorized:x")
	ten := open(t, cfg)
	orphans, err := ten.Sweep(context.Background(), marker.Prefix+"-")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range orphans {
		if _, _, ok := marker.ParseObjectName(o.Name); !ok {
			t.Fatalf("sweep offered a non-run object: %q", o.Name)
		}
		if o.Name == "saashound-range" {
			t.Fatal("sweep offered the ownership-marker repo")
		}
	}
}
