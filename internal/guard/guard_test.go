package guard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
)

type stubTenant struct {
	provider.Tenant
	id       provider.Identity
	marker   string
	found    bool
	whoErr   error
	markRead int
}

func (s *stubTenant) Whoami(context.Context) (provider.Identity, error) { return s.id, s.whoErr }
func (s *stubTenant) ReadMarker(context.Context) (string, bool, error) {
	s.markRead++
	return s.marker, s.found, nil
}
func (s *stubTenant) Capabilities(context.Context) (provider.Caps, error) {
	return provider.Caps{Audit: true}, nil
}

func setup(env string) (*target.Target, *stubTenant) {
	t := &target.Target{Name: "lab", Platform: "fake", Tenant: "sim-lab", Principal: "app1", Environment: env, MaxLabUsers: 25}
	return t, &stubTenant{
		id:     provider.Identity{Tenant: "sim-lab", Principal: "app1", ShortName: "sim-lab", DisplayName: "Lab", ActiveUsers: 3},
		marker: t.MarkerValue(), found: true,
	}
}

func runs(safe bool) []*plan.Run {
	return []*plan.Run{{Technique: "fake.persistence.x", Safety: technique.Safety{ProductionSafe: safe}}}
}

func check(t *testing.T, req Request) (*Report, error) {
	t.Helper()
	return Check(context.Background(), req)
}

func wantRefusal(t *testing.T, err error, check, contains string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Check != check || !strings.Contains(r.Reason, contains) {
		t.Fatalf("got %v; want a %s refusal containing %q", err, check, contains)
	}
}

func TestPasses(t *testing.T) {
	tgt, ten := setup(target.Lab)
	rep, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(false), Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := rep.Summary(); s != "allowlisted · tenant matches · marker ok · lab" {
		t.Fatalf("summary %q", s)
	}
}

func TestRefusals(t *testing.T) {
	t.Run("not allowlisted", func(t *testing.T) {
		_, err := check(t, Request{Mode: ModeApply})
		wantRefusal(t, err, CheckAllowlist, "not declared")
	})
	t.Run("wrong tenant", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.id.Tenant = "corp-prod"
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckIdentity, `belongs to tenant "corp-prod"`)
		if ten.markRead != 0 {
			t.Fatal("nothing else may be read from the wrong tenant")
		}
	})
	t.Run("wrong principal", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.id.Principal = "someone-else"
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckIdentity, "principal")
	})
	t.Run("whoami fails", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.whoErr = errors.New("401")
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckIdentity, "401")
	})
	t.Run("marker missing", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.found = false
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckMarker, "no ownership marker")
	})
	t.Run("marker for another entry", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.marker = "saashound-authorized:000000000000"
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckMarker, "needs")
	})
	t.Run("relabelled to production invalidates the marker", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		tgt.Environment = target.Production
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true, Production: true, Ticket: "CHG-1"})
		wantRefusal(t, err, CheckMarker, "needs")
	})
	t.Run("lab with too many users", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		ten.id.ActiveUsers = 400
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true})
		wantRefusal(t, err, CheckEnvironment, "400 active users")
	})
	t.Run("--production on a lab", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Yes: true, Production: true})
		wantRefusal(t, err, CheckEnvironment, "labelled lab")
	})
	t.Run("production without --production", func(t *testing.T) {
		tgt, ten := setup(target.Production)
		ten.marker = tgt.MarkerValue()
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(true), Yes: true})
		wantRefusal(t, err, CheckEnvironment, "pass --production")
	})
	t.Run("production without a ticket", func(t *testing.T) {
		tgt, ten := setup(target.Production)
		ten.marker = tgt.MarkerValue()
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(true), Yes: true, Production: true})
		wantRefusal(t, err, CheckEnvironment, "--ticket")
	})
	t.Run("production with an unsafe technique", func(t *testing.T) {
		tgt, ten := setup(target.Production)
		ten.marker = tgt.MarkerValue()
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(false), Yes: true, Production: true, Ticket: "CHG-1"})
		wantRefusal(t, err, CheckEnvironment, "not production_safe")
	})
	t.Run("non-interactive without --yes", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(true)})
		wantRefusal(t, err, CheckConfirm, "--yes")
	})
	t.Run("typed the wrong name", func(t *testing.T) {
		tgt, ten := setup(target.Lab)
		_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(true), Interactive: true,
			Confirm: func(string) (string, error) { return "sim-prod", nil }})
		wantRefusal(t, err, CheckConfirm, "does not match")
	})
}

func TestProductionAndConfirmationPass(t *testing.T) {
	tgt, ten := setup(target.Production)
	ten.marker = tgt.MarkerValue()
	var prompt string
	_, err := check(t, Request{Mode: ModeApply, Target: tgt, Tenant: ten, Runs: runs(true), Production: true, Ticket: "CHG-2231",
		Interactive: true, Confirm: func(p string) (string, error) { prompt = p; return " sim-lab\n", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt, `"Lab"`) || !strings.Contains(prompt, "sim-lab") {
		t.Fatalf("the prompt must show the live tenant name: %q", prompt)
	}
}

func TestModes(t *testing.T) {
	tgt, ten := setup(target.Lab)
	ten.found = false
	if _, err := check(t, Request{Mode: ModeCleanup, Target: tgt, Tenant: ten}); err != nil {
		t.Fatalf("cleanup needs no marker: %v", err)
	}
	ten.id.Tenant = "other"
	_, err := check(t, Request{Mode: ModeCleanup, Target: tgt, Tenant: ten})
	wantRefusal(t, err, CheckIdentity, "belongs to tenant")

	tgt, ten = setup(target.Lab)
	if _, err := check(t, Request{Mode: ModePlan, Target: tgt, Tenant: ten}); err != nil {
		t.Fatalf("plan never prompts: %v", err)
	}
}
