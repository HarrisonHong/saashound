// Package guard is the tenant-you-own guardrail. It runs in the core, before
// any mutating call, so no provider can skip it:
//
//  1. allowlist: the target is declared in targets.yaml;
//  2. live identity: the platform says the credential belongs to the
//     declared tenant and principal;
//  3. ownership marker: a tenant admin placed the target's marker value,
//     which the tool only ever reads;
//  4. environment class: production runs need --production, a --ticket and
//     production-safe techniques; a "lab" with too many active users is
//     refused as probably mislabelled;
//  5. typed confirmation on a TTY, or --yes when non-interactive.
//
// What this proves is limited: someone with admin rights in the tenant
// deliberately opted it in. It does not prove legal ownership; nothing can.
package guard

import (
	"context"
	"fmt"
	"strings"

	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/target"
)

// Mode selects which checks apply.
type Mode int

// Modes.
const (
	// ModeApply runs every check, including confirmation.
	ModeApply Mode = iota
	// ModePlan runs the read-only checks 1-4 and never prompts.
	ModePlan
	// ModeCleanup runs checks 1-2 only: undoing the run's own objects is
	// always allowed, but only against the tenant that holds them.
	ModeCleanup
)

// Refusal is a guardrail refusal. The CLI maps it to exit code 2.
type Refusal struct {
	Check  string
	Reason string
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused (%s): %s", r.Check, r.Reason) }

// Check names.
const (
	CheckAllowlist   = "allowlist"
	CheckIdentity    = "identity"
	CheckMarker      = "marker"
	CheckEnvironment = "environment"
	CheckConfirm     = "confirmation"
)

// Request is what the gate needs.
type Request struct {
	Mode   Mode
	Target *target.Target
	Tenant provider.Tenant
	// Runs are the techniques about to run (ModeApply, ModePlan).
	Runs []*plan.Run
	// Production is the --production flag; Ticket the --ticket value.
	Production bool
	Ticket     string
	// Yes is --yes. Interactive is true when stdin and stderr are terminals.
	Yes         bool
	Interactive bool
	// Confirm shows prompt and returns the line the operator typed.
	Confirm func(prompt string) (string, error)
}

// Result is one check's outcome.
type Result struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// Report is the gate's outcome.
type Report struct {
	Results  []Result          `json:"results"`
	Identity provider.Identity `json:"identity"`
	Caps     provider.Caps     `json:"caps"`
}

// Summary renders the passed checks for the plan's "guard" line, e.g.
// "allowlisted · tenant matches · marker ok · lab".
func (r *Report) Summary() string {
	var parts []string
	for _, c := range r.Results {
		if c.Check == CheckConfirm {
			continue
		}
		parts = append(parts, c.Detail)
	}
	return strings.Join(parts, " · ")
}

// Check runs the gate. It returns a *Refusal if any check fails; the report
// lists every check run so far either way.
func Check(ctx context.Context, req Request) (*Report, error) {
	rep := &Report{}
	pass := func(check, detail string) {
		rep.Results = append(rep.Results, Result{Check: check, OK: true, Detail: detail})
	}
	refuse := func(check, detail, reason string) (*Report, error) {
		rep.Results = append(rep.Results, Result{Check: check, OK: false, Detail: detail})
		return rep, &Refusal{Check: check, Reason: reason}
	}
	t := req.Target

	// 1. Allowlist. The caller found t in targets.yaml.
	if t == nil {
		return refuse(CheckAllowlist, "not allowlisted", "the target is not declared in targets.yaml")
	}
	pass(CheckAllowlist, "allowlisted")

	// 2. Live identity.
	id, err := req.Tenant.Whoami(ctx)
	if err != nil {
		return refuse(CheckIdentity, "identity unknown", "could not ask the platform who this credential is: "+err.Error())
	}
	rep.Identity = id
	if id.Tenant != t.Tenant {
		return refuse(CheckIdentity, "TENANT MISMATCH",
			fmt.Sprintf("the credential belongs to tenant %q, but target %s declares %q", id.Tenant, t.Name, t.Tenant))
	}
	if id.Principal != t.Principal {
		return refuse(CheckIdentity, "PRINCIPAL MISMATCH",
			fmt.Sprintf("the credential is principal %q, but target %s declares %q", id.Principal, t.Name, t.Principal))
	}
	pass(CheckIdentity, "tenant matches")
	if req.Mode == ModeCleanup {
		return rep, nil
	}

	// 3. Ownership marker, placed by a human admin; the tool only reads it.
	value, found, err := req.Tenant.ReadMarker(ctx)
	switch {
	case err != nil:
		return refuse(CheckMarker, "marker unreadable", "could not read the ownership marker: "+err.Error())
	case !found:
		return refuse(CheckMarker, "MARKER MISSING",
			fmt.Sprintf("no ownership marker in tenant %s; a tenant admin must place %s (see `saashound init %s`)", t.Tenant, t.MarkerValue(), t.Name))
	case value != t.MarkerValue():
		return refuse(CheckMarker, "MARKER MISMATCH",
			fmt.Sprintf("the tenant's ownership marker is %q, but this target entry needs %q (did the entry change?)", value, t.MarkerValue()))
	}
	pass(CheckMarker, "marker ok")

	if caps, err := req.Tenant.Capabilities(ctx); err == nil {
		rep.Caps = caps
	} else {
		return refuse(CheckEnvironment, "capabilities unknown", "could not read tenant capabilities: "+err.Error())
	}

	// 4. Environment class.
	switch t.Environment {
	case target.Production:
		if !req.Production {
			return refuse(CheckEnvironment, "production",
				fmt.Sprintf("target %s is production: pass --production and --ticket <change reference>", t.Name))
		}
		if strings.TrimSpace(req.Ticket) == "" {
			return refuse(CheckEnvironment, "production", "production runs need --ticket <change reference>, written into every record")
		}
		var unsafe []string
		for _, r := range req.Runs {
			if !r.Safety.ProductionSafe {
				unsafe = append(unsafe, r.Technique)
			}
		}
		if len(unsafe) > 0 {
			return refuse(CheckEnvironment, "production",
				"these techniques are not production_safe and only run against lab targets: "+strings.Join(unsafe, ", "))
		}
		pass(CheckEnvironment, "production ("+req.Ticket+")")
	default:
		if req.Production {
			return refuse(CheckEnvironment, "lab", fmt.Sprintf("--production was given, but target %s is labelled lab", t.Name))
		}
		if id.ActiveUsers > t.MaxLabUsers {
			return refuse(CheckEnvironment, "lab?",
				fmt.Sprintf("target %s is labelled lab but has %d active users (more than %d); relabel it or raise max_lab_users", t.Name, id.ActiveUsers, t.MaxLabUsers))
		}
		pass(CheckEnvironment, "lab")
	}
	if req.Mode == ModePlan {
		return rep, nil
	}

	// 5. Confirmation.
	switch {
	case req.Yes:
		pass(CheckConfirm, "--yes")
	case !req.Interactive || req.Confirm == nil:
		return refuse(CheckConfirm, "not confirmed",
			"not running on a terminal: pass --yes to confirm (the ownership marker plus --yes replace typed confirmation in CI)")
	default:
		prompt := fmt.Sprintf("About to run %d technique(s) against %q (%s), environment %s.\nType the tenant short name %q to continue: ",
			len(req.Runs), id.DisplayName, id.Domain, t.Environment, id.ShortName)
		typed, err := req.Confirm(prompt)
		if err != nil {
			return refuse(CheckConfirm, "not confirmed", "confirmation was not read: "+err.Error())
		}
		if strings.TrimSpace(typed) != id.ShortName {
			return refuse(CheckConfirm, "not confirmed", "the typed name does not match the tenant's short name")
		}
		pass(CheckConfirm, "confirmed")
	}
	return rep, nil
}
