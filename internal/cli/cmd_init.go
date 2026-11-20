package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/guard"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/internal/target"
)

func (a *app) initCmd() *cobra.Command {
	var (
		t           target.Target
		credEnv     string
		credFile    string
		placeMarker bool
	)
	cmd := &cobra.Command{
		Use:   "init <target> --platform <platform>",
		Short: "Declare a target in targets.yaml and print its ownership marker",
		Long: `Declare a target in targets.yaml (the allowlist) and print the ownership
marker a tenant admin must place before the tool will touch the tenant.

For a simulated platform (fake) there is no real tenant: init also provisions
the simulated tenant, and --place-marker plays the tenant admin.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t.Name = args[0]
			if !target.ValidName(t.Name) {
				return refused("target name %q must be lowercase letters, digits and '-'", t.Name)
			}
			p, ok := a.reg.Provider(t.Platform)
			if !ok {
				return refused("--platform must be one of: %s", strings.Join(a.reg.Providers(), ", "))
			}
			sim, simulated := p.(provider.Simulator)
			if simulated {
				// A simulated tenant has no external identifiers to look up.
				if t.Tenant == "" {
					t.Tenant = "sim-" + t.Name
				}
				if t.Principal == "" {
					t.Principal = "saashound-operator"
				}
			}
			if t.Tenant == "" || t.Principal == "" {
				return refused("--tenant and --principal are required for platform %s", t.Platform)
			}
			if placeMarker && !simulated {
				return refused("--place-marker is only for simulated platforms: on a real tenant a human admin places the marker")
			}
			switch {
			case credEnv != "" && credFile != "":
				return refused("use one of --credential-env and --credential-file")
			case credEnv != "":
				t.Credential = secret.Ref{Env: credEnv}
			case credFile != "":
				t.Credential = secret.Ref{File: credFile}
			}
			f, err := a.targets()
			if err != nil {
				return err
			}
			tt := t
			if prev, ok := f.Targets[tt.Name]; ok {
				// Re-running init keeps whatever was not given explicitly.
				inherit := func(flag string, dst *string, v string) {
					if !cmd.Flags().Changed(flag) {
						*dst = v
					}
				}
				inherit("tenant", &tt.Tenant, prev.Tenant)
				inherit("principal", &tt.Principal, prev.Principal)
				inherit("environment", &tt.Environment, prev.Environment)
				inherit("test-domain", &tt.TestDomain, prev.TestDomain)
				if !cmd.Flags().Changed("credential-env") && !cmd.Flags().Changed("credential-file") {
					tt.Credential = prev.Credential
				}
			}
			out := cmd.OutOrStdout()
			switch err := f.Add(&tt); {
			case errors.Is(err, target.ErrExists):
				fmt.Fprintf(out, "target %s is already declared in %s\n", tt.Name, a.targetsPath)
			case err != nil:
				return refused("%v", err)
			default:
				if err := f.Save(a.targetsPath); err != nil {
					return exit(report.ExitRefused, err)
				}
				fmt.Fprintf(out, "wrote %s  (target %s, platform %s, environment %s)\n", a.targetsPath, tt.Name, tt.Platform, tt.Environment)
			}
			cfg := a.providerConfig(&tt, nil)
			if simulated {
				switch err := sim.Provision(cmd.Context(), cfg); {
				case errors.Is(err, provider.ErrAlreadyExists):
					fmt.Fprintf(out, "simulated tenant %s is already provisioned\n", tt.Tenant)
				case err != nil:
					return exit(report.ExitRefused, fmt.Errorf("provision simulated tenant: %w", err))
				default:
					fmt.Fprintf(out, "provisioned simulated tenant %s\n", tt.Tenant)
				}
			}
			fmt.Fprintf(out, "\nAuthorize saashound for this tenant (a tenant admin must do this once):\n")
			if ob, ok := p.(provider.Onboarder); ok {
				for _, l := range ob.MarkerInstructions(tt.Info(), tt.MarkerValue()) {
					fmt.Fprintf(out, "  %s\n", l)
				}
			} else {
				fmt.Fprintf(out, "  place the ownership marker  %s\n", tt.MarkerValue())
			}
			if placeMarker {
				if err := sim.PlaceMarker(cmd.Context(), cfg, tt.MarkerValue()); err != nil {
					return exit(report.ExitRefused, fmt.Errorf("place marker: %w", err))
				}
				fmt.Fprintf(out, "placed the ownership marker in the simulated tenant (as its admin)\n")
			}
			fmt.Fprintf(out, "Then: saashound auth %s\n", tt.Name)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&t.Platform, "platform", "", "platform (provider) name")
	fl.StringVar(&t.Tenant, "tenant", "", "tenant identifier (org URL, org slug, ...)")
	fl.StringVar(&t.Principal, "principal", "", "principal the credential must belong to")
	fl.StringVar(&t.Environment, "environment", target.Lab, "lab or production")
	fl.StringVar(&t.TestDomain, "test-domain", "", "domain for synthetic accounts (default example.com)")
	fl.StringVar(&credEnv, "credential-env", "", "read the credential from this environment variable")
	fl.StringVar(&credFile, "credential-file", "", "read the credential from this 0600 key file")
	fl.BoolVar(&placeMarker, "place-marker", false, "simulated platforms only: place the ownership marker as the tenant admin")
	_ = cmd.MarkFlagRequired("platform")
	return cmd
}

func (a *app) authCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth <target>",
		Short: "Check a target end to end with read-only calls",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := a.lookupTarget(args[0])
			if err != nil {
				return err
			}
			need, needErr := a.corpusScopes(t.Platform)
			p, _ := a.reg.Provider(t.Platform)
			tr := &tracer{p: a.progress}
			// auth only reads (identity, marker, capabilities, the audit
			// API), so it requires just the audit scopes. It asks for the rest
			// of what the corpus needs optionally, only to report which of
			// them the credential cannot get.
			ten, err := a.open(cmd.Context(), t, tr, access{scopes: p.Audit().Scopes, optional: need})
			if err != nil {
				return err
			}
			defer ten.Close()
			rep, gerr := guard.Check(cmd.Context(), guard.Request{Mode: guard.ModePlan, Target: t, Tenant: ten})
			out := cmd.OutOrStdout()
			id := rep.Identity
			head := fmt.Sprintf("%s   %s   %s", t.Name, t.Platform, orDash(id.Domain))
			if id.DisplayName != "" {
				head += fmt.Sprintf("   %q", id.DisplayName)
			}
			fmt.Fprintln(out, head)
			fmt.Fprintf(out, "  principal   %s\n", orDash(id.Principal))
			if id.Credential != "" {
				fmt.Fprintf(out, "  credential  %s\n", id.Credential)
			}
			if len(id.Roles) > 0 {
				fmt.Fprintf(out, "  roles       %s\n", strings.Join(id.Roles, " "))
			}
			if len(id.Scopes) > 0 {
				line := fmt.Sprintf("%d granted", len(id.Scopes))
				if needErr == nil {
					line += fmt.Sprintf(", %d needed by the %s corpus", len(need), t.Platform)
					if missing := missingScopes(need, id.Scopes); len(missing) > 0 {
						line += "; MISSING " + strings.Join(missing, " ")
					}
				}
				fmt.Fprintf(out, "  scopes      %s\n", line)
			}
			for _, r := range rep.Results {
				fmt.Fprintf(out, "  %-11s %s\n", r.Check, r.Detail)
			}
			if id.ActiveUsers >= 0 && gerr == nil {
				fmt.Fprintf(out, "  tier        %s: %d of %d active users allowed for a lab\n", orDash(rep.Caps.Tier), id.ActiveUsers, t.MaxLabUsers)
			}
			if gerr == nil {
				if rep.Caps.Audit {
					fmt.Fprintf(out, "  telemetry   audit API reachable\n")
				} else {
					fmt.Fprintf(out, "  telemetry   unsupported: %s\n", rep.Caps.Note)
				}
			}
			if gerr != nil {
				return exit(report.ExitRefused, gerr)
			}
			fmt.Fprintln(out, "ready")
			return nil
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// corpusScopes is every scope the platform's corpus needs.
func (a *app) corpusScopes(platform string) ([]string, error) {
	c, err := a.corpus()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	if p, ok := a.reg.Provider(platform); ok {
		for _, s := range p.Audit().Scopes {
			set[s] = true
		}
	}
	for _, t := range c.List() {
		if t.Platform != platform {
			continue
		}
		for _, s := range t.Steps {
			if e, ok := a.reg.Op(s.Op); ok {
				for _, sc := range e.Spec.Scopes {
					set[sc] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sortStrings(out)
	return out, nil
}

func missingScopes(need, have []string) []string {
	got := map[string]bool{}
	for _, s := range have {
		got[s] = true
	}
	var out []string
	for _, s := range need {
		if !got[s] {
			out = append(out, s)
		}
	}
	return out
}
