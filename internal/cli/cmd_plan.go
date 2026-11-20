package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/guard"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/techniques"
)

type runFlags struct {
	target     string
	production bool
	ticket     string
}

func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.target, "target", "t", "", "target name from targets.yaml")
	cmd.Flags().BoolVar(&f.production, "production", false, "acknowledge that the target is production")
	cmd.Flags().StringVar(&f.ticket, "ticket", "", "change reference, required for production and written into every record")
}

func (a *app) newRunID() (string, error) {
	if a.env.NewRunID != nil {
		return a.env.NewRunID()
	}
	return marker.NewRunID()
}

// buildPlans plans each technique as its own run against t. Each technique
// is a separate run, so each gets its own journal, marker and audit window.
func (a *app) buildPlans(c *technique.Corpus, t *target.Target, ids []string, ticket string) ([]*plan.Run, error) {
	if len(ids) == 0 {
		return nil, refused("name at least one technique (see `saashound list`)")
	}
	pl := plan.Planner{Registry: a.reg}
	var runs []*plan.Run
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return nil, refused("technique %s is listed twice", id)
		}
		seen[id] = true
		tech, err := c.Lookup(id)
		if err != nil {
			return nil, refused("%v", err)
		}
		runID, err := a.newRunID()
		if err != nil {
			return nil, err
		}
		r, err := pl.Plan(tech, t, runID, ticket)
		if err != nil {
			return nil, refused("%v", err)
		}
		runs = append(runs, r)
	}
	return runs, nil
}

func (a *app) planCmd() *cobra.Command {
	var (
		rf      runFlags
		outPath string
		offline bool
	)
	cmd := &cobra.Command{
		Use:   "plan <technique...> --target <target>",
		Short: "Show exactly what apply would do; read-only",
		Long: `Show every call the run will make, every object it will create (with its
name), the scopes needed, the expected events and deadlines, the cleanup
order, and the guardrail result. plan makes only read calls (identity, the
ownership marker, capabilities), on a connection asking for exactly the
scopes apply would, so a credential that cannot get one is refused here;
--offline makes none.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.corpus()
			if err != nil {
				return err
			}
			t, err := a.lookupTarget(rf.target)
			if err != nil {
				return err
			}
			runs, err := a.buildPlans(c, t, args, rf.ticket)
			if err != nil {
				return err
			}
			guardLine := "not checked (--offline)"
			var gerr error
			if !offline {
				// The same scopes apply would ask for, so a credential that
				// cannot get one is refused here rather than mid-run.
				ten, err := a.open(cmd.Context(), t, &tracer{p: a.progress}, access{scopes: runScopes(runs)})
				if err != nil {
					return err
				}
				defer ten.Close()
				rep, err := guard.Check(cmd.Context(), guard.Request{
					Mode: guard.ModePlan, Target: t, Tenant: ten, Runs: runs,
					Production: rf.production, Ticket: rf.ticket,
				})
				guardLine = rep.Summary()
				if err != nil {
					gerr = err
				}
			}
			out := cmd.OutOrStdout()
			for i, r := range runs {
				if i > 0 {
					fmt.Fprintln(out)
				}
				a.printPlan(out, c, r, guardLine)
			}
			if outPath != "" {
				f := plan.File{Schema: plan.Schema, Version: plan.Version, Tool: "saashound/" + a.version, Corpus: techniques.Version(), Runs: runs}
				b, err := json.MarshalIndent(f, "", "  ")
				if err != nil {
					return err
				}
				if fi, err := os.Stat(filepath.Dir(outPath)); err != nil || !fi.IsDir() {
					return refused("write plan: directory %s does not exist", filepath.Dir(outPath))
				}
				if err := fsutil.WriteFileAtomic(outPath, append(b, '\n')); err != nil {
					return refused("write plan %s: %v", outPath, err)
				}
				fmt.Fprintf(a.env.Stderr, "wrote %s\n", outPath)
			}
			if gerr != nil {
				return exit(report.ExitRefused, gerr)
			}
			return nil
		},
	}
	rf.register(cmd)
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "save the plan as JSON, for `apply --plan`")
	cmd.Flags().BoolVar(&offline, "offline", false, "make no calls at all; skip the guardrail checks")
	return cmd
}

func (a *app) printPlan(w io.Writer, c *technique.Corpus, r *plan.Run, guardLine string) {
	tech, _ := c.Get(r.Technique)
	fmt.Fprintf(w, "%s   %s\n", r.Technique, r.Name)
	var meta []string
	if len(r.Attack) > 0 {
		meta = append(meta, "ATT&CK "+strings.Join(r.Attack, ", "))
	}
	if tech != nil && len(tech.Tradecraft) > 0 {
		meta = append(meta, "tradecraft "+tech.Tradecraft[0].Date)
	}
	meta = append(meta, safetyLabel(r.Safety))
	if !r.Verified {
		meta = append(meta, "UNVERIFIED corpus")
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(meta, " · "))
	fmt.Fprintf(w, "  run       %s against %s (tenant %s, %s)\n", r.Run, r.Target, r.Tenant, r.Environment)
	ref := map[string]int{}
	for _, s := range r.Steps {
		ref[s.ID] = s.Index
	}
	env := technique.Env{
		Run:    map[string]string{"id": r.Run, "prefix": marker.RunPrefix(r.Run)},
		Target: map[string]string{"name": r.Target, "test_domain": r.TestDomain},
	}
	rows := make([][]string, 0, len(r.Steps))
	for _, s := range r.Steps {
		args := renderWith(s.With, ref, env)
		detail := s.Name
		if s.Kind == "modify" {
			detail = "modifies " + args
		} else if args != "" {
			detail += "  " + args
		}
		if s.Note != "" {
			detail += "  (" + s.Note + ")"
		}
		rows = append(rows, []string{fmt.Sprintf("  %d", s.Index), s.Op, s.Request, detail})
	}
	printRows(w, rows)
	for i, cl := range r.Cleanup {
		label := ""
		if i == 0 {
			label = "cleanup"
		}
		fmt.Fprintf(w, "  %-9s %d: %s, then verify %s\n", label, ref[cl.Step], cl.Undo, cl.GoneCheck)
	}
	var exps []string
	for _, x := range r.Expect {
		exps = append(exps, fmt.Sprintf("%s (%s)", x.Type, x.Deadline))
	}
	fmt.Fprintf(w, "  expect    %s\n", strings.Join(exps, ", "))
	for _, d := range r.Detections {
		rule := d.Rule
		if rule == "" {
			rule = "none: no public rule covers this"
		}
		fmt.Fprintf(w, "  detect    %s %s\n", d.Checker, rule)
	}
	fmt.Fprintf(w, "  scopes    %s\n", strings.Join(r.Scopes, " "))
	fmt.Fprintf(w, "  guard     %s\n", guardLine)
}

// renderWith shows parameters for the plan: run and target placeholders
// resolved, step references as {n} (the step's ID) or {n.field}.
func renderWith(with map[string]string, ref map[string]int, env technique.Env) string {
	keys := make([]string, 0, len(with))
	for k := range with {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := with[k]
		tmpl, err := technique.ParseTemplate(v)
		if err == nil {
			e := env
			e.Steps = map[string]map[string]string{}
			for _, r := range tmpl.Refs() {
				if r.Scope != technique.ScopeSteps {
					continue
				}
				if e.Steps[r.Step] == nil {
					e.Steps[r.Step] = map[string]string{}
				}
				label := fmt.Sprintf("{%d}", ref[r.Step])
				if r.Field != "id" {
					label = fmt.Sprintf("{%d.%s}", ref[r.Step], r.Field)
				}
				e.Steps[r.Step][r.Field] = label
			}
			if s, err := tmpl.Resolve(e); err == nil {
				v = s
			}
		}
		if strings.ContainsAny(v, " \t") {
			v = fmt.Sprintf("%q", v)
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

// planTarget names the target a saved plan was made for, for an apply
// that gives --plan without --target. It only picks the name: the target
// is still looked up in the allowlist and loadPlanFile validates the file.
func planTarget(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", refused("read plan: %v", err)
	}
	var f plan.File
	if err := json.Unmarshal(b, &f); err != nil {
		return "", refused("plan %s: %v", path, err)
	}
	if len(f.Runs) == 0 || f.Runs[0].Target == "" {
		return "", refused("plan %s names no target", path)
	}
	return f.Runs[0].Target, nil
}

// loadPlanFile reads a saved plan and re-derives every run from the
// current corpus: a saved plan can only replay what the corpus would plan,
// so editing plan.json cannot make apply run anything else.
func (a *app) loadPlanFile(path string, c *technique.Corpus, t *target.Target, ticket string) ([]*plan.Run, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, refused("read plan: %v", err)
	}
	var f plan.File
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, refused("plan %s: %v", path, err)
	}
	if f.Schema != plan.Schema || f.Version != plan.Version {
		return nil, refused("plan %s: not a %s v%d file", path, plan.Schema, plan.Version)
	}
	if f.Corpus != techniques.Version() {
		return nil, refused("plan %s was made with corpus %s; this binary has %s: re-plan", path, f.Corpus, techniques.Version())
	}
	pl := plan.Planner{Registry: a.reg}
	var runs []*plan.Run
	listed := map[string]bool{}
	for _, saved := range f.Runs {
		if listed[saved.Run] {
			return nil, refused("plan %s lists run %s more than once", path, saved.Run)
		}
		listed[saved.Run] = true
		if saved.Target != t.Name {
			return nil, refused("plan %s is for target %s, not %s", path, saved.Target, t.Name)
		}
		tech, err := c.Lookup(saved.Technique)
		if err != nil {
			return nil, refused("plan %s: %v", path, err)
		}
		fresh, err := pl.Plan(tech, t, saved.Run, ticket)
		if err != nil {
			return nil, refused("plan %s: %v", path, err)
		}
		if saved.Ticket != ticket {
			return nil, refused("plan %s was approved with ticket %q, not %q", path, saved.Ticket, ticket)
		}
		sb, _ := json.Marshal(saved)
		fb, _ := json.Marshal(fresh)
		if !bytes.Equal(sb, fb) {
			return nil, refused("plan %s no longer matches what the corpus and target would do for %s (technique or target changed): re-plan", path, saved.Technique)
		}
		if _, err := a.st.RunDir(saved.Run); err != nil {
			return nil, refused("plan %s: %v", path, err)
		}
		runs = append(runs, fresh)
	}
	if len(runs) == 0 {
		return nil, refused("plan %s has no runs", path)
	}
	return runs, nil
}
