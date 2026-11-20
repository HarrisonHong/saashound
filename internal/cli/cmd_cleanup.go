package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/guard"
	"github.com/HarrisonHong/saashound/internal/journal"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/target"
)

func (a *app) cleanupCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "cleanup [<run-id>...] [--all]",
		Short: "Undo runs from their journals and prove every object gone; idempotent",
		Long: `Replay a run's write-ahead journal: undo, in reverse, every step that may
have left something behind, and prove each object gone. A step whose
journal has an intent but no recorded ID (the process died mid-call) is
found by its exact deterministic name. Running cleanup again is harmless.

Every named run is attempted: one that cannot be cleaned up (its target
is gone from targets.yaml, it is busy, the tenant does not match) is
reported on stderr and the rest still run. Only abandoning a cleanup
(a second Ctrl-C) stops the command: the remaining runs are not attempted
and are listed with the command that cleans each one up.

Exit 0 when every object is proven gone, 3 when a cleanup is not verified,
otherwise 2 when a run was refused.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return refused("name run ids, or --all for every run with pending cleanup")
			}
			runs := args
			if all {
				infos, err := a.st.Runs()
				if err != nil {
					return exit(report.ExitRefused, err)
				}
				for _, in := range infos {
					if in.Pending > 0 && in.State != state.StateRunning {
						runs = append(runs, in.Run)
					}
				}
				if len(runs) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "no runs with pending cleanup")
					return nil
				}
			}
			code := report.ExitOK
			for i, run := range runs {
				c, abandoned, err := a.cleanupRun(cmd, run)
				if abandoned {
					for _, rest := range runs[i+1:] {
						fmt.Fprintf(cmd.OutOrStdout(), "cleanup not attempted for run %s (cleanup was abandoned); retry with:  saashound cleanup %s\n", rest, rest)
					}
					return exit(report.ExitCleanupUnverified, nil)
				}
				if err != nil {
					c = report.ExitRefused
					var ee *exitError
					if errors.As(err, &ee) {
						c = ee.code
					}
					fmt.Fprintf(cmd.ErrOrStderr(), "saashound: run %s: %v\n", run, err)
				}
				code = max(code, c)
			}
			return exit(code, nil)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "clean up every run with pending cleanup")
	return cmd
}

// cleanupRun cleans up one run. abandoned reports that the operator gave up
// on it, which ends the whole command.
func (a *app) cleanupRun(cmd *cobra.Command, run string) (code int, abandoned bool, err error) {
	if !marker.ValidRunID(run) {
		return 0, false, refused("%q is not a run id", run)
	}
	jpath, err := a.st.File(run, state.JournalFile)
	if err != nil {
		return 0, false, refused("%v", err)
	}
	j, err := journal.Load(jpath)
	if err != nil {
		return 0, false, refused("%v", err)
	}
	t, err := a.lookupTarget(j.Header.Target)
	if err != nil {
		return 0, false, err
	}
	lock, err := a.st.LockTarget(t.Name)
	if err != nil {
		return 0, false, refused("%v", err)
	}
	defer lock.Unlock()
	rlock, err := a.st.LockRun(run)
	if err != nil {
		return 0, false, refused("%v", err)
	}
	defer rlock.Unlock()

	tr := &tracer{p: a.progress}
	tr.setRun(run)
	// Undoing the run needs exactly the scopes of the ops it journalled.
	ops := make([]string, 0, len(j.Header.Steps))
	for _, s := range j.Header.Steps {
		ops = append(ops, s.Op)
	}
	ten, err := a.open(cmd.Context(), t, tr, access{scopes: a.opScopes(ops)})
	if err != nil {
		return 0, false, err
	}
	defer ten.Close()
	// Cleanup needs no marker, but it must be the tenant the run touched.
	if _, err := guard.Check(cmd.Context(), guard.Request{Mode: guard.ModeCleanup, Target: t, Tenant: ten}); err != nil {
		return 0, false, exit(report.ExitRefused, err)
	}
	// Cleanup is always shown step by step: it is what the operator asked.
	a.progress.detail = map[string]bool{"cleanup": true}
	eng := a.engine()
	_, cctx, stop := a.interrupts(cmd.Context(), "interrupted: cleanup of run "+run+" continues, so nothing is left behind (Ctrl-C again to abandon it)")
	defer stop()
	res, err := eng.Cleanup(cctx, run, t, ten, "cleanup")
	if err != nil {
		return 0, false, refused("%v", err)
	}
	out := cmd.OutOrStdout()
	if res.Verified() {
		fmt.Fprintf(out, "cleanup verified for run %s (%d %s)\n", run, res.Objects, plural(res.Objects, "object", "objects"))
		return report.ExitOK, false, nil
	}
	fmt.Fprintf(out, "cleanup NOT verified for run %s; retry with:  saashound cleanup %s\n", run, run)
	return report.ExitCleanupUnverified, res.Status == engine.CleanupAbandoned, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func (a *app) statusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List runs and their states",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			infos, err := a.st.Runs()
			if err != nil {
				return exit(report.ExitRefused, err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				for _, in := range infos {
					b, _ := json.Marshal(in)
					fmt.Fprintln(out, string(b))
				}
				return nil
			}
			if len(infos) == 0 {
				fmt.Fprintln(out, "no runs")
				return nil
			}
			rows := [][]string{{"RUN", "TARGET", "TECHNIQUE", "STATE", "STARTED"}}
			for _, in := range infos {
				st := in.State
				if in.Error != "" {
					st = "error: " + in.Error
				}
				started := "-"
				if !in.Started.IsZero() {
					started = in.Started.Local().Format("2006-01-02 15:04:05")
				}
				rows = append(rows, []string{in.Run, orDash(in.Target), orDash(in.Technique), st, started})
			}
			printRows(out, rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "one JSON object per run")
	return cmd
}

func (a *app) sweepCmd() *cobra.Command {
	var (
		targetName string
		del        bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "sweep --target <target> [--delete]",
		Short: "Find objects carrying the reserved prefix that no journal accounts for",
		Long: fmt.Sprintf(`Ask the platform for every object named %s-<run>-<step>. Objects whose run
has a local journal are reported with the cleanup command to use; the rest
are true orphans (their journal was lost, e.g. on a vanished CI runner) and
--delete removes them, after typed confirmation or --yes, proving each gone.

Exit 0 when nothing is left behind, 3 otherwise.`, marker.Prefix),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := a.lookupTarget(targetName)
			if err != nil {
				return err
			}
			lock, err := a.st.LockTarget(t.Name)
			if err != nil {
				return refused("%v", err)
			}
			defer lock.Unlock()
			tr := &tracer{p: a.progress}
			// Sweep lists every kind of object the platform's create ops
			// make, and with --delete may remove any of them, so it asks for
			// those ops' scopes (read-only without --delete), but only those
			// the credential can get: an operator may withhold the scopes of
			// techniques they never run. A provider that then cannot see some
			// kind of object refuses rather than report the tenant clean.
			ten, err := a.open(cmd.Context(), t, tr, access{optional: a.sweepScopes(t.Platform), readOnly: !del})
			if err != nil {
				return err
			}
			defer ten.Close()
			rep, err := guard.Check(cmd.Context(), guard.Request{Mode: guard.ModeCleanup, Target: t, Tenant: ten})
			if err != nil {
				return exit(report.ExitRefused, err)
			}
			return a.sweep(cmd, t, ten, rep.Identity, del, yes)
		},
	}
	cmd.Flags().StringVarP(&targetName, "target", "t", "", "target name from targets.yaml")
	cmd.Flags().BoolVar(&del, "delete", false, "remove orphans that no local journal accounts for")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "confirm deletion without typing the tenant name")
	return cmd
}

func (a *app) sweep(cmd *cobra.Command, t *target.Target, ten provider.Tenant, id provider.Identity, del, yes bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	found, err := ten.Sweep(provider.WithUserAgent(ctx, marker.UserAgent(a.version, "", marker.PhaseSweep)), marker.Prefix+"-")
	if err != nil {
		return refused("sweep: %v", err)
	}
	type item struct {
		o     provider.Orphan
		run   string
		state string
	}
	var tracked, orphans []item
	for _, o := range found {
		run, _, ok := marker.ParseObjectName(o.Name)
		if !ok {
			continue // not a run-created name; never touched
		}
		it := item{o: o, run: run}
		if dir, err := a.st.File(run, state.JournalFile); err == nil && fileExists(dir) {
			it.state = a.st.Info(run).State
			tracked = append(tracked, it)
		} else {
			orphans = append(orphans, it)
		}
	}
	if len(tracked)+len(orphans) == 0 {
		fmt.Fprintf(out, "no %s- objects found in tenant %s\n", marker.Prefix, t.Tenant)
		return nil
	}
	rows := [][]string{{"OBJECT", "RESOURCE", "ID", "RUN", "JOURNAL"}}
	for _, it := range tracked {
		rows = append(rows, []string{it.o.Name, it.o.Resource, it.o.Record.ID, it.run, it.state + " (use: saashound cleanup " + it.run + ")"})
	}
	for _, it := range orphans {
		rows = append(rows, []string{it.o.Name, it.o.Resource, it.o.Record.ID, it.run, "none"})
	}
	printRows(out, rows)
	if !del || len(orphans) == 0 {
		if len(orphans) > 0 {
			fmt.Fprintf(out, "%d orphaned %s with no local journal; remove with:  saashound sweep --target %s --delete\n",
				len(orphans), plural(len(orphans), "object", "objects"), t.Name)
		}
		return exit(report.ExitCleanupUnverified, nil)
	}
	if !yes {
		if !a.interactive() {
			return refused("not running on a terminal: pass --yes to confirm deletion")
		}
		typed, err := a.confirm(fmt.Sprintf("Delete %d %s from %q (%s)? Type the tenant short name %q to continue: ",
			len(orphans), plural(len(orphans), "object", "objects"), id.DisplayName, id.Domain, id.ShortName))
		if err != nil || strings.TrimSpace(typed) != id.ShortName {
			return refused("deletion not confirmed")
		}
	}
	eng := a.engine()
	failed := 0
	for _, it := range orphans {
		res := eng.RemoveOrphan(ctx, t, ten, it.o)
		if res.Verified {
			fmt.Fprintf(out, "%s %s -> %s -> verified gone\n", it.o.Name, it.o.Record.ID, res.Outcome)
		} else {
			failed++
			fmt.Fprintf(out, "%s %s -> NOT verified: %s\n", it.o.Name, it.o.Record.ID, res.Error)
		}
	}
	if failed > 0 || len(tracked) > 0 {
		return exit(report.ExitCleanupUnverified, nil)
	}
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
