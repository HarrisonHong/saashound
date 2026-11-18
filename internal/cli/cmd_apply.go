package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/guard"
	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/telemetry"
	"github.com/HarrisonHong/saashound/techniques"
)

func (a *app) applyCmd() *cobra.Command {
	var (
		rf       runFlags
		yes      bool
		planPath string
	)
	cmd := &cobra.Command{
		Use:   "apply (<technique...> --target <target> | --plan plan.json)",
		Short: "Detonate, clean up and prove it, collect telemetry, check expectations, report",
		Long: `For each technique: run the guardrail, detonate step by step with a
write-ahead journal, undo everything in reverse and prove each object gone,
then read the platform's own audit log for exactly this run's events and
match them against the technique's expectations.

The first Ctrl-C stops detonating and cleans up; a second abandons cleanup
and prints the command that resumes it.

Exit codes: 0 every expectation met, 1 an expectation failed, 2 refused,
3 cleanup not verified (overrides 1).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if planPath == "" && len(args) == 0 {
				return refused("name at least one technique, or --plan plan.json")
			}
			if planPath != "" && len(args) > 0 {
				return refused("use either technique names or --plan, not both")
			}
			c, err := a.corpus()
			if err != nil {
				return err
			}
			targetName := rf.target
			if targetName == "" && planPath != "" {
				// A saved plan records its target; loadPlanFile still
				// refuses a plan whose runs disagree with it.
				if targetName, err = planTarget(planPath); err != nil {
					return err
				}
			}
			t, err := a.lookupTarget(targetName)
			if err != nil {
				return err
			}
			var runs []*plan.Run
			if planPath != "" {
				runs, err = a.loadPlanFile(planPath, c, t, rf.ticket)
			} else {
				runs, err = a.buildPlans(c, t, args, rf.ticket)
			}
			if err != nil {
				return err
			}

			lock, err := a.st.LockTarget(t.Name)
			if err != nil {
				return refused("%v", err)
			}
			defer lock.Unlock()

			tr := &tracer{p: a.progress}
			ten, err := a.open(cmd.Context(), t, tr)
			if err != nil {
				return err
			}
			defer ten.Close()

			_, err = guard.Check(cmd.Context(), guard.Request{
				Mode: guard.ModeApply, Target: t, Tenant: ten, Runs: runs,
				Production: rf.production, Ticket: rf.ticket,
				Yes: yes, Interactive: a.interactive(), Confirm: a.confirm,
			})
			if err != nil {
				return exit(report.ExitRefused, err)
			}

			dctx, cctx, stop := a.interrupts(cmd.Context(), "interrupted: stopping detonation and cleaning up (Ctrl-C again to abandon cleanup)")
			defer stop()
			eng := a.engine()
			sink := a.sink()
			var records []*report.Record
			stopReason := ""
			var applyErr error
			for _, r := range runs {
				var rec *report.Record
				switch {
				case stopReason != "":
					rec = a.skipped(r, stopReason)
				default:
					tr.setRun(r.Run)
					rec, err = eng.Apply(dctx, cctx, t, ten, r)
					if err != nil {
						// Nothing was mutated: the journal could not be
						// started. Do not run anything else, but still
						// report the techniques that already ran.
						applyErr = fmt.Errorf("%s (run %s) was not started: %w", r.Technique, r.Run, err)
					}
					switch {
					case applyErr != nil:
					case rec.Cleanup.Status != report.CleanupVerified:
						stopReason = "run " + r.Run + " left cleanup unverified; no further techniques run until it is cleaned up"
					case dctx.Err() != nil:
						stopReason = "interrupted"
					}
				}
				if applyErr != nil {
					break
				}
				records = append(records, rec)
				if err := sink.Write(rec); err != nil {
					return err
				}
			}
			if err := sink.Close(); err != nil {
				return err
			}
			if applyErr != nil {
				return exit(max(report.ExitRefused, report.Combine(records)), applyErr)
			}
			return exit(report.Combine(records), nil)
		},
	}
	rf.register(cmd)
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "confirm without typing the tenant name (required when not on a terminal)")
	cmd.Flags().StringVar(&planPath, "plan", "", "execute exactly this saved plan; refused if it no longer matches")
	cmd.Flags().BoolVar(&a.jsonl, "jsonl", false, "JSON lines on stdout even on a terminal")
	return cmd
}

// skipped is the record for a technique that was not run.
func (a *app) skipped(r *plan.Run, reason string) *report.Record {
	now := a.env.Clock.Now().UTC()
	rec := &report.Record{
		Schema: report.Schema, Version: report.Version,
		Run: r.Run, Technique: r.Technique, Corpus: corpusName(r.Verified), CorpusVersion: techniques.Version(),
		Target: r.Target, Platform: r.Platform, Environment: r.Environment,
		Tool:    "saashound/" + a.version,
		Started: now, Finished: now,
		Detonate:   report.Detonate{Status: report.DetonateNotRun, Steps: len(r.Steps)},
		Cleanup:    report.Cleanup{Status: report.CleanupNotRun, Orphans: []report.Orphan{}},
		Telemetry:  report.Telemetry{Status: telemetry.StatusNotRun, Expectations: []telemetry.Outcome{}, Expected: len(r.Expect)},
		Detections: []detect.Result{},
	}
	if r.Ticket != "" {
		t := r.Ticket
		rec.Ticket = &t
	}
	rec.Decide()
	rec.Reason = reason
	return rec
}
