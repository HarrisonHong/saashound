package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/techniques"
)

func (a *app) listCmd() *cobra.Command {
	var platform string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the technique corpus",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.corpus()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			rows := [][]string{{"TECHNIQUE", "NAME", "SAFETY", "CORPUS"}}
			for _, t := range c.List() {
				if platform != "" && t.Platform != platform {
					continue
				}
				rows = append(rows, []string{t.ID, t.Name, safetyLabel(t.Safety), corpusName(t.Verified)})
			}
			printRows(out, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "", "only this platform")
	return cmd
}

func safetyLabel(s technique.Safety) string {
	switch {
	case s.ProductionSafe:
		return "production-safe"
	case s.ModifiesExisting:
		return "lab only (modifies existing)"
	}
	return "lab only"
}

func corpusName(verified bool) string {
	if verified {
		return "verified"
	}
	return "unverified"
}

func (a *app) showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <technique>",
		Short: "Describe a technique: steps, inverses, expected events, detections, safety",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.corpus()
			if err != nil {
				return err
			}
			t, err := c.Lookup(args[0])
			if err != nil {
				return refused("%v", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s   %s\n", t.ID, t.Name)
			if t.Description != "" {
				fmt.Fprintf(out, "\n%s\n", wrap(strings.TrimSpace(t.Description), 76, "  "))
			}
			fmt.Fprintf(out, "\n  platform    %s (%s corpus)\n", t.Platform, corpusName(t.Verified))
			if len(t.Attack) > 0 {
				fmt.Fprintf(out, "  ATT&CK      %s\n", strings.Join(t.Attack, ", "))
			}
			fmt.Fprintf(out, "  author      %s\n", strings.Join(t.Author, ", "))
			fmt.Fprintf(out, "  evidence    %s\n", t.Evidence)
			fmt.Fprintf(out, "  safety      %s; third-party contact: %s\n", safetyLabel(t.Safety), t.Safety.ThirdPartyContact)
			for _, r := range t.Tradecraft {
				fmt.Fprintf(out, "  tradecraft  %s (%s)\n              %s\n", r.Title, r.Date, r.URL)
			}
			fmt.Fprintf(out, "\n  steps\n")
			for i, s := range t.Steps {
				e, _ := a.reg.Op(s.Op)
				fmt.Fprintf(out, "    %d  %-8s %-24s %s\n", i+1, s.ID, s.Op, e.Spec.Summary)
				fmt.Fprintf(out, "       %-8s undo: %s; proof: %s\n", "", e.Spec.UndoSummary, e.Spec.GoneCheck)
			}
			fmt.Fprintf(out, "\n  expect\n")
			for _, x := range t.Expect {
				d := "default deadline"
				if x.Deadline != 0 {
					d = "deadline " + time.Duration(x.Deadline).String()
				}
				fmt.Fprintf(out, "    after %-8s %s  %s\n", x.After, formatMatch(x.Match), d)
			}
			if len(t.Detections) > 0 {
				fmt.Fprintf(out, "\n  detections\n")
				for _, d := range t.Detections {
					rule := d.Rule()
					if rule == "" {
						rule = "none: no public rule covers this"
					}
					fmt.Fprintf(out, "    %-7s %s\n", d.Kind(), rule)
				}
			}
			fmt.Fprintf(out, "\n  cleanup     %s\n", strings.Join(t.Cleanup.Order, " -> "))
			return nil
		},
	}
}

func (a *app) validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file.yaml|dir ...]",
		Short: "Validate technique files against the schema and the registered op vocabulary",
		Long: `Validate technique files. With no arguments, validates the embedded corpus
and any --corpus-dir. Exit 0 if every file is valid, 2 otherwise.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				c, err := a.corpus()
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%d techniques valid (corpus %s)\n", len(c.List()), techniques.Version())
				return nil
			}
			cat := technique.RegistryCatalog(a.reg)
			var errs []error
			n := 0
			for _, p := range args {
				fi, err := os.Stat(p)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				c := technique.NewCorpus("")
				if fi.IsDir() {
					err = c.LoadDir(p, cat)
				} else {
					err = validateFile(p, cat)
					if err == nil {
						n++
					}
				}
				if err != nil {
					errs = append(errs, err)
				}
				n += len(c.List())
			}
			if len(errs) > 0 {
				return exit(report.ExitRefused, errors.Join(errs...))
			}
			fmt.Fprintf(out, "%d techniques valid\n", n)
			return nil
		},
	}
}

func validateFile(path string, cat technique.Catalog) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	t, err := technique.Parse(filepath.Base(path), b)
	if err != nil {
		return err
	}
	return technique.Validate(t, cat)
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "saashound %s (corpus %s, result schema %s/v%d, providers: %s)\n",
				a.version, techniques.Version(), report.Schema, report.Version, strings.Join(a.reg.Providers(), ", "))
			return nil
		},
	}
}

func formatMatch(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}

func wrap(s string, width int, indent string) string {
	var lines []string
	line := indent
	for _, w := range strings.Fields(s) {
		if len(line)+len(w)+1 > width && strings.TrimSpace(line) != "" {
			lines = append(lines, line)
			line = indent
		}
		if strings.TrimSpace(line) != "" {
			line += " "
		}
		line += w
	}
	if strings.TrimSpace(line) != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
