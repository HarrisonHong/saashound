package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/HarrisonHong/saashound/internal/detect"
)

// IsTerminal reports whether f is a character device (a TTY).
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Sink receives finished records.
type Sink interface {
	Write(r *Record) error
	Close() error
}

// JSONLines writes one JSON object per line, as each technique finishes.
type JSONLines struct{ W io.Writer }

// Write implements Sink.
func (j JSONLines) Write(r *Record) error {
	b, err := r.MarshalLine()
	if err != nil {
		return err
	}
	_, err = j.W.Write(b)
	return err
}

// Close implements Sink.
func (JSONLines) Close() error { return nil }

// Table collects records and prints the human view when closed.
type Table struct {
	W       io.Writer
	Color   bool
	records []*Record
}

// Write implements Sink.
func (t *Table) Write(r *Record) error {
	t.records = append(t.records, r)
	return nil
}

// Close implements Sink: it renders the table.
func (t *Table) Close() error {
	if len(t.records) == 0 {
		return nil
	}
	rows := [][]string{{"TECHNIQUE", "VERDICT", "TELEMETRY", "DETECTIONS", "CLEANUP"}}
	for _, r := range t.records {
		rows = append(rows, []string{r.Technique, r.Verdict, telemetryCell(r), detectionsCell(r), cleanupCell(r)})
	}
	// Pad before colouring, so escape codes never skew the columns.
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			widths[i] = max(widths[i], len(c))
		}
	}
	for n, row := range rows {
		var b strings.Builder
		for i, c := range row {
			cell := c
			if i < len(row)-1 {
				cell += strings.Repeat(" ", widths[i]-len(c)+2)
			}
			if n > 0 && (i == 1 || i == 4) {
				cell = strings.Replace(cell, c, t.paint(c), 1)
			}
			b.WriteString(cell)
		}
		if _, err := fmt.Fprintln(t.W, b.String()); err != nil {
			return err
		}
	}
	for _, r := range t.records {
		if r.Cleanup.Status == CleanupUnverified {
			fmt.Fprintf(t.W, "%s\n", t.red(fmt.Sprintf("cleanup NOT verified for run %s; orphans:", r.Run)))
			for _, o := range r.Cleanup.Orphans {
				fmt.Fprintf(t.W, "  %s %s %s %s\n", o.Step, o.Op, o.Name, o.Error)
			}
			fmt.Fprintf(t.W, "retry with:  %s\n", r.Cleanup.Retry)
		}
	}
	return nil
}

func telemetryCell(r *Record) string {
	tel := r.Telemetry
	switch tel.Status {
	case "unsupported":
		return "unsupported"
	case "":
		return "-"
	}
	s := fmt.Sprintf("%d/%d", tel.Observed, tel.Expected)
	if tel.MaxLatencyS != nil {
		s += fmt.Sprintf(" (%.1fs)", *tel.MaxLatencyS)
	}
	if tel.Late > 0 {
		s += fmt.Sprintf(" %d late", tel.Late)
	}
	return s
}

func detectionsCell(r *Record) string {
	if len(r.Detections) == 0 {
		return "-"
	}
	var fired, unknown, unsupported, errc int
	for _, d := range r.Detections {
		switch {
		case d.Fired != nil && *d.Fired:
			fired++
		case d.Status == detect.StatusUnknown:
			unknown++
		case d.Status == detect.StatusUnsupported:
			unsupported++
		case d.Status == detect.StatusError:
			errc++
		}
	}
	cell := fmt.Sprintf("%d/%d", fired, len(r.Detections))
	var notes []string
	if unknown > 0 {
		notes = append(notes, "unknown")
	}
	if unsupported > 0 {
		notes = append(notes, "unsupported")
	}
	if errc > 0 {
		notes = append(notes, "error")
	}
	if len(notes) > 0 {
		cell += " (" + strings.Join(notes, ",") + ")"
	}
	return cell
}

func cleanupCell(r *Record) string {
	switch r.Cleanup.Status {
	case CleanupVerified:
		return "verified"
	case CleanupUnverified:
		return "UNVERIFIED"
	}
	return r.Cleanup.Status
}

func (t *Table) paint(s string) string {
	switch {
	case !t.Color:
		return s
	case s == VerdictPass || s == "verified":
		return "\x1b[32m" + s + "\x1b[0m"
	case s == VerdictCleanupUnverified || s == "UNVERIFIED":
		return t.red(s)
	case s == VerdictSkipped || s == VerdictTelemetryUnsupported:
		return s
	case strings.Contains(s, "missing") || s == VerdictDetonateFailed:
		return "\x1b[33m" + s + "\x1b[0m"
	}
	return s
}

func (t *Table) red(s string) string {
	if !t.Color {
		return s
	}
	return "\x1b[1;31m" + s + "\x1b[0m"
}
