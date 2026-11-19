package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/detect"
	"github.com/HarrisonHong/saashound/internal/telemetry"
)

func f(v float64) *float64 { return &v }
func b(v bool) *bool       { return &v }

func rec() *Record {
	r := &Record{
		Run: "k3v9q2", Technique: "fake.persistence.x",
		Detonate:   Detonate{Status: DetonateOK, Steps: 2, Completed: 2},
		Cleanup:    Cleanup{Status: CleanupVerified, Objects: 2, Orphans: []Orphan{}},
		Detections: []detect.Result{},
		Telemetry: Telemetry{Expectations: []telemetry.Outcome{
			{Status: telemetry.StatusObserved, LatencyS: f(1.5)},
			{Status: telemetry.StatusObserved, LatencyS: f(3)},
		}},
	}
	r.Telemetry.Summarize()
	return r
}

func TestVerdicts(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Record)
		want string
		code int
	}{
		{"pass", func(*Record) {}, VerdictPass, 0},
		{"detection missing", func(r *Record) {
			r.Detections = []detect.Result{{Checker: "sigma", Fired: b(true)}, {Checker: "exec", Fired: b(false)}}
		}, VerdictDetectionMissing, 1},
		{"undecided detection is not a miss", func(r *Record) {
			r.Detections = []detect.Result{{Checker: "exec", Error: "timeout"}}
		}, VerdictPass, 0},
		{"telemetry missing", func(r *Record) {
			r.Telemetry.Expectations[1].Status = telemetry.StatusMissing
			r.Telemetry.Summarize()
		}, VerdictTelemetryMissing, 1},
		{"late counts as missing", func(r *Record) {
			r.Telemetry.Expectations[1].Status = telemetry.StatusLate
			r.Telemetry.Summarize()
		}, VerdictTelemetryMissing, 1},
		{"unsupported tier", func(r *Record) {
			r.Telemetry.Expectations[0].Status = telemetry.StatusUnsupported
			r.Telemetry.Summarize()
		}, VerdictTelemetryUnsupported, 0},
		{"detonation failed", func(r *Record) {
			r.Detonate = Detonate{Status: DetonateFailed, FailedStep: "factor", Error: "boom"}
		}, VerdictDetonateFailed, 1},
		{"skipped", func(r *Record) {
			r.Detonate = Detonate{Status: DetonateNotRun}
			r.Cleanup = Cleanup{Status: CleanupNotRun}
		}, VerdictSkipped, 0},
		{"unverified cleanup outranks everything", func(r *Record) {
			r.Cleanup = Cleanup{Status: CleanupUnverified, Retry: "saashound cleanup k3v9q2"}
			r.Detonate = Detonate{Status: DetonateFailed}
			r.Telemetry.Expectations[1].Status = telemetry.StatusMissing
			r.Telemetry.Summarize()
		}, VerdictCleanupUnverified, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rec()
			c.mut(r)
			r.Decide()
			if r.Verdict != c.want || ExitCode(r.Verdict) != c.code {
				t.Fatalf("verdict %s (exit %d), want %s (exit %d)", r.Verdict, ExitCode(r.Verdict), c.want, c.code)
			}
			if r.Verdict != VerdictPass && r.Reason == "" {
				t.Fatal("a non-pass verdict needs a reason")
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	r := rec()
	if r.Telemetry.Status != telemetry.StatusObserved || r.Telemetry.Observed != 2 || *r.Telemetry.MaxLatencyS != 3 {
		t.Fatalf("%+v", r.Telemetry)
	}
	r.Telemetry.Expectations[0].Status = telemetry.StatusNotRun
	r.Telemetry.Summarize()
	if r.Telemetry.Status != TelemetryIncomplete {
		t.Fatalf("status %s", r.Telemetry.Status)
	}
}

func TestCombine(t *testing.T) {
	mk := func(v string) *Record { return &Record{Verdict: v} }
	cases := []struct {
		vs   []string
		want int
	}{
		{nil, 0},
		{[]string{VerdictPass, VerdictSkipped, VerdictTelemetryUnsupported}, 0},
		{[]string{VerdictPass, VerdictDetectionMissing}, 1},
		{[]string{VerdictTelemetryMissing, VerdictCleanupUnverified, VerdictPass}, 3},
		{[]string{VerdictCleanupUnverified, VerdictDetectionMissing}, 3},
	}
	for _, c := range cases {
		var rs []*Record
		for _, v := range c.vs {
			rs = append(rs, mk(v))
		}
		if got := Combine(rs); got != c.want {
			t.Errorf("Combine(%v) = %d, want %d", c.vs, got, c.want)
		}
	}
}

func TestDetectionsCell(t *testing.T) {
	cases := []struct {
		name string
		dets []detect.Result
		want string
	}{
		{"none", nil, "-"},
		{"fired", []detect.Result{{Status: detect.StatusFired, Fired: b(true)}}, "1/1"},
		{"not fired", []detect.Result{{Status: detect.StatusNotFired, Fired: b(false)}}, "0/1"},
		{"unknown", []detect.Result{{Status: detect.StatusUnknown}}, "0/1 (unknown)"},
		{"unsupported", []detect.Result{{Status: detect.StatusUnsupported}}, "0/1 (unsupported)"},
		{"mixed", []detect.Result{
			{Status: detect.StatusFired, Fired: b(true)},
			{Status: detect.StatusUnknown},
			{Status: detect.StatusUnsupported},
		}, "1/3 (unknown,unsupported)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rec()
			r.Detections = c.dets
			if got := detectionsCell(r); got != c.want {
				t.Fatalf("detectionsCell = %q, want %q", got, c.want)
			}
		})
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	tb := &Table{W: &buf, Color: true}
	r := rec()
	r.Decide()
	bad := rec()
	bad.Technique = "fake.privilege-escalation.longer-technique-name"
	bad.Cleanup = Cleanup{Status: CleanupUnverified, Retry: "saashound cleanup abcdef", Orphans: []Orphan{{Step: "victim", Op: "fake.user.create", Name: "saashound-abcdef-victim"}}}
	bad.Decide()
	_ = tb.Write(r)
	_ = tb.Write(bad)
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(stripANSI(buf.String()), "\n")
	// Colour codes must not break column alignment.
	col := strings.Index(lines[0], "VERDICT")
	for _, l := range lines[1:3] {
		if !strings.HasPrefix(l[col:], "pass") && !strings.HasPrefix(l[col:], "cleanup-unverified") {
			t.Fatalf("misaligned table:\n%s", buf.String())
		}
	}
	if !strings.Contains(buf.String(), "saashound cleanup abcdef") {
		t.Fatal("an unverified cleanup must print the retry command")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
