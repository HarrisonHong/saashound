package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// progress renders engine events on stderr:
//
//	[k3v9q2] detonate  2/2 steps ok                    0.1s
type progress struct {
	mu      sync.Mutex
	w       io.Writer
	quiet   bool
	verbose int
	color   bool
	// detail shows -v detail for these stages even without -v.
	detail map[string]bool
}

func (p *progress) event(ev engine.Event) {
	if p == nil || p.quiet {
		return
	}
	level := p.verbose
	if p.detail[ev.Stage] {
		level = max(level, 1)
	}
	if ev.Level > level {
		return
	}
	line := fmt.Sprintf("[%s] %-9s %s", ev.Run, ev.Stage, ev.Msg)
	if ev.Duration > 0 {
		line = fmt.Sprintf("%-62s %s", line, formatDuration(ev.Duration))
	}
	if ev.Alarm && p.color {
		line = "\x1b[1;31m" + line + "\x1b[0m"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintln(p.w, strings.TrimRight(line, " "))
}

// alarm prints a message the operator must see, even with -q.
func (p *progress) alarm(msg string) {
	if p == nil {
		return
	}
	if p.color {
		msg = "\x1b[1;31m" + msg + "\x1b[0m"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintln(p.w, msg)
}

func formatDuration(d time.Duration) string {
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// tracer prints one line per API call at -v: method, path, status and
// latency. It never sees headers or bodies, so it cannot print a secret.
type tracer struct {
	p   *progress
	mu  sync.Mutex
	run string
}

func (t *tracer) setRun(run string) {
	t.mu.Lock()
	t.run = run
	t.mu.Unlock()
}

func (t *tracer) trace(r provider.Request) {
	t.mu.Lock()
	run := t.run
	t.mu.Unlock()
	if run == "" {
		run = "------"
	}
	t.p.event(engine.Event{Run: run, Level: 1, Stage: "api", Msg: fmt.Sprintf("%s %s %d %s", r.Method, r.Path, r.Status, formatDuration(r.Duration))})
}
