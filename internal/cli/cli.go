// Package cli is the saashound command line. It wires targets.yaml, the
// embedded corpus, the provider registry, the guardrail and the engine
// together; everything with behaviour lives in those packages.
//
// stdout carries results only (a table on a terminal, JSON lines when piped
// or with --jsonl); stderr carries progress. Exit codes: 0 every expectation
// met, 1 an expectation failed, 2 usage/config/guardrail refusal, 3 cleanup
// not verified.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/detect/sigma"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/guard"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/internal/state"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/internal/technique"
	"github.com/HarrisonHong/saashound/internal/version"
	"github.com/HarrisonHong/saashound/techniques"
)

// Env is everything the CLI takes from its surroundings, so tests can run
// it in-process.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// StdoutTTY selects the table view; StdinTTY/StderrTTY enable typed
	// confirmation.
	StdoutTTY bool
	StdinTTY  bool
	StderrTTY bool
	// Registry defaults to provider.Default.
	Registry *provider.Registry
	Clock    clock.Clock
	// Secrets defaults to secret.DefaultSource.
	Secrets secret.Source
	// Retry overrides the cleaner's retry policy (tests use zero backoff).
	Retry *engine.Retry
	// Hook is the crash-injection hook; only tests set it.
	Hook func(engine.Point, string)
	// Signals, if set, replaces os/signal for interrupts.
	Signals <-chan os.Signal
	// NewRunID overrides run ID generation (golden tests).
	NewRunID func() (string, error)
	// Version overrides the tool version (golden tests).
	Version string
}

// OSEnv is the real process environment.
func OSEnv() Env {
	return Env{
		Stdin:     os.Stdin,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Getenv:    os.Getenv,
		StdoutTTY: report.IsTerminal(os.Stdout),
		StdinTTY:  report.IsTerminal(os.Stdin),
		StderrTTY: report.IsTerminal(os.Stderr),
	}
}

// exitError carries an exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// exit returns an error that makes Main exit with code; a nil err prints
// nothing.
func exit(code int, err error) error { return &exitError{code: code, err: err} }

// refused is a usage, config or guardrail refusal: exit 2.
func refused(format string, a ...any) error {
	return exit(report.ExitRefused, fmt.Errorf(format, a...))
}

type app struct {
	env Env

	targetsPath string
	stateDir    string
	corpusDir   string
	sigmaRules  string
	quiet       bool
	verbose     int
	noColor     bool
	jsonl       bool

	reg      *provider.Registry
	st       state.Dir
	progress *progress
	version  string
}

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if env.Stdin == nil {
		env.Stdin = strings.NewReader("")
	}
	if env.Registry == nil {
		env.Registry = provider.Default
	}
	if env.Clock == nil {
		env.Clock = clock.Real{}
	}
	if env.Secrets == nil {
		env.Secrets = secret.DefaultSource{LookupEnv: func(k string) (string, bool) {
			v := env.Getenv(k)
			return v, v != ""
		}}
	}
	a := &app{env: env, reg: env.Registry, version: env.Version}
	if a.version == "" {
		a.version = version.String()
	}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetIn(env.Stdin)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return report.ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(env.Stderr, "saashound: %v\n", ee.err)
		}
		return ee.code
	}
	// Anything else is a usage or configuration problem found before any
	// mutation (cobra's own argument errors included).
	fmt.Fprintf(env.Stderr, "saashound: %v\n", err)
	return report.ExitRefused
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "saashound",
		Short: "Adversary emulation with verified detection for SaaS and identity platforms",
		Long: `SaaSHound runs documented SaaS and identity-provider intrusion techniques
against a tenant you own, cleans up provably, and tells you technique by
technique whether the platform logged it and whether your detection fired.

It talks to nothing but the declared tenant: no telemetry, no update checks,
no listener.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return a.setup()
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&a.targetsPath, "targets", "", "path to targets.yaml (default $SAASHOUND_TARGETS or <config dir>/saashound/targets.yaml)")
	pf.StringVar(&a.stateDir, "state-dir", "", "state directory for run journals (default $SAASHOUND_STATE_DIR or $XDG_STATE_HOME/saashound)")
	pf.StringVar(&a.corpusDir, "corpus-dir", "", "load extra techniques from this directory; they are reported as unverified")
	pf.BoolVarP(&a.quiet, "quiet", "q", false, "no progress on stderr")
	pf.CountVarP(&a.verbose, "verbose", "v", "more progress: -v adds one line per API call, -vv per-event matching detail")
	pf.BoolVar(&a.noColor, "no-color", false, "never colour output")
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return refused("%v", err) })

	root.AddCommand(
		a.initCmd(), a.authCmd(),
		a.listCmd(), a.showCmd(), a.validateCmd(),
		a.planCmd(), a.applyCmd(),
		a.cleanupCmd(), a.statusCmd(), a.sweepCmd(),
		a.versionCmd(),
	)
	return root
}

func (a *app) setup() error {
	if a.targetsPath == "" {
		a.targetsPath = a.env.Getenv("SAASHOUND_TARGETS")
	}
	if a.targetsPath == "" {
		dir, err := configDir(a.env.Getenv)
		if err != nil {
			return refused("%v", err)
		}
		a.targetsPath = filepath.Join(dir, "targets.yaml")
	}
	root := a.stateDir
	if root == "" {
		var err error
		if root, err = state.DefaultRoot(a.env.Getenv); err != nil {
			return refused("%v", err)
		}
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return refused("state directory: %v", err)
	}
	a.st = state.Dir{Root: abs}
	color := !a.noColor && a.env.StderrTTY && a.env.Getenv("NO_COLOR") == ""
	a.progress = &progress{w: a.env.Stderr, quiet: a.quiet, verbose: a.verbose, color: color}
	return nil
}

func configDir(getenv func(string) string) (string, error) {
	if d := getenv("SAASHOUND_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := getenv("XDG_CONFIG_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "saashound"), nil
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "saashound"), nil
	}
	home := getenv("HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config directory: %w", err)
		}
		home = h
	}
	return filepath.Join(home, ".config", "saashound"), nil
}

// corpus loads the embedded corpus and any --corpus-dir techniques.
func (a *app) corpus() (*technique.Corpus, error) {
	c := technique.NewCorpus(techniques.Version())
	cat := technique.RegistryCatalog(a.reg)
	if err := c.LoadFS(techniques.FS(), true, cat); err != nil {
		return nil, fmt.Errorf("embedded corpus is invalid (this is a bug): %w", err)
	}
	if a.corpusDir != "" {
		if err := c.LoadDir(a.corpusDir, cat); err != nil {
			return nil, exit(report.ExitRefused, err)
		}
	}
	return c, nil
}

func (a *app) targets() (*target.File, error) {
	f, err := target.Load(a.targetsPath)
	if err != nil {
		return nil, refused("%v", err)
	}
	return f, nil
}

// lookupTarget returns an allowlisted target or a refusal.
func (a *app) lookupTarget(name string) (*target.Target, error) {
	if name == "" {
		return nil, refused("--target is required")
	}
	f, err := a.targets()
	if err != nil {
		return nil, err
	}
	t, err := f.Get(name)
	if err != nil {
		return nil, exit(report.ExitRefused, &guard.Refusal{Check: guard.CheckAllowlist,
			Reason: fmt.Sprintf("%v (%s); declare it with `saashound init %s --platform <platform>`", err, a.targetsPath, name)})
	}
	if _, ok := a.reg.Provider(t.Platform); !ok {
		return nil, refused("target %s: platform %q is not built into this binary (have: %s)", name, t.Platform, strings.Join(a.reg.Providers(), ", "))
	}
	return t, nil
}

// providerConfig builds the config a provider opens a target with.
func (a *app) providerConfig(t *target.Target, tr *tracer) provider.Config {
	cfg := provider.Config{
		Target:     t.Info(),
		Credential: t.Credential,
		Secrets:    a.env.Secrets,
		StateDir:   a.st.ProviderDir(t.Platform),
		Clock:      a.env.Clock,
	}
	if tr != nil {
		cfg.Trace = tr.trace
	}
	return cfg
}

// open connects to a target's tenant.
func (a *app) open(ctx context.Context, t *target.Target, tr *tracer) (provider.Tenant, error) {
	p, _ := a.reg.Provider(t.Platform)
	ten, err := p.Open(ctx, a.providerConfig(t, tr))
	if err != nil {
		return nil, refused("open target %s: %v", t.Name, err)
	}
	return ten, nil
}

func (a *app) engine() *engine.Engine {
	retry := engine.DefaultRetry()
	if a.env.Retry != nil {
		retry = *a.env.Retry
	}
	return &engine.Engine{
		Registry:      a.reg,
		State:         a.st,
		Clock:         a.env.Clock,
		Version:       a.version,
		CorpusVersion: techniques.Version(),
		Retry:         retry,
		Progress:      a.progress.event,
		Hook:          a.env.Hook,
	}
}

// sigmaRulesDir returns the directory of operator-supplied Sigma rules: the
// --sigma-rules flag, else $SAASHOUND_SIGMA_RULES, else a `sigma-rules`
// directory beside targets.yaml if one exists. It returns "" when none is
// configured, in which case only the bundled example rules are loaded.
func (a *app) sigmaRulesDir() string {
	if a.sigmaRules != "" {
		return a.sigmaRules
	}
	if d := a.env.Getenv("SAASHOUND_SIGMA_RULES"); d != "" {
		return d
	}
	def := filepath.Join(filepath.Dir(a.targetsPath), "sigma-rules")
	if fi, err := os.Stat(def); err == nil && fi.IsDir() {
		return def
	}
	return ""
}

// sigmaChecker builds the Sigma detection checker: the bundled example rules
// plus every rule under the operator's rules directory. A directory named
// explicitly (flag or env) that cannot be read is a refusal; a directory only
// discovered is already known to exist. Non-fatal load problems are summarised
// on stderr as one count, with the per-file detail at -v, so a large rule
// checkout cannot bury real alarms; a problem with a rule a technique actually
// references is carried in that detection's record.
func (a *app) sigmaChecker() (*sigma.Checker, error) {
	dir := a.sigmaRulesDir()
	chk, err := sigma.Load(dir)
	if err != nil {
		return nil, refused("%v", err)
	}
	rs := chk.RuleSet()
	if n := len(rs.Warnings()); n > 0 {
		a.progress.event(engine.Event{Stage: "sigma", Msg: fmt.Sprintf("%d Sigma rule(s) could not be loaded; run with -v for details", n)})
	}
	for _, w := range rs.Warnings() {
		a.progress.event(engine.Event{Level: 1, Stage: "sigma", Msg: "rule not loaded: " + w})
	}
	if dir != "" {
		a.progress.event(engine.Event{Level: 1, Stage: "sigma", Msg: fmt.Sprintf("loaded %d rules (incl. bundled examples) from %s", rs.Len(), dir)})
	}
	return chk, nil
}

// interactive reports whether typed confirmation is possible.
func (a *app) interactive() bool { return a.env.StdinTTY && a.env.StderrTTY }

// confirm prompts on stderr and reads one line from stdin.
func (a *app) confirm(prompt string) (string, error) {
	fmt.Fprint(a.env.Stderr, prompt)
	line, err := bufio.NewReader(a.env.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// interrupts returns two contexts: the first is cancelled by the first
// Ctrl-C (stop detonating, start cleanup), the second by the second Ctrl-C
// (abandon cleanup). first is what the operator is told on the first
// Ctrl-C; it must describe what that does in the calling command.
func (a *app) interrupts(ctx context.Context, first string) (detonate, cleanup context.Context, stop func()) {
	dctx, dcancel := context.WithCancel(ctx)
	cctx, ccancel := context.WithCancel(context.WithoutCancel(ctx))
	sigs := a.env.Signals
	var ch chan os.Signal
	if sigs == nil {
		ch = make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		sigs = ch
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(finished)
		n := 0
		for {
			select {
			case <-done:
				return
			case <-sigs:
				n++
				if n == 1 {
					a.progress.alarm(first)
					dcancel()
				} else if n == 2 {
					a.progress.alarm("abandoning cleanup")
					ccancel()
				}
			}
		}
	}()
	return dctx, cctx, func() {
		once.Do(func() {
			close(done)
			<-finished
			if ch != nil {
				signal.Stop(ch)
			}
			dcancel()
			ccancel()
		})
	}
}

func (a *app) sink() report.Sink {
	if a.env.StdoutTTY && !a.jsonl {
		return &report.Table{W: a.env.Stdout, Color: !a.noColor && a.env.Getenv("NO_COLOR") == ""}
	}
	return report.JSONLines{W: a.env.Stdout}
}
