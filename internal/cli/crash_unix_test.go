//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/HarrisonHong/saashound/internal/cli"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/providers/fake"
)

// Environment variables of the crash helper process.
const (
	helperArgs  = "SAASHOUND_CRASH_HELPER_ARGS"  // CLI args, as a JSON array
	helperPoint = "SAASHOUND_CRASH_HELPER_POINT" // crash point
	helperStep  = "SAASHOUND_CRASH_HELPER_STEP"  // step to crash on
	helperRun   = "SAASHOUND_CRASH_HELPER_RUN"   // run id to use
)

// TestMain turns the test binary into a saashound process that SIGKILLs
// itself at a chosen crash point, when asked to.
func TestMain(m *testing.M) {
	if raw := os.Getenv(helperArgs); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			panic(err)
		}
		os.Exit(crashHelper(args))
	}
	os.Exit(m.Run())
}

func crashHelper(args []string) int {
	point, step, run := engine.Point(os.Getenv(helperPoint)), os.Getenv(helperStep), os.Getenv(helperRun)
	env := cli.OSEnv()
	env.Registry = provider.Default // the real, file-backed simulated tenant
	env.Stdout, env.Stderr = os.Stdout, os.Stderr
	env.NewRunID = func() (string, error) { return run, nil }
	env.Hook = func(p engine.Point, s string) {
		if p == point && s == step {
			// No deferred function, no flush, no cleanup: the kernel kills us.
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	}
	return cli.Main(context.Background(), args, env)
}

// TestKilledProcessRecovers runs `saashound apply` in a child process that
// is SIGKILLed between INTENT and RESULT (after the platform applied the
// call) or between UNDO and GONE, then proves `saashound cleanup <run>` in a
// new process finds and removes everything, verified, leaving the tenant as
// it was.
func TestKilledProcessRecovers(t *testing.T) {
	cases := []struct {
		technique, step string
		point           engine.Point
	}{
		{"fake.persistence.mfa-factor-register", "victim", engine.AfterDo},
		{"fake.persistence.mfa-factor-register", "factor", engine.AfterDo},
		{"fake.persistence.mfa-factor-register", "factor", engine.AfterIntent},
		{"fake.persistence.mfa-factor-register", "factor", engine.AfterUndo},
		{"fake.persistence.mfa-factor-register", "victim", engine.AfterUndoCall},
		{"fake.privilege-escalation.admin-role-assign", "grant", engine.AfterDo},
		{"fake.privilege-escalation.admin-role-assign", "grant", engine.AfterUndo},
		{"fake.defense-impairment.network-zone-deactivate", "deactivate", engine.AfterDo},
		{"fake.defense-impairment.network-zone-deactivate", "deactivate", engine.AfterUndo},
		{"fake.defense-impairment.network-zone-deactivate", "zone", engine.AfterUndo},
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.technique+"/"+c.step+"/"+string(c.point), func(t *testing.T) {
			dir := t.TempDir()
			base := []string{"--targets", filepath.Join(dir, "targets.yaml"), "--state-dir", filepath.Join(dir, "state")}
			main := func(args ...string) (string, int) {
				var out bytes.Buffer
				env := cli.Env{Stdout: &out, Stderr: &out, Getenv: func(string) string { return "" }, Registry: provider.Default}
				code := cli.Main(context.Background(), append(append([]string{}, base...), args...), env)
				return out.String(), code
			}
			if out, code := main("init", "lab", "--platform", "fake", "--place-marker"); code != 0 {
				t.Fatalf("init: %d %s", code, out)
			}
			store := fake.FileStore{Dir: filepath.Join(dir, "state", "providers", "fake", "tenants")}
			before, err := fake.Snapshot(store, "sim-lab")
			if err != nil {
				t.Fatal(err)
			}

			run := "c" + strings.Repeat("r", 4) + "s"
			cmd := exec.Command(exe)
			args, _ := json.Marshal(append(base, "apply", c.technique, "--target", "lab", "--yes", "-q"))
			cmd.Env = append(os.Environ(),
				helperArgs+"="+string(args),
				helperPoint+"="+string(c.point), helperStep+"="+c.step, helperRun+"="+run)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err = cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("the helper was not killed: %v\n%s", err, out.String())
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("the helper exited (%v) instead of dying by SIGKILL\n%s", err, out.String())
			}

			if st, _ := main("status"); !strings.Contains(st, "cleanup-pending") {
				t.Fatalf("status after the kill:\n%s", st)
			}
			if c.point == engine.AfterDo || c.point == engine.AfterIntent {
				sw, code := main("sweep", "--target", "lab")
				if code != 3 && c.point == engine.AfterDo {
					t.Fatalf("sweep must report what the dead process left: exit %d\n%s", code, sw)
				}
			}
			res, code := main("cleanup", run)
			if code != 0 || !strings.Contains(res, "cleanup verified for run "+run) {
				t.Fatalf("cleanup: exit %d\n%s", code, res)
			}
			if sw, code := main("sweep", "--target", "lab"); code != 0 || !strings.Contains(sw, "no "+marker.Prefix+"- objects found") {
				t.Fatalf("sweep after cleanup: exit %d\n%s", code, sw)
			}
			after, err := fake.Snapshot(store, "sim-lab")
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("tenant changed:\nbefore %s\nafter  %s", before, after)
			}
			if st, _ := main("status"); !strings.Contains(st, "cleaned") {
				t.Fatalf("status after cleanup:\n%s", st)
			}
		})
	}
}
