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
	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/engine"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// TestOktaKilledProcessRecovers runs `saashound apply` against a mock Okta org
// in a child process that is SIGKILLed between a step's INTENT and RESULT
// (after the org applied the call) or between UNDO and GONE, then proves
// `saashound cleanup <run>` in the parent finds and removes everything,
// verified, leaving the org exactly as it was. The mock org lives in the
// parent, so it survives the child's death the way a real org would, and the
// child reaches it over real TCP.
func TestOktaKilledProcessRecovers(t *testing.T) {
	cases := []struct {
		technique, step string
		point           engine.Point
	}{
		{"okta.persistence.mfa-factor-register", "victim", engine.AfterDo},
		{"okta.persistence.mfa-factor-register", "factor", engine.AfterDo},
		{"okta.persistence.mfa-factor-register", "factor", engine.AfterIntent},
		{"okta.persistence.mfa-factor-register", "factor", engine.AfterUndo},
		{"okta.persistence.mfa-factor-register", "victim", engine.AfterUndoCall},
		{"okta.persistence.mfa-factor-reset", "reset", engine.AfterDo},
		{"okta.privilege-escalation.admin-role-assign", "grant", engine.AfterDo},
		{"okta.privilege-escalation.admin-role-assign", "grant", engine.AfterUndo},
		{"okta.persistence.service-app-api-access", "grant", engine.AfterDo},
		{"okta.privilege-escalation.custom-admin-role", "bind", engine.AfterDo},
		{"okta.privilege-escalation.custom-admin-role", "rset", engine.AfterDo},
		{"okta.defense-impairment.policy-rule-weaken", "weaken", engine.AfterDo},
		{"okta.defense-impairment.network-zone-deactivate", "deactivate", engine.AfterDo},
		{"okta.defense-impairment.network-zone-deactivate", "deactivate", engine.AfterUndo},
		{"okta.defense-impairment.network-zone-deactivate", "zone", engine.AfterUndo},
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.technique+"/"+c.step+"/"+string(c.point), func(t *testing.T) {
			dir := t.TempDir()
			srv := mockokta.New(mockokta.WithToken(oktaToken), mockokta.WithPrincipal(oktaPrincipal))
			defer srv.Close()
			targetsPath := filepath.Join(dir, "targets.yaml")
			stateDir := filepath.Join(dir, "state")
			base := []string{"--targets", targetsPath, "--state-dir", stateDir}

			parent := func(args ...string) (string, int) {
				var out bytes.Buffer
				env := cli.Env{Stdout: &out, Stderr: &out, Clock: clock.Real{}, Registry: provider.Default,
					Getenv: func(k string) string {
						if k == "OKTA_TOKEN" {
							return oktaToken
						}
						return ""
					}}
				code := cli.Main(context.Background(), append(append([]string{}, base...), args...), env)
				return out.String(), code
			}

			if out, code := parent("init", "okta", "--platform", "okta", "--tenant", srv.URL(),
				"--principal", oktaPrincipal, "--test-domain", "lab.example.com", "--credential-env", "OKTA_TOKEN"); code != 0 {
				t.Fatalf("init: %d %s", code, out)
			}
			tgt := &target.Target{Name: "okta", Platform: "okta", Tenant: srv.URL(), Principal: oktaPrincipal, Environment: "lab"}
			srv.PlaceMarker(marker.AuthorizationName, tgt.MarkerValue())
			before := srv.Snapshot()

			run := "k" + strings.Repeat("r", 4) + "s"
			cmd := exec.Command(exe)
			args, _ := json.Marshal(append(base, "apply", c.technique, "--target", "okta", "--yes", "-q"))
			cmd.Env = append(os.Environ(),
				helperArgs+"="+string(args),
				helperPoint+"="+string(c.point), helperStep+"="+c.step, helperRun+"="+run,
				"OKTA_TOKEN="+oktaToken)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("the helper was not killed: %v\n%s", err, out.String())
			}
			if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("the helper exited (%v) instead of dying by SIGKILL\n%s", err, out.String())
			}

			if st, _ := parent("status"); !strings.Contains(st, "cleanup-pending") {
				t.Fatalf("status after the kill:\n%s", st)
			}
			res, code := parent("cleanup", run)
			if code != 0 || !strings.Contains(res, "cleanup verified for run "+run) {
				t.Fatalf("cleanup: exit %d\n%s", code, res)
			}
			if sw, code := parent("sweep", "--target", "okta"); code != 0 || !strings.Contains(sw, "no "+marker.Prefix+"- objects found") {
				t.Fatalf("sweep after cleanup: exit %d\n%s", code, sw)
			}
			if after := srv.Snapshot(); string(after) != string(before) {
				t.Fatalf("org changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}
