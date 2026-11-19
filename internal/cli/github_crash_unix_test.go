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
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/internal/target"
	"github.com/HarrisonHong/saashound/providers/github"
	"github.com/HarrisonHong/saashound/providers/github/mockgithub"
)

// TestGithubKilledProcessRecovers runs `saashound apply` against a mock GitHub
// org in a child process that is SIGKILLed between a step's INTENT and RESULT
// (after the org applied the call) or between UNDO and GONE, then proves
// `saashound cleanup <run>` in the parent finds and removes everything,
// verified, leaving the org exactly as it was. The mock org lives in the
// parent, so it survives the child's death the way a real org would, and the
// child reaches it over real TCP.
func TestGithubKilledProcessRecovers(t *testing.T) {
	cases := []struct {
		technique, step string
		point           engine.Point
	}{
		{"github.persistence.deploy-key-add", "repo", engine.AfterDo},
		{"github.persistence.deploy-key-add", "key", engine.AfterDo},
		{"github.persistence.deploy-key-add", "key", engine.AfterIntent},
		{"github.persistence.deploy-key-add", "key", engine.AfterUndo},
		{"github.persistence.deploy-key-add", "repo", engine.AfterUndoCall},
		{"github.persistence.repo-webhook-create", "hook", engine.AfterDo},
		{"github.persistence.outside-collaborator-add", "collab", engine.AfterDo},
		{"github.privilege-escalation.org-owner-promote", "promote", engine.AfterDo},
		{"github.privilege-escalation.org-owner-promote", "promote", engine.AfterUndo},
		{"github.defense-impairment.secret-scanning-disable", "disable", engine.AfterDo},
		{"github.defense-impairment.branch-protection-remove", "remove", engine.AfterDo},
		{"github.defense-impairment.branch-protection-remove", "protect", engine.AfterDo},
		{"github.defense-impairment.branch-protection-remove", "remove", engine.AfterUndo},
		{"github.exfiltration.repo-visibility-public", "publicize", engine.AfterDo},
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.technique+"/"+c.step+"/"+string(c.point), func(t *testing.T) {
			dir := t.TempDir()
			srv := mockgithub.New(mockgithub.WithToken(ghToken), mockgithub.WithPrincipal(ghPrincipal),
				mockgithub.WithOrg(ghOrg), mockgithub.WithMember(ghSecond))
			defer srv.Close()
			targetsPath := filepath.Join(dir, "targets.yaml")
			stateDir := filepath.Join(dir, "state")
			base := []string{"--targets", targetsPath, "--state-dir", stateDir}

			tgt := &target.Target{
				Name: "github", Platform: github.Name, Tenant: ghOrg, Principal: ghPrincipal, Environment: "lab",
				TestDomain: "lab.example.com", Credential: secret.Ref{Env: "GITHUB_TOKEN"},
				Options: map[string]string{"api_url": srv.URL(), "second_account": ghSecond},
			}
			f := &target.File{Version: target.FileVersion, Targets: map[string]*target.Target{}}
			if err := f.Add(tgt); err != nil {
				t.Fatal(err)
			}
			if err := f.Save(targetsPath); err != nil {
				t.Fatal(err)
			}
			srv.PlaceMarker(github.MarkerRepo, github.MarkerFile, tgt.MarkerValue())
			before := srv.Snapshot()

			parent := func(args ...string) (string, int) {
				var out bytes.Buffer
				env := cli.Env{Stdout: &out, Stderr: &out, Clock: clock.Real{}, Registry: provider.Default,
					Getenv: func(k string) string {
						if k == "GITHUB_TOKEN" {
							return ghToken
						}
						return ""
					}}
				code := cli.Main(context.Background(), append(append([]string{}, base...), args...), env)
				return out.String(), code
			}

			run := "g" + strings.Repeat("r", 4) + "s"
			cmd := exec.Command(exe)
			args, _ := json.Marshal(append(base, "apply", c.technique, "--target", "github", "--yes", "-q"))
			cmd.Env = append(os.Environ(),
				helperArgs+"="+string(args),
				helperPoint+"="+string(c.point), helperStep+"="+c.step, helperRun+"="+run,
				"GITHUB_TOKEN="+ghToken)
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
			if sw, code := parent("sweep", "--target", "github"); code != 0 || !strings.Contains(sw, "no "+marker.Prefix+"- objects found") {
				t.Fatalf("sweep after cleanup: exit %d\n%s", code, sw)
			}
			if after := srv.Snapshot(); string(after) != string(before) {
				t.Fatalf("org changed:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}
