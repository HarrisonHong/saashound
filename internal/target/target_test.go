package target

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/HarrisonHong/saashound/internal/secret"
)

func TestParse(t *testing.T) {
	f, err := Parse([]byte(`version: 1
targets:
  okta-lab:
    platform: okta
    tenant: https://integrator-1.okta.com
    principal: 0oa9x2
    credential: {env: SAASHOUND_OKTA_KEY}
`))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := f.Get("okta-lab")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Environment != Lab || tg.TestDomain != "example.com" || tg.MaxLabUsers != DefaultMaxLabUsers || tg.Name != "okta-lab" {
		t.Fatalf("defaults not applied: %+v", tg)
	}
	if _, err := f.Get("prod"); !errors.Is(err, ErrNotAllowlisted) {
		t.Fatalf("Get(unknown) = %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field (a pasted token)": "version: 1\ntargets:\n  a: {platform: fake, tenant: t, principal: p, token: abc}\n",
		"bad version":                    "version: 2\ntargets: {}\n",
		"no tenant":                      "version: 1\ntargets:\n  a: {platform: fake, principal: p}\n",
		"no principal":                   "version: 1\ntargets:\n  a: {platform: fake, tenant: t}\n",
		"bad environment":                "version: 1\ntargets:\n  a: {platform: fake, tenant: t, principal: p, environment: staging}\n",
		"bad name":                       "version: 1\ntargets:\n  ../x: {platform: fake, tenant: t, principal: p}\n",
		"two credential sources":         "version: 1\ntargets:\n  a: {platform: fake, tenant: t, principal: p, credential: {env: A, file: /k}}\n",
		"test domain with a path":        "version: 1\ntargets:\n  a: {platform: fake, tenant: t, principal: p, test_domain: evil.com/x}\n",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSaveAddAndFingerprint(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg", "targets.yaml")
	f, err := Load(p)
	if err != nil || len(f.Targets) != 0 {
		t.Fatalf("a missing file is an empty allowlist: %v", err)
	}
	tg := &Target{Name: "lab", Platform: "fake", Tenant: "sim-lab", Principal: "op", Credential: secret.Ref{Env: "TOK"}}
	if err := f.Add(tg); err != nil {
		t.Fatal(err)
	}
	again := &Target{Name: "lab", Platform: "fake", Tenant: "sim-lab", Principal: "op", Credential: secret.Ref{Env: "TOK"}}
	if err := f.Add(again); !errors.Is(err, ErrExists) {
		t.Fatalf("identical re-add = %v; want ErrExists", err)
	}
	if err := f.Add(&Target{Name: "lab", Platform: "fake", Tenant: "other", Principal: "op"}); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("conflicting re-add = %v", err)
	}
	if err := f.Save(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "env: TOK") || !strings.Contains(string(b), "never secrets") {
		t.Fatalf("saved:\n%s", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
	g, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ := g.Get("lab")
	if loaded.Fingerprint() != tg.Fingerprint() || !strings.HasPrefix(loaded.MarkerValue(), "saashound-authorized:") {
		t.Fatalf("fingerprint changed across save: %s vs %s", loaded.Fingerprint(), tg.Fingerprint())
	}
	prod := *loaded
	prod.Environment = Production
	if prod.Fingerprint() == loaded.Fingerprint() {
		t.Fatal("relabelling must change the fingerprint")
	}
}
