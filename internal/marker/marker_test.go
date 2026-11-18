package marker

import (
	"strings"
	"testing"
)

func TestRunID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := NewRunID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidRunID(id) {
			t.Fatalf("NewRunID() = %q, not valid", id)
		}
		seen[id] = true
	}
	if len(seen) < 195 {
		t.Fatalf("run ids collide too often: %d unique of 200", len(seen))
	}
	for _, bad := range []string{"", "abc", "ABCDEF", "abcdeo", "../../", "abcdefg", "abc/ef"} {
		if ValidRunID(bad) {
			t.Errorf("ValidRunID(%q) = true", bad)
		}
	}
}

func TestObjectNames(t *testing.T) {
	name := ObjectName("k3v9q2", "victim")
	if name != Prefix+"-k3v9q2-victim" {
		t.Fatalf("ObjectName = %q", name)
	}
	run, step, ok := ParseObjectName(name)
	if !ok || run != "k3v9q2" || step != "victim" {
		t.Fatalf("ParseObjectName(%q) = %q %q %v", name, run, step, ok)
	}
	for _, bad := range []string{
		AuthorizationName,               // the ownership marker must never parse as a run object
		Prefix + "-k3v9q2",              // no step
		Prefix + "-k3v9q2-",             // empty step
		Prefix + "-K3V9Q2-victim",       // upper case
		"x" + Prefix + "-k3v9q2-victim", // prefix not at start
		Prefix + "-k3v9q2-victim x",     // trailing junk
		Prefix + "-k3v9q2-" + strings.Repeat("a", MaxStepIDLength+1),
	} {
		if _, _, ok := ParseObjectName(bad); ok {
			t.Errorf("ParseObjectName(%q) accepted", bad)
		}
	}
}

func TestUserAgentRoundTrip(t *testing.T) {
	ua := UserAgent("0.1.0", "k3v9q2", PhaseCleanup)
	if ua != "saashound/0.1.0 (run=k3v9q2; phase=cleanup)" {
		t.Fatalf("UserAgent = %q", ua)
	}
	got, ok := ParseUserAgent(ua)
	if !ok || got.Run != "k3v9q2" || got.Phase != PhaseCleanup || got.Version != "0.1.0" {
		t.Fatalf("ParseUserAgent = %+v %v", got, ok)
	}
	// Platforms may prepend or append their own text.
	if got, ok := ParseUserAgent("okta-proxy " + ua + " extra"); !ok || got.Run != "k3v9q2" {
		t.Fatalf("embedded UA not parsed: %+v %v", got, ok)
	}
	for _, p := range []Phase{PhasePreflight, PhaseDetonate, PhaseCleanup, PhaseCollect, PhaseSweep} {
		got, ok := ParseUserAgent(UserAgent("0.1.0", "k3v9q2", p))
		if !p.Valid() || !ok || got.Phase != p {
			t.Errorf("phase %q does not round-trip: %+v %v", p, got, ok)
		}
	}
	if c := UserAgent("0.1.0", "k3v9q2", PhaseCollect); c != "saashound/0.1.0 (run=k3v9q2; phase=collect)" {
		t.Errorf("collect UserAgent = %q", c)
	}
	for _, bad := range []string{
		"Mozilla/5.0",
		"saashound/0.1.0 (run=k3v9q2; phase=exfiltrate)",
		"saashound/0.1.0 (run=K3V9Q2; phase=detonate)",
		"notsaashound/0.1.0(run=k3v9q2; phase=detonate)",
		UserAgent("0.1.0", "", PhasePreflight), // no run
	} {
		if p, ok := ParseUserAgent(bad); ok {
			t.Errorf("ParseUserAgent(%q) = %+v; want no match", bad, p)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a := Fingerprint("lab", "okta", "org", "app", "lab")
	if len(a) != 12 {
		t.Fatalf("fingerprint %q", a)
	}
	if a != Fingerprint("lab", "okta", "org", "app", "lab") {
		t.Fatal("fingerprint not deterministic")
	}
	if a == Fingerprint("lab", "okta", "org", "app", "production") {
		t.Fatal("relabelling a target must change its fingerprint")
	}
	if Fingerprint("ab", "c") == Fingerprint("a", "bc") {
		t.Fatal("field boundaries must matter")
	}
	if v := AuthorizationValue(a); v != "saashound-authorized:"+a {
		t.Fatalf("AuthorizationValue = %q", v)
	}
}
