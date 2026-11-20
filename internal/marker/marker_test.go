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

func TestFindObjectNames(t *testing.T) {
	cases := map[string][]string{
		Prefix + "-k3v9q2-victim":                                   {Prefix + "-k3v9q2-victim"},
		Prefix + "-k3v9q2-victim@lab.example.com":                   {Prefix + "-k3v9q2-victim"},
		"acme-labs/" + Prefix + "-k3v9q2-repo":                      {Prefix + "-k3v9q2-repo"},
		"https://" + Prefix + "-k3v9q2-hook.invalid/x":              {Prefix + "-k3v9q2-hook"},
		"Victim (" + Prefix + "-k3v9q2-a), " + Prefix + "-p7m2xw-b": {Prefix + "-k3v9q2-a", Prefix + "-p7m2xw-b"},
		Prefix + "-k3v9q2-a/" + Prefix + "-p7m2xw-b":                {Prefix + "-k3v9q2-a", Prefix + "-p7m2xw-b"},
		// Not whole names, or not names at all.
		"":                              nil,
		"Victim (k3v9q2)":               nil,
		AuthorizationName:               nil,
		Prefix + "-k3v9q2":              nil,
		Prefix + "-k3v9q2-":             nil,
		Prefix + "-K3V9Q2-victim":       nil,
		"x" + Prefix + "-k3v9q2-victim": nil,
		"X" + Prefix + "-k3v9q2-victim": nil,
		"_" + Prefix + "-k3v9q2-victim": nil,
		Prefix + "-k3v9q2-victim-":      nil,
		Prefix + "-k3v9q2-victimX":      nil,
		Prefix + "-k3v9q2-victim_old":   nil,
		Prefix + "-k3v9q2x-victim":      nil,
		Prefix + "-k3v9q-victim":        nil,
		Prefix + "-k3v9q2-" + strings.Repeat("a", MaxStepIDLength+1): nil,
	}
	for in, want := range cases {
		got := FindObjectNames(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("FindObjectNames(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInspectUserAgent(t *testing.T) {
	full := UserAgent("0.1.0", "k3v9q2", PhaseDetonate)
	cases := []struct {
		ua   string
		want RecordedUA
		run  string
	}{
		{full, UAMarker, "k3v9q2"},
		{"proxy/1 " + full, UAMarker, "k3v9q2"},
		{"", UAAbsent, ""},
		{"  \t", UAAbsent, ""},
		{full[:len(full)-1], UADamaged, "k3v9q2"},                 // lost the closing parenthesis
		{"saashound/0.1.0 (run=k3v9q2; pha", UADamaged, "k3v9q2"}, // truncated in the phase
		{"saashound/0.1.0 (run=k3v9q2", UADamaged, "k3v9q2"},      // truncated right after the run
		{"saashound/0.1.0 (run=k3v9", UADamaged, ""},              // the run ID itself is cut
		{"saashound/0.1.0 (ru", UADamaged, ""},
		{"saashound/", UADamaged, ""},
		{"saashound/0.1.0 (run=k3v9q2; phase=exfiltrate)", UADamaged, "k3v9q2"},
		{"Mozilla/5.0 (X11; Linux x86_64)", UAForeign, ""},
		{"notsaashound/0.1.0 (run=k3v9q2; phase=detonate)", UAForeign, ""},
		{"saashound", UAForeign, ""}, // no product token
		{"curl/8.4.0 (run=k3v9q2)", UAForeign, ""},
	}
	for _, c := range cases {
		p, got := InspectUserAgent(c.ua)
		if got != c.want || p.Run != c.run {
			t.Errorf("InspectUserAgent(%q) = %+v, %d; want kind %d run %q", c.ua, p, got, c.want, c.run)
		}
		if got != UAMarker && p.Phase != "" {
			t.Errorf("InspectUserAgent(%q) recovered phase %q from an incomplete marker", c.ua, p.Phase)
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
