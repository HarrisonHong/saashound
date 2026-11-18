// Package marker defines how SaaSHound marks everything it does so defenders,
// the collector and the sweeper can tell the tool's own activity apart from
// everyone else's: the run ID, the reserved object-name prefix, the
// User-Agent string and the tenant ownership marker.
//
// Prefix is the single place the reserved prefix is defined. Every object
// name, User-Agent and ownership marker is derived from it.
package marker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// Prefix is the reserved run-marker prefix. Every object the tool creates is
// named Prefix-<run>-<step>, every request carries Prefix/<version> in its
// User-Agent, and the human-placed ownership marker is Prefix-authorized:...
const Prefix = "saashound"

// runIDAlphabet omits characters that are easy to misread (0/o, 1/l/i).
const runIDAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// RunIDLength is the length of a run ID.
const RunIDLength = 6

var (
	runIDRe  = regexp.MustCompile(`^[` + runIDAlphabet + `]{6}$`)
	stepIDRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	// objectNameRe is the strict grammar of a run-created object name. The
	// sweeper only ever considers names that match it exactly.
	objectNameRe = regexp.MustCompile(`^` + Prefix + `-([` + runIDAlphabet + `]{6})-([a-z][a-z0-9]*(?:-[a-z0-9]+)*)$`)
	uaRe         = regexp.MustCompile(`(?:^|\s)` + Prefix + `/(\S+) \(run=([` + runIDAlphabet + `]{6}); phase=([a-z]+)\)`)
)

// MaxStepIDLength bounds step IDs so derived object names stay short enough
// for every platform's name limits.
const MaxStepIDLength = 24

// NewRunID returns a fresh random run ID.
func NewRunID() (string, error) {
	var b [RunIDLength]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	out := make([]byte, RunIDLength)
	for i, v := range b {
		out[i] = runIDAlphabet[int(v)%len(runIDAlphabet)]
	}
	return string(out), nil
}

// ValidRunID reports whether s is a well-formed run ID. Run IDs name
// directories, so anything else is rejected before it touches the filesystem.
func ValidRunID(s string) bool { return runIDRe.MatchString(s) }

// ValidStepID reports whether s is a well-formed technique step ID.
func ValidStepID(s string) bool {
	return len(s) <= MaxStepIDLength && stepIDRe.MatchString(s)
}

// ObjectName is the deterministic name of the object a step creates. The
// cleaner uses it to find an object whose ID was never journalled, by exact
// match only.
func ObjectName(run, step string) string {
	return Prefix + "-" + run + "-" + step
}

// RunPrefix is the name prefix shared by every object of one run.
func RunPrefix(run string) string { return Prefix + "-" + run }

// ParseObjectName splits a run-created object name into its run and step.
// It returns ok=false for any name that does not match the grammar exactly,
// including the ownership marker's own name.
func ParseObjectName(name string) (run, step string, ok bool) {
	m := objectNameRe.FindStringSubmatch(name)
	if m == nil || len(m[2]) > MaxStepIDLength {
		return "", "", false
	}
	return m[1], m[2], true
}

// Phase says which part of a run a request belongs to. It is carried in the
// User-Agent so cleanup traffic can be told apart from detonation traffic.
type Phase string

// Phases of a run.
const (
	PhasePreflight Phase = "preflight" // read-only guardrail and plan calls
	PhaseDetonate  Phase = "detonate"
	PhaseCleanup   Phase = "cleanup"
	PhaseCollect   Phase = "collect" // read-only audit-log reads after cleanup
	PhaseSweep     Phase = "sweep"
)

// Valid reports whether p is a known phase.
func (p Phase) Valid() bool {
	switch p {
	case PhasePreflight, PhaseDetonate, PhaseCleanup, PhaseCollect, PhaseSweep:
		return true
	}
	return false
}

// UserAgent returns the User-Agent every request of a run carries, for
// example "saashound/0.1.0 (run=k3v9q2; phase=detonate)". The tool never
// spoofs or omits it.
func UserAgent(version, run string, phase Phase) string {
	if run == "" {
		run = "------"
	}
	return fmt.Sprintf("%s/%s (run=%s; phase=%s)", Prefix, version, run, phase)
}

// ParsedUA is the run marker recovered from a recorded User-Agent.
type ParsedUA struct {
	Version string
	Run     string
	Phase   Phase
}

// ParseUserAgent extracts the run marker from a User-Agent string as a
// platform recorded it. It matches the exact format only.
func ParseUserAgent(ua string) (ParsedUA, bool) {
	m := uaRe.FindStringSubmatch(ua)
	if m == nil {
		return ParsedUA{}, false
	}
	p := Phase(m[3])
	if !p.Valid() {
		return ParsedUA{}, false
	}
	return ParsedUA{Version: m[1], Run: m[2], Phase: p}, true
}

// AuthorizationName is the name of the object a human admin creates in the
// tenant to opt it in, for example an Okta group.
const AuthorizationName = Prefix + "-authorized"

// AuthorizationValue is the ownership-marker value for a target fingerprint:
// "saashound-authorized:<fingerprint>".
func AuthorizationValue(fingerprint string) string {
	return AuthorizationName + ":" + fingerprint
}

// Fingerprint hashes the identifying fields of a target entry. Changing any of
// them (for example relabelling a lab target as production) changes the
// fingerprint, so the tenant admin has to opt in again.
func Fingerprint(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		// Length-prefix each field so ("ab","c") and ("a","bc") differ.
		fmt.Fprintf(h, "%d:%s;", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
