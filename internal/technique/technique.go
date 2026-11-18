// Package technique defines the technique file format, loads technique YAML
// strictly, and validates it against the registered op vocabulary.
//
// A technique is data. It can only name registered ops with typed
// parameters, substitute values with a strict {{scope.field}} syntax that has
// no functions, conditionals or loops, and state what the platform must log.
// It has no host or URL field anywhere, so a contributed file cannot send a
// request, or a credential, to any host but the tenant's own API.
package technique

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxFileSize bounds a technique file.
const MaxFileSize = 64 << 10

// Technique is one technique file.
type Technique struct {
	// ID is "<platform>.<tactic>.<verb-object>", permanent once released.
	ID          string      `yaml:"id" json:"id"`
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Author      []string    `yaml:"author" json:"author"`
	Platform    string      `yaml:"platform" json:"platform"`
	Attack      []string    `yaml:"attack,omitempty" json:"attack,omitempty"`
	Tradecraft  []Reference `yaml:"tradecraft,omitempty" json:"tradecraft,omitempty"`
	// Evidence is how well attested the technique is: incident, guidance or
	// rules-only.
	Evidence   string        `yaml:"evidence" json:"evidence"`
	Safety     Safety        `yaml:"safety" json:"safety"`
	Steps      []Step        `yaml:"steps" json:"steps"`
	Expect     []Expectation `yaml:"expect" json:"expect"`
	Cleanup    Cleanup       `yaml:"cleanup" json:"cleanup"`
	Detections []Detection   `yaml:"detections,omitempty" json:"detections,omitempty"`
	Fixtures   []string      `yaml:"fixtures,omitempty" json:"fixtures,omitempty"`

	// Source is where the technique was loaded from (not part of the file).
	Source string `yaml:"-" json:"-"`
	// Verified is true for the corpus embedded in the binary.
	Verified bool `yaml:"-" json:"-"`
	// Digest is the SHA-256 of the file's bytes.
	Digest string `yaml:"-" json:"-"`
}

// Reference is a dated tradecraft write-up. Its URL is documentation; the
// tool never fetches it.
type Reference struct {
	Title string `yaml:"title" json:"title"`
	URL   string `yaml:"url" json:"url"`
	Date  string `yaml:"date" json:"date"`
}

// Safety flags. production_safe means the technique touches only objects the
// run creates, makes no change a real user would notice, and leaves no
// secret that survives the run. modifies_existing can never be
// production-safe.
type Safety struct {
	ProductionSafe    bool   `yaml:"production_safe" json:"production_safe"`
	ModifiesExisting  bool   `yaml:"modifies_existing" json:"modifies_existing"`
	ThirdPartyContact string `yaml:"third_party_contact" json:"third_party_contact"`
}

// Step invokes one registered op.
type Step struct {
	ID   string            `yaml:"id" json:"id"`
	Op   string            `yaml:"op" json:"op"`
	With map[string]string `yaml:"with,omitempty" json:"with,omitempty"`
}

// Expectation is an audit event that must be observed after a step.
type Expectation struct {
	// After is the step whose action should produce the event; latency is
	// measured from that step's completion.
	After string `yaml:"after" json:"after"`
	// Source is the provider's audit source name.
	Source string `yaml:"source" json:"source"`
	// Match maps event field paths ("eventType", "target[].id") to values.
	// Every entry must match; "[]" matches any element of an array.
	Match map[string]string `yaml:"match" json:"match"`
	// Deadline overrides the audit source's default deadline.
	Deadline Duration `yaml:"deadline,omitempty" json:"deadline,omitempty"`
}

// Cleanup declares how the technique is undone. Order must list every step,
// in reverse: the cleaner undoes the last step first.
type Cleanup struct {
	Order []string `yaml:"order" json:"order"`
}

// Detection maps the technique to a public detection rule. A null rule is a
// first-class statement: no public rule of that kind covers the technique.
type Detection struct {
	Sigma   *string `yaml:"sigma,omitempty" json:"sigma,omitempty"`
	Elastic *string `yaml:"elastic,omitempty" json:"elastic,omitempty"`
	// set records which key was present, so "sigma: null" is distinguishable
	// from an empty entry.
	set string
}

// Kind returns "sigma" or "elastic".
func (d Detection) Kind() string { return d.set }

// Rule returns the referenced rule ID, or "" for a null mapping.
func (d Detection) Rule() string {
	switch {
	case d.Sigma != nil:
		return *d.Sigma
	case d.Elastic != nil:
		return *d.Elastic
	}
	return ""
}

// UnmarshalYAML records which key was present, including explicit nulls.
func (d *Detection) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode || len(n.Content) != 2 {
		return fmt.Errorf("line %d: a detection is exactly one of sigma: <id|null> or elastic: <id|null>", n.Line)
	}
	key, val := n.Content[0].Value, n.Content[1]
	var v *string
	if !(val.Tag == "!!null") {
		if val.Kind != yaml.ScalarNode {
			return fmt.Errorf("line %d: %s must be a rule ID or null", val.Line, key)
		}
		s := val.Value
		v = &s
	}
	switch key {
	case "sigma":
		d.Sigma = v
	case "elastic":
		d.Elastic = v
	default:
		return fmt.Errorf("line %d: unknown detection kind %q (want sigma or elastic)", n.Line, key)
	}
	d.set = key
	return nil
}

// Duration is a time.Duration written as "30s" or "5m".
type Duration time.Duration

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string like 30s or 5m", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalText writes the duration as a string.
func (d Duration) MarshalText() ([]byte, error) { return []byte(time.Duration(d).String()), nil }

// Parse decodes one technique file strictly: unknown fields, duplicate keys
// and multiple documents are errors.
func Parse(source string, b []byte) (*Technique, error) {
	if len(b) > MaxFileSize {
		return nil, fmt.Errorf("%s: file is larger than %d bytes", source, MaxFileSize)
	}
	t := &Technique{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(t); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file", source)
		}
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: a technique file must hold exactly one YAML document", source)
	}
	sum := sha256.Sum256(b)
	t.Source = source
	t.Digest = hex.EncodeToString(sum[:])
	return t, nil
}

// Step returns the step with the given ID.
func (t *Technique) Step(id string) (Step, int, bool) {
	for i, s := range t.Steps {
		if s.ID == id {
			return s, i, true
		}
	}
	return Step{}, -1, false
}
