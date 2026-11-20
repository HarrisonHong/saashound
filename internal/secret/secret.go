// Package secret holds credentials in a type that cannot be printed, logged
// or serialised by accident, and resolves credential references from a
// target's configuration.
//
// Every formatting path of Value (fmt verbs, JSON, text, slog) yields
// "[redacted]". The raw bytes are reachable only through Reveal, and a policy
// test restricts which files may call it: provider transports, which turn a
// credential into a request's authentication (an Authorization header, or a
// signed OAuth client assertion and the token it buys), and nothing else.
package secret

import (
	"errors"
	"fmt"
	"log/slog"
)

// Redacted is what every formatting path of a Value prints.
const Redacted = "[redacted]"

// Value is a secret. Its zero value is empty.
type Value struct {
	// raw is unexported so the secret is invisible to encoding/json,
	// reflection-based printers and struct copies into output records.
	raw *[]byte
}

// New wraps raw as a secret. The caller should drop its own reference.
func New(raw string) Value {
	b := []byte(raw)
	return Value{raw: &b}
}

// Empty reports whether the secret has no content.
func (v Value) Empty() bool { return v.raw == nil || len(*v.raw) == 0 }

// Reveal returns the raw secret. Only provider transports may call it; see
// the package documentation and internal/policy_test.go.
func (v Value) Reveal() string {
	if v.raw == nil {
		return ""
	}
	return string(*v.raw)
}

// Wipe overwrites the secret's bytes in place. Copies made by Reveal are not
// affected; wiping is best effort, not a guarantee.
func (v Value) Wipe() {
	if v.raw == nil {
		return
	}
	for i := range *v.raw {
		(*v.raw)[i] = 0
	}
	*v.raw = (*v.raw)[:0]
}

// String implements fmt.Stringer.
func (Value) String() string { return Redacted }

// GoString implements fmt.GoStringer, covering %#v.
func (Value) GoString() string { return Redacted }

// Format implements fmt.Formatter so that every verb, including %x and %q,
// prints the redaction marker rather than the underlying bytes.
func (Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (YAML, XML, map keys).
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(Redacted) }

// ErrNotConfigured is returned when a target declares no credential.
var ErrNotConfigured = errors.New("no credential configured for this target")
