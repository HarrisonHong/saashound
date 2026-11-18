package secret

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Ref is a reference to a credential, as written in targets.yaml. It names
// where the secret lives and never holds the secret itself, so targets.yaml
// can be committed. Exactly one field is set.
type Ref struct {
	// Env names an environment variable.
	Env string `yaml:"env,omitempty" json:"env,omitempty"`
	// File is a path to a key file. It must be mode 0600 (as ssh requires).
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Keychain is "service/account" in the OS keychain.
	Keychain string `yaml:"keychain,omitempty" json:"keychain,omitempty"`
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// IsZero reports whether no credential is referenced.
func (r Ref) IsZero() bool { return r == Ref{} }

// Validate checks the reference is well formed without resolving it.
func (r Ref) Validate() error {
	n := 0
	for _, s := range []string{r.Env, r.File, r.Keychain} {
		if s != "" {
			n++
		}
	}
	switch {
	case n == 0:
		return nil
	case n > 1:
		return errors.New("credential: set exactly one of env, file, keychain")
	case r.Env != "" && !envNameRe.MatchString(r.Env):
		return fmt.Errorf("credential: %q is not a valid environment variable name", r.Env)
	}
	return nil
}

// String describes where the credential comes from, never its value.
func (r Ref) String() string {
	switch {
	case r.Env != "":
		return "env:" + r.Env
	case r.File != "":
		return "file:" + r.File
	case r.Keychain != "":
		return "keychain:" + r.Keychain
	}
	return "none"
}

// Source resolves credential references. Providers receive a Source rather
// than a secret so that a credential is read only when, and only if, it is
// needed.
type Source interface {
	Resolve(ctx context.Context, ref Ref) (Value, error)
}

// DefaultSource resolves env and file references. Keychain references are
// reported as unsupported in this build.
type DefaultSource struct {
	// LookupEnv defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

// Resolve implements Source.
func (s DefaultSource) Resolve(_ context.Context, ref Ref) (Value, error) {
	if err := ref.Validate(); err != nil {
		return Value{}, err
	}
	switch {
	case ref.IsZero():
		return Value{}, ErrNotConfigured
	case ref.Env != "":
		lookup := s.LookupEnv
		if lookup == nil {
			lookup = os.LookupEnv
		}
		v, ok := lookup(ref.Env)
		if !ok || v == "" {
			return Value{}, fmt.Errorf("credential: environment variable %s is not set", ref.Env)
		}
		return New(strings.TrimSpace(v)), nil
	case ref.File != "":
		return readKeyFile(ref.File)
	default:
		return Value{}, fmt.Errorf("credential: keychain references are not supported in this build (%s)", ref)
	}
}

func readKeyFile(path string) (Value, error) {
	path = filepath.Clean(path)
	fi, err := os.Stat(path)
	if err != nil {
		return Value{}, fmt.Errorf("credential: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Value{}, fmt.Errorf("credential: %s is not a regular file", path)
	}
	if err := checkKeyFileMode(fi.Mode()); err != nil {
		return Value{}, fmt.Errorf("credential: %s: %w", path, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Value{}, fmt.Errorf("credential: %w", err)
	}
	v := New(strings.TrimSpace(string(b)))
	for i := range b {
		b[i] = 0
	}
	return v, nil
}

func checkKeyFileMode(m fs.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil // POSIX permission bits are not meaningful on Windows.
	}
	if m.Perm()&0o077 != 0 {
		return fmt.Errorf("permissions %04o are too open; it must be 0600", m.Perm())
	}
	return nil
}
