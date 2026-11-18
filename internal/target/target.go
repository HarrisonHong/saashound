// Package target loads targets.yaml, the allowlist of tenants the tool may
// touch. It holds tenant identifiers and credential references, never
// credentials, so it can be committed to a detection-engineering repo.
package target

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
)

// Environment classes.
const (
	Lab        = "lab"
	Production = "production"
)

// DefaultMaxLabUsers is the active-user count above which a "lab" target is
// refused as probably mislabelled.
const DefaultMaxLabUsers = 25

// FileVersion is the targets.yaml format version.
const FileVersion = 1

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidName reports whether s is a valid target name. Names become lock file
// names, so the grammar is strict.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// File is targets.yaml.
type File struct {
	Version int                `yaml:"version"`
	Targets map[string]*Target `yaml:"targets"`
}

// Target is one allowlisted tenant.
type Target struct {
	Name string `yaml:"-"`
	// Platform is the registered provider name.
	Platform string `yaml:"platform"`
	// Tenant is the platform's tenant identifier: Okta org URL, GitHub org
	// slug, Google customer ID, ...
	Tenant string `yaml:"tenant"`
	// Principal is the identity the credential must belong to.
	Principal string `yaml:"principal"`
	// Environment is "lab" (default) or "production".
	Environment string `yaml:"environment,omitempty"`
	// TestDomain is the domain synthetic accounts are created under.
	TestDomain string `yaml:"test_domain,omitempty"`
	// Credential references where the secret lives.
	Credential secret.Ref `yaml:"credential,omitempty"`
	// MaxLabUsers overrides DefaultMaxLabUsers.
	MaxLabUsers int `yaml:"max_lab_users,omitempty"`
	// Options are provider-specific, non-secret settings.
	Options map[string]string `yaml:"options,omitempty"`
}

// ErrNotAllowlisted is returned for a target that targets.yaml does not list.
var ErrNotAllowlisted = errors.New("not allowlisted")

// Load reads targets.yaml. A missing file yields an empty allowlist.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &File{Version: FileVersion, Targets: map[string]*Target{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes targets.yaml strictly: unknown fields are errors.
func Parse(b []byte) (*File, error) {
	f := &File{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(f); err != nil {
		if errors.Is(err, io.EOF) {
			return &File{Version: FileVersion, Targets: map[string]*Target{}}, nil
		}
		return nil, fmt.Errorf("targets.yaml: %w", err)
	}
	if f.Version != FileVersion {
		return nil, fmt.Errorf("targets.yaml: version must be %d, got %d", FileVersion, f.Version)
	}
	if f.Targets == nil {
		f.Targets = map[string]*Target{}
	}
	for name, t := range f.Targets {
		if t == nil {
			return nil, fmt.Errorf("targets.yaml: target %q is empty", name)
		}
		t.Name = name
		t.applyDefaults()
		if err := t.validate(); err != nil {
			return nil, fmt.Errorf("targets.yaml: target %q: %w", name, err)
		}
	}
	return f, nil
}

func (t *Target) applyDefaults() {
	if t.Environment == "" {
		t.Environment = Lab
	}
	if t.TestDomain == "" {
		t.TestDomain = "example.com"
	}
	if t.MaxLabUsers == 0 {
		t.MaxLabUsers = DefaultMaxLabUsers
	}
}

func (t *Target) validate() error {
	switch {
	case !ValidName(t.Name):
		return fmt.Errorf("name must match %s", nameRe)
	case t.Platform == "":
		return errors.New("platform is required")
	case t.Tenant == "":
		return errors.New("tenant is required")
	case t.Principal == "":
		return errors.New("principal is required")
	case t.Environment != Lab && t.Environment != Production:
		return fmt.Errorf("environment must be %q or %q", Lab, Production)
	case t.MaxLabUsers < 0:
		return errors.New("max_lab_users must not be negative")
	case strings.ContainsAny(t.TestDomain, "/@:? \t"):
		return fmt.Errorf("test_domain %q is not a bare domain", t.TestDomain)
	}
	return t.Credential.Validate()
}

// Get returns the named target or ErrNotAllowlisted.
func (f *File) Get(name string) (*Target, error) {
	t, ok := f.Targets[name]
	if !ok {
		return nil, fmt.Errorf("target %q is %w in targets.yaml", name, ErrNotAllowlisted)
	}
	return t, nil
}

// Names returns the target names, sorted.
func (f *File) Names() []string {
	out := make([]string, 0, len(f.Targets))
	for n := range f.Targets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ErrExists is returned by Add for an identical, already declared target.
var ErrExists = errors.New("already declared")

// Add inserts t. Declaring an identical entry again returns ErrExists, so
// `init` can be re-run; a different entry under the same name is refused.
func (f *File) Add(t *Target) error {
	t.applyDefaults()
	if err := t.validate(); err != nil {
		return fmt.Errorf("target %q: %w", t.Name, err)
	}
	if prev, exists := f.Targets[t.Name]; exists {
		if prev.Fingerprint() == t.Fingerprint() && prev.TestDomain == t.TestDomain && prev.Credential == t.Credential {
			return fmt.Errorf("target %q is %w", t.Name, ErrExists)
		}
		return fmt.Errorf("target %q already exists in targets.yaml with different settings; edit or remove it first", t.Name)
	}
	f.Targets[t.Name] = t
	return nil
}

// Save writes the file atomically with mode 0600.
func (f *File) Save(path string) error {
	if err := fsutil.MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# SaaSHound targets: the allowlist of tenants this tool may touch.\n")
	buf.WriteString("# It holds tenant identifiers and credential references, never secrets.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, buf.Bytes())
}

// Fingerprint identifies this target entry for the ownership marker.
func (t *Target) Fingerprint() string {
	return marker.Fingerprint(t.Name, t.Platform, t.Tenant, t.Principal, t.Environment)
}

// MarkerValue is the ownership marker a tenant admin must place.
func (t *Target) MarkerValue() string { return marker.AuthorizationValue(t.Fingerprint()) }

// Info returns the non-secret view handed to providers.
func (t *Target) Info() provider.TargetInfo {
	opts := make(map[string]string, len(t.Options))
	for k, v := range t.Options {
		opts[k] = v
	}
	return provider.TargetInfo{
		Name:        t.Name,
		Platform:    t.Platform,
		Tenant:      t.Tenant,
		Principal:   t.Principal,
		Environment: t.Environment,
		TestDomain:  t.TestDomain,
		Options:     opts,
	}
}
