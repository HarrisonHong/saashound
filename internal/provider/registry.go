package provider

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	providerNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	opNameRe       = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	resourceRe     = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$`)
	identRe        = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	sourceNameRe   = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$`)
)

// Registry holds providers and their ops.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	ops       map[string]*Entry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]Provider{}, ops: map[string]*Entry{}}
}

// Default is the registry the binary uses. Providers add themselves to it
// from init() through Register.
var Default = NewRegistry()

// Register adds p to the default registry. It panics if p or any of its ops
// is invalid, so a provider with an irreversible op fails every build's tests
// and every start of the binary, loudly.
func Register(p Provider) {
	if err := Default.Register(p); err != nil {
		panic("saashound: " + err.Error())
	}
}

// Register validates p and every op it declares, then adds them. Nothing is
// added if anything is invalid.
func (r *Registry) Register(p Provider) error {
	if p == nil {
		return errors.New("register provider: nil provider")
	}
	name := p.Name()
	if !providerNameRe.MatchString(name) {
		return fmt.Errorf("register provider %q: name must match %s", name, providerNameRe)
	}
	if err := validateAudit(name, p.Audit()); err != nil {
		return fmt.Errorf("register provider %q: %w", name, err)
	}
	ops := p.Ops()
	if len(ops) == 0 {
		return fmt.Errorf("register provider %q: no ops", name)
	}
	entries := make(map[string]*Entry, len(ops))
	var errs []error
	for _, op := range ops {
		e, err := newEntry(name, op)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := entries[e.Spec.Name]; dup {
			errs = append(errs, fmt.Errorf("op %s: registered twice", e.Spec.Name))
			continue
		}
		entries[e.Spec.Name] = e
	}
	if err := validateRefs(entries); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("register provider %q: %w", name, errors.Join(errs...))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.providers[name]; dup {
		return fmt.Errorf("register provider %q: already registered", name)
	}
	for n := range entries {
		if _, dup := r.ops[n]; dup {
			return fmt.Errorf("register provider %q: op %s already registered", name, n)
		}
	}
	r.providers[name] = p
	for n, e := range entries {
		r.ops[n] = e
	}
	return nil
}

// newEntry checks one op. This is where "every op has an inverse and a
// proof" is enforced.
func newEntry(provider string, op Op) (*Entry, error) {
	if op == nil {
		return nil, errors.New("nil op")
	}
	s := op.Spec()
	fail := func(format string, a ...any) error {
		return fmt.Errorf("op %s: %s", s.Name, fmt.Sprintf(format, a...))
	}
	if !opNameRe.MatchString(s.Name) {
		return nil, fail("name must be <provider>.<object>.<verb> (%s)", opNameRe)
	}
	if !strings.HasPrefix(s.Name, provider+".") {
		return nil, fail("name must start with the provider name %q", provider+".")
	}
	e := &Entry{Spec: s, Provider: provider, Op: op}
	var ok bool
	if e.Undo, ok = op.(Inverter); !ok {
		return nil, fail("has no inverse: it must implement Undo (provider.Inverter)")
	}
	if e.Gone, ok = op.(GoneProver); !ok {
		return nil, fail("has no gone check: it must implement Gone (provider.GoneProver)")
	}
	switch s.Kind {
	case KindCreate:
		if e.Locate, ok = op.(Locator); !ok {
			return nil, fail("creates objects but cannot find them after a crash: it must implement Locate (provider.Locator)")
		}
	case KindModify:
		if e.Prior, ok = op.(PriorReader); !ok {
			return nil, fail("modifies objects but does not record the prior value: it must implement Prior (provider.PriorReader)")
		}
	default:
		return nil, fail("kind must be %q or %q, got %q", KindCreate, KindModify, s.Kind)
	}
	if s.Summary == "" {
		return nil, fail("missing summary")
	}
	if !resourceRe.MatchString(s.Resource) || !strings.HasPrefix(s.Resource, provider+".") {
		return nil, fail("resource %q must be <provider>.<type>", s.Resource)
	}
	if len(s.Scopes) == 0 {
		return nil, fail("declares no scopes")
	}
	if len(s.Events) == 0 {
		return nil, fail("declares no expected audit events")
	}
	if len(s.UndoEvents) == 0 {
		return nil, fail("declares no audit events for its inverse")
	}
	if s.UndoSummary == "" || s.GoneCheck == "" {
		return nil, fail("must describe its inverse (UndoSummary) and its proof (GoneCheck)")
	}
	seen := map[string]bool{}
	for _, p := range s.Params {
		if !identRe.MatchString(p.Name) {
			return nil, fail("param %q: name must match %s", p.Name, identRe)
		}
		if seen[p.Name] {
			return nil, fail("param %q declared twice", p.Name)
		}
		seen[p.Name] = true
		switch p.Type {
		case ParamString:
			if p.Example == "" {
				return nil, fail("param %q: string params need an Example for the conformance suite", p.Name)
			}
		case ParamEnum:
			if len(p.Enum) == 0 {
				return nil, fail("param %q: enum without values", p.Name)
			}
		case ParamRef:
			if !resourceRe.MatchString(p.Ref) {
				return nil, fail("param %q: ref must name a resource type", p.Name)
			}
		default:
			return nil, fail("param %q: unknown type %q", p.Name, p.Type)
		}
	}
	for _, o := range s.Outputs {
		if !identRe.MatchString(o) {
			return nil, fail("output %q: name must match %s", o, identRe)
		}
	}
	return e, nil
}

// validateRefs checks every ref param points at a resource some create op in
// the same provider produces, so the conformance suite can build it.
func validateRefs(entries map[string]*Entry) error {
	produced := map[string]bool{}
	for _, e := range entries {
		if e.Spec.Kind == KindCreate {
			produced[e.Spec.Resource] = true
		}
	}
	var errs []error
	for _, e := range entries {
		for _, p := range e.Spec.Params {
			if p.Type == ParamRef && !produced[p.Ref] {
				errs = append(errs, fmt.Errorf("op %s: param %q refers to %s, which no create op produces", e.Spec.Name, p.Name, p.Ref))
			}
		}
	}
	return errors.Join(errs...)
}

func validateAudit(provider string, a AuditInfo) error {
	switch {
	case !sourceNameRe.MatchString(a.Name) || !strings.HasPrefix(a.Name, provider+"."):
		return fmt.Errorf("audit source name %q must be <provider>.<source>", a.Name)
	case a.TypeField == "":
		return errors.New("audit source has no type field")
	case a.Deadline <= 0 || a.Deadline > 24*time.Hour:
		return fmt.Errorf("audit default deadline %s out of range", a.Deadline)
	case a.PollInterval <= 0:
		return errors.New("audit poll interval must be positive")
	}
	return nil
}

// Provider returns the named provider.
func (r *Registry) Provider(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// Op returns the named registered op.
func (r *Registry) Op(name string) (*Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.ops[name]
	return e, ok
}

// Providers returns the registered provider names, sorted.
func (r *Registry) Providers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Ops returns every registered op, sorted by name. With a provider name, only
// that provider's.
func (r *Registry) Ops(provider ...string) []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Entry
	for _, e := range r.ops {
		if len(provider) > 0 && e.Provider != provider[0] {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.Name < out[j].Spec.Name })
	return out
}
