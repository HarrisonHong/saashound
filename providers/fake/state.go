package fake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/HarrisonHong/saashound/internal/fsutil"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// StateVersion is the simulated tenant's on-disk format version.
const StateVersion = 1

// State is the whole simulated tenant: its identity, its objects and its
// audit log.
type State struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	Principal   string `json:"principal"`
	DisplayName string `json:"display_name"`
	Domain      string `json:"domain"`
	ShortName   string `json:"short_name"`
	Tier        string `json:"tier"`
	// TokenSHA256 is the SHA-256 of the credential the tenant accepts, if
	// it requires one. The tenant never stores the credential itself.
	TokenSHA256 string `json:"token_sha256,omitempty"`

	NextID   int                   `json:"next_id"`
	Users    map[string]*User      `json:"users"`
	Groups   map[string]*Group     `json:"groups"`
	Factors  map[string]*Factor    `json:"factors"`
	Grants   map[string]*RoleGrant `json:"grants"`
	Zones    map[string]*Zone      `json:"zones"`
	Settings map[string]string     `json:"settings"`
	Log      []LogEntry            `json:"log"`
}

// User is a tenant user.
type User struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Login       string    `json:"login"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"` // ACTIVE, DEPROVISIONED
	PasswordSet bool      `json:"password_set"`
	Created     time.Time `json:"created"`
}

// Group is a tenant group. The ownership marker is a group.
type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Factor is an enrolled MFA factor. Its seed is never stored.
type Factor struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	UserID string `json:"user_id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// RoleGrant is an admin role assigned to a user.
type RoleGrant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// Zone is a network zone.
type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Gateway string `json:"gateway"`
	Status  string `json:"status"` // ACTIVE, INACTIVE
}

// LogEntry is one audit event plus when it becomes visible to the audit API.
type LogEntry struct {
	VisibleAt time.Time       `json:"visible_at"`
	Event     json.RawMessage `json:"event"`
}

func (s *State) init() {
	if s.Users == nil {
		s.Users = map[string]*User{}
	}
	if s.Groups == nil {
		s.Groups = map[string]*Group{}
	}
	if s.Factors == nil {
		s.Factors = map[string]*Factor{}
	}
	if s.Grants == nil {
		s.Grants = map[string]*RoleGrant{}
	}
	if s.Zones == nil {
		s.Zones = map[string]*Zone{}
	}
	if s.Settings == nil {
		s.Settings = map[string]string{}
	}
}

func (s *State) newID(prefix string) string {
	s.NextID++
	return fmt.Sprintf("%s%07d", prefix, s.NextID)
}

// Store persists simulated tenants.
type Store interface {
	// Create stores a new tenant, failing if it exists.
	Create(id string, s *State) error
	// Update loads the tenant, applies fn and saves it if fn succeeds. The
	// change is durable when Update returns.
	Update(id string, fn func(*State) error) error
	// View loads the tenant read-only.
	View(id string, fn func(*State) error) error
}

// ErrNoTenant is returned for a tenant that was never provisioned.
var ErrNoTenant = errors.New("simulated tenant not provisioned")

// MemoryStore keeps tenants in memory. State is copied through JSON on every
// access, exactly as the file store does, so no caller can alias it.
type MemoryStore struct {
	mu      sync.Mutex
	tenants map[string][]byte
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{tenants: map[string][]byte{}} }

// Create implements Store.
func (m *MemoryStore) Create(id string, s *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[id]; ok {
		return fmt.Errorf("simulated tenant %s: %w", id, provider.ErrAlreadyExists)
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	m.tenants[id] = b
	return nil
}

// Update implements Store.
func (m *MemoryStore) Update(id string, fn func(*State) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load(id)
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	m.tenants[id] = b
	return nil
}

// View implements Store.
func (m *MemoryStore) View(id string, fn func(*State) error) error {
	m.mu.Lock()
	s, err := m.load(id)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return fn(s)
}

func (m *MemoryStore) load(id string) (*State, error) {
	b, ok := m.tenants[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoTenant, id)
	}
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	s.init()
	return s, nil
}

// FileStore keeps each tenant in a JSON file (mode 0600) so the simulated
// tenant outlives the process: `apply` can crash and a later `cleanup` or
// `sweep` sees exactly what was left behind. Every update is atomic and
// fsynced before it returns, the way a real platform's write is durable once
// the API call returns.
type FileStore struct {
	Dir string
}

var tenantFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (f FileStore) path(id string) (string, error) {
	if !tenantFileRe.MatchString(id) {
		return "", fmt.Errorf("simulated tenant id %q must match %s", id, tenantFileRe)
	}
	return filepath.Join(f.Dir, id+".json"), nil
}

func (f FileStore) lock(id string) (*fsutil.Lock, error) {
	if err := fsutil.MkdirPrivate(f.Dir); err != nil {
		return nil, err
	}
	p, err := f.path(id)
	if err != nil {
		return nil, err
	}
	// Writers to one tenant are serialised; a run holds the target lock as
	// well, so contention here is short.
	for i := 0; ; i++ {
		l, err := fsutil.TryLock(p + ".lock")
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, fsutil.ErrLocked) || i >= 500 {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Create implements Store.
func (f FileStore) Create(id string, s *State) error {
	l, err := f.lock(id)
	if err != nil {
		return err
	}
	defer l.Unlock()
	p, _ := f.path(id)
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("simulated tenant %s at %s: %w", id, p, provider.ErrAlreadyExists)
	}
	return f.save(p, s)
}

// Update implements Store.
func (f FileStore) Update(id string, fn func(*State) error) error {
	l, err := f.lock(id)
	if err != nil {
		return err
	}
	defer l.Unlock()
	p, _ := f.path(id)
	s, err := f.load(p, id)
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	return f.save(p, s)
}

// View implements Store.
func (f FileStore) View(id string, fn func(*State) error) error {
	l, err := f.lock(id)
	if err != nil {
		return err
	}
	p, _ := f.path(id)
	s, err := f.load(p, id)
	_ = l.Unlock()
	if err != nil {
		return err
	}
	return fn(s)
}

func (f FileStore) load(p, id string) (*State, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoTenant, id)
	}
	if err != nil {
		return nil, err
	}
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("simulated tenant %s: %w", id, err)
	}
	if s.Version != StateVersion {
		return nil, fmt.Errorf("simulated tenant %s: unsupported state version %d", id, s.Version)
	}
	s.init()
	return s, nil
}

func (f FileStore) save(p string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, append(b, '\n'))
}
