package technique

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// Corpus is a set of validated techniques.
type Corpus struct {
	// Version is the verified corpus version, e.g. "2026.11.0".
	Version string
	byID    map[string]*Technique
}

// NewCorpus returns an empty corpus.
func NewCorpus(version string) *Corpus {
	return &Corpus{Version: version, byID: map[string]*Technique{}}
}

// LoadFS reads every *.yaml file under fsys, validates each against cat and
// adds it to the corpus. verified marks the embedded, release-pinned corpus;
// everything else (--corpus-dir) is reported as unverified. Every invalid
// file is reported, not only the first.
func (c *Corpus) LoadFS(fsys fs.FS, verified bool, cat Catalog) error {
	var errs []error
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path.Ext(p) != ".yaml" {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		t, err := Parse(p, b)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		t.Verified = verified
		if err := Validate(t, cat); err != nil {
			errs = append(errs, err)
			return nil
		}
		if err := c.add(t); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return errors.Join(errs...)
}

// LoadDir loads extra techniques from a directory on disk (--corpus-dir).
func (c *Corpus) LoadDir(dir string, cat Catalog) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("corpus dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("corpus dir: %s is not a directory", dir)
	}
	return c.LoadFS(os.DirFS(dir), false, cat)
}

func (c *Corpus) add(t *Technique) error {
	if prev, dup := c.byID[t.ID]; dup {
		return fmt.Errorf("%s: technique %s is already defined by %s", t.Source, t.ID, prev.Source)
	}
	c.byID[t.ID] = t
	return nil
}

// Get returns the technique with the given ID.
func (c *Corpus) Get(id string) (*Technique, bool) {
	t, ok := c.byID[id]
	return t, ok
}

// Lookup returns the technique with the given ID or a helpful error.
func (c *Corpus) Lookup(id string) (*Technique, error) {
	if t, ok := c.byID[id]; ok {
		return t, nil
	}
	var near []string
	for _, t := range c.List() {
		if strings.Contains(t.ID, id) || strings.Contains(id, t.ID) {
			near = append(near, t.ID)
		}
	}
	if len(near) > 0 {
		return nil, fmt.Errorf("unknown technique %q (did you mean %s?)", id, strings.Join(near, ", "))
	}
	return nil, fmt.Errorf("unknown technique %q (see `saashound list`)", id)
}

// List returns every technique, sorted by ID.
func (c *Corpus) List() []*Technique {
	out := make([]*Technique, 0, len(c.byID))
	for _, t := range c.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
