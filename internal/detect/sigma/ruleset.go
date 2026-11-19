package sigma

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/HarrisonHong/saashound/internal/detect"
	sigmalite "github.com/runreveal/sigmalite"
	yaml "go.yaml.in/yaml/v3"
)

// maxRuleFileSize bounds a Sigma rule file the loader will read.
const maxRuleFileSize = 1 << 20

// loadedRule is a parsed Sigma rule and where it came from.
type loadedRule struct {
	rule   *sigmalite.Rule
	source string // the path it was loaded from, relative to the rules root
}

// RuleSet is a collection of Sigma rules loaded from one or more local
// directories, indexed so a technique can reference a rule by its stable ID
// (a Sigma UUID), its title, or its path. Rules are the operator's: the tool
// loads them, it never vendors them.
type RuleSet struct {
	rules   []*loadedRule
	byID    map[string]*loadedRule
	byTitle map[string][]*loadedRule
	byPath  map[string]*loadedRule

	// unsupported records rules the checker recognises but cannot evaluate
	// faithfully (Sigma v2 correlation rules, rules the evaluator cannot
	// parse), keyed by every identifier they can be referenced by, mapped to
	// a human reason.
	unsupported map[string]string

	// idSources and pathDocs record every rule document seen, evaluable or
	// not: the sources each id was declared in, and how many rule documents
	// each path holds. An id or path naming more than one rule document is
	// ambiguous and is never silently resolved to one of them.
	idSources map[string][]string
	pathDocs  map[string]int

	// warnings are non-fatal load problems (a file that would not parse),
	// surfaced to the operator but never turned into a silent pass.
	warnings []string
}

// NewRuleSet returns an empty rule set.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		byID:        map[string]*loadedRule{},
		byTitle:     map[string][]*loadedRule{},
		byPath:      map[string]*loadedRule{},
		unsupported: map[string]string{},
		idSources:   map[string][]string{},
		pathDocs:    map[string]int{},
	}
}

// Warnings returns the non-fatal problems seen while loading.
func (rs *RuleSet) Warnings() []string { return rs.warnings }

// Len returns the number of evaluable rules loaded.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// LoadDir loads every .yml/.yaml Sigma rule under dir. A directory that does
// not exist is an error; an unreadable or unparseable file is a warning, so a
// single bad file never stops the operator's whole rule checkout from loading.
func (rs *RuleSet) LoadDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("sigma rules dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("sigma rules dir: %s is not a directory", dir)
	}
	return rs.LoadFS(os.DirFS(dir))
}

// LoadFS loads every .yml/.yaml Sigma rule under fsys.
func (rs *RuleSet) LoadFS(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isRuleFile(p) {
			return nil
		}
		b, err := readCapped(fsys, p)
		if err != nil {
			rs.warnings = append(rs.warnings, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		rs.addFile(p, b)
		return nil
	})
}

func isRuleFile(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".yml", ".yaml":
		return true
	}
	return false
}

func readCapped(fsys fs.FS, p string) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRuleFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRuleFileSize {
		return nil, fmt.Errorf("rule file larger than %d bytes", maxRuleFileSize)
	}
	return b, nil
}

// addFile parses one rule file, which may hold several YAML documents. A
// document carrying a Sigma v2 `correlation` block is recorded as
// unsupported; a normal detection document is parsed and indexed, or recorded
// as unsupported with the parse error when the evaluator cannot parse it;
// anything else is ignored.
func (rs *RuleSet) addFile(source string, b []byte) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	parsedAny := false
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			rs.warnings = append(rs.warnings, fmt.Sprintf("%s: %v", source, err))
			return
		}
		raw := map[string]any{}
		if err := doc.Decode(&raw); err != nil {
			continue
		}
		parsedAny = true
		if _, isCorrelation := raw["correlation"]; isCorrelation {
			rs.addUnsupported(source, raw, "Sigma correlation rule (not supported by any Go evaluator)")
			continue
		}
		if _, hasDetection := raw["detection"]; !hasDetection {
			continue // not a rule document
		}
		docBytes, err := yaml.Marshal(&doc)
		if err != nil {
			rs.warnings = append(rs.warnings, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		r, err := sigmalite.ParseRule(docBytes)
		if err != nil {
			rs.warnings = append(rs.warnings, fmt.Sprintf("%s: %v", source, err))
			rs.addUnsupported(source, raw, fmt.Sprintf("the rule could not be parsed by the evaluator: %v", err))
			continue
		}
		if r.Status == sigmalite.Unsupported {
			rs.addUnsupported(source, raw, "rule is marked status: unsupported")
			continue
		}
		rs.index(&loadedRule{rule: r, source: source})
	}
	if !parsedAny {
		rs.warnings = append(rs.warnings, fmt.Sprintf("%s: no YAML documents", source))
	}
}

func (rs *RuleSet) index(lr *loadedRule) {
	rs.rules = append(rs.rules, lr)
	rs.noteDocument(lr.source, lr.rule.ID)
	if id := lr.rule.ID; id != "" {
		if _, dup := rs.byID[id]; !dup {
			rs.byID[id] = lr
		}
	}
	if t := lr.rule.Title; t != "" {
		rs.byTitle[t] = append(rs.byTitle[t], lr)
	}
	rs.byPath[normPath(lr.source)] = lr
}

func (rs *RuleSet) addUnsupported(source string, raw map[string]any, reason string) {
	id, _ := raw["id"].(string)
	rs.noteDocument(source, id)
	for _, key := range []string{"id", "title", "name"} {
		if v, ok := raw[key].(string); ok && v != "" {
			rs.unsupported[v] = reason
		}
	}
	rs.unsupported[normPath(source)] = reason
}

// noteDocument records one rule document, evaluable or not, against its
// source path and its id, so resolve can refuse a reference that names more
// than one rule.
func (rs *RuleSet) noteDocument(source, id string) {
	rs.pathDocs[normPath(source)]++
	if id == "" {
		return
	}
	if prev := rs.idSources[id]; len(prev) > 0 {
		rs.warnings = append(rs.warnings, fmt.Sprintf("%s: duplicate rule id %s (already loaded from %s)", source, id, prev[0]))
	}
	rs.idSources[id] = append(rs.idSources[id], source)
}

func normPath(p string) string { return path.Clean(strings.TrimPrefix(p, "./")) }

// resolution is the outcome of looking a reference up in a rule set.
type resolution struct {
	// status is one of detect.Status{Unknown,Unsupported} on failure, or ""
	// when a rule was found.
	status string
	rule   *sigmalite.Rule
	// reason explains an unknown/unsupported/ambiguous reference.
	reason string
}

// resolve finds the rule a technique's reference names. It tries the Sigma
// UUID first (the stable identifier the design uses), then the title, then the
// path. A reference that matches nothing is unknown; one that matches a rule
// the evaluator cannot handle is unsupported; an ambiguous id, title or path
// is reported as unknown, never silently resolved to one rule.
func (rs *RuleSet) resolve(ref string) resolution {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return resolution{status: detect.StatusUnknown, reason: "empty rule reference"}
	}
	if srcs := rs.idSources[ref]; len(srcs) > 1 {
		return resolution{status: detect.StatusUnknown, reason: fmt.Sprintf("the id %q is declared by %d rules (%s); give each rule a unique id", ref, len(srcs), strings.Join(srcs, ", "))}
	}
	if lr, ok := rs.byID[ref]; ok {
		return resolution{rule: lr.rule}
	}
	if reason, ok := rs.unsupported[ref]; ok {
		return resolution{status: detect.StatusUnsupported, reason: reason}
	}
	if lrs, ok := rs.byTitle[ref]; ok {
		if len(lrs) == 1 {
			return resolution{rule: lrs[0].rule}
		}
		return resolution{status: detect.StatusUnknown, reason: fmt.Sprintf("the title %q matches %d rules; reference it by its Sigma id instead", ref, len(lrs))}
	}
	// A reference that ends without an extension may name a path; try common
	// extensions so `fake/role-assign` finds `fake/role-assign.yml`.
	for _, ext := range []string{"", ".yml", ".yaml"} {
		key := normPath(ref) + ext
		if n := rs.pathDocs[key]; n > 1 {
			return resolution{status: detect.StatusUnknown, reason: fmt.Sprintf("the path %q holds %d rules; reference the rule by its Sigma id instead", key, n)}
		}
		if reason, ok := rs.unsupported[key]; ok {
			return resolution{status: detect.StatusUnsupported, reason: reason}
		}
		if lr, ok := rs.byPath[key]; ok {
			return resolution{rule: lr.rule}
		}
	}
	return resolution{status: detect.StatusUnknown, reason: "no rule with this id, title or path was found in the loaded Sigma rules"}
}
