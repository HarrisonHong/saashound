package provider

import (
	"context"
	"encoding/json"
)

// Op is one operation in a provider's closed vocabulary, for example
// "okta.user.create". Techniques can only compose registered ops.
//
// Do alone is not enough to register: every op must also implement Inverter
// (Undo) and GoneProver (Gone), plus Locator if it creates an object or
// PriorReader if it modifies one. Register refuses an op that lacks any of
// them, which is what makes the corpus reversible by construction.
type Op interface {
	Spec() Spec
	// Do performs the operation. It must name any object it creates
	// c.Name exactly, so the object can be found again after a crash.
	Do(ctx context.Context, c *Call) (Result, error)
}

// Inverter undoes an op.
type Inverter interface {
	// Undo reverses Do using what the journal recorded. For a create op it
	// deletes the object; for a modify op it restores r.Prior exactly, never
	// an assumed default. Undo on an object that is already gone must return
	// nil or an error wrapping ErrNotFound.
	Undo(ctx context.Context, c *Call, r Record) error
}

// GoneProver proves that Undo worked.
type GoneProver interface {
	// Gone reports whether the object Do created no longer exists (create
	// ops), or whether the modified value equals r.Prior again (modify ops).
	Gone(ctx context.Context, c *Call, r Record) (bool, error)
}

// Locator finds a created object by its deterministic name. The cleaner uses
// it when the journal holds an intent without a result: the process died
// mid-call, so the object may exist with an unknown ID. Locate matches
// c.Name exactly, never a substring.
type Locator interface {
	Locate(ctx context.Context, c *Call) (res Result, found bool, err error)
}

// PriorReader reads the value a modify op is about to change. The executor
// calls it before writing the intent, so the prior value is in the journal
// before anything changes and a crash mid-call can still be undone.
type PriorReader interface {
	Prior(ctx context.Context, c *Call) (json.RawMessage, error)
}

// Kind says whether an op creates a new object or modifies an existing one.
type Kind string

// Op kinds.
const (
	KindCreate Kind = "create"
	KindModify Kind = "modify"
)

// ParamType is the type of an op parameter.
type ParamType string

// Parameter types. There is deliberately no URL or host type: ops build
// requests against the target's own API base, so a technique cannot choose
// where a request goes.
const (
	// ParamString is free text. It may use {{run.*}}, {{target.*}} and
	// {{steps.<id>.<output>}} substitutions.
	ParamString ParamType = "string"
	// ParamEnum is one of Param.Enum, literally.
	ParamEnum ParamType = "enum"
	// ParamRef is the ID of an object an earlier step created, written
	// exactly "{{steps.<id>.id}}"; that step's op must produce Param.Ref.
	ParamRef ParamType = "ref"
)

// Param declares one typed op parameter.
type Param struct {
	Name     string
	Type     ParamType
	Required bool
	// Ref is the resource type a ParamRef must point at, e.g. "okta.user".
	Ref string
	// Enum lists the allowed values of a ParamEnum.
	Enum []string
	// Example is a valid value used by the conformance suite for ParamString.
	Example string
	Doc     string
}

// Spec declares what an op is and does. It is static data, printed by
// `plan` and checked by the validator and the conformance suite.
type Spec struct {
	// Name is "<provider>.<object>.<verb>", e.g. "okta.factor.enroll_totp".
	Name    string
	Summary string
	Kind    Kind
	// Resource is the resource type the op creates or modifies, e.g.
	// "okta.user". It is what ParamRef parameters point at.
	Resource string
	Params   []Param
	// Outputs are the result fields later steps may reference as
	// {{steps.<id>.<field>}}. "id" and "name" are always available.
	Outputs []string
	// Scopes are the permissions the op needs.
	Scopes []string
	// Events are the audit event types Do is expected to produce.
	Events []string
	// UndoEvents are the audit event types Undo produces.
	UndoEvents []string
	// Request describes the API call for the plan, e.g. "POST /api/v1/users".
	Request string
	// UndoSummary describes the inverse for the plan, e.g. "delete user".
	UndoSummary string
	// GoneCheck describes the proof for the plan, e.g. "GET /users/{id} -> 404".
	GoneCheck string
	// Note is shown in the plan next to the object, e.g. "password discarded".
	Note string
}

// Param returns the named parameter.
func (s Spec) Param(name string) (Param, bool) {
	for _, p := range s.Params {
		if p.Name == name {
			return p, true
		}
	}
	return Param{}, false
}

// TargetsRunObject reports whether a modify op changes an object an earlier
// step of the same run created (it has a required ref parameter pointing at
// its own resource type). A modify op that does not, changes something that
// existed before the run, and techniques using it must declare
// safety.modifies_existing.
func (s Spec) TargetsRunObject() bool {
	for _, p := range s.Params {
		if p.Type == ParamRef && p.Required && p.Ref == s.Resource {
			return true
		}
	}
	return false
}

// HasOutput reports whether field may be referenced from a later step.
func (s Spec) HasOutput(field string) bool {
	if field == "id" || field == "name" {
		return true
	}
	for _, o := range s.Outputs {
		if o == field {
			return true
		}
	}
	return false
}

// Call is one invocation of an op.
type Call struct {
	Run  string
	Step string
	// Name is the deterministic object name, marker.ObjectName(Run, Step).
	Name string
	// Params are the resolved parameter values. They never hold secrets.
	Params map[string]string
	Target TargetInfo
	// Tenant is the provider's own Tenant; ops type-assert it.
	Tenant Tenant
}

// Result is what Do (or Locate) reports about the object.
type Result struct {
	// ID is the platform's identifier for the created or modified object.
	ID string
	// Outputs are declared output fields. They are journalled, so they must
	// never hold secrets.
	Outputs map[string]string
}

// Record is what the journal knows about a step, handed to Undo and Gone.
type Record struct {
	ID      string            `json:"id,omitempty"`
	Outputs map[string]string `json:"outputs,omitempty"`
	// Prior is the value a modify op changed, read before the change.
	Prior json.RawMessage `json:"prior,omitempty"`
}

// Entry is a registered op. Registration guarantees Undo and Gone are set,
// and Locate (create ops) or Prior (modify ops).
type Entry struct {
	Spec     Spec
	Provider string
	Op       Op
	Undo     Inverter
	Gone     GoneProver
	Locate   Locator     // set for create ops
	Prior    PriorReader // set for modify ops
}
