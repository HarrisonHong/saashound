package provider_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// testProvider is a minimal provider whose ops the tests choose.
type testProvider struct {
	name string
	ops  []provider.Op
}

func (p testProvider) Name() string       { return p.name }
func (p testProvider) Ops() []provider.Op { return p.ops }
func (p testProvider) Audit() provider.AuditInfo {
	return provider.AuditInfo{Name: p.name + ".audit", TypeField: "type", Deadline: time.Minute, PollInterval: time.Second}
}
func (p testProvider) Open(context.Context, provider.Config) (provider.Tenant, error) {
	return nil, nil
}

func spec(name string, kind provider.Kind) provider.Spec {
	return provider.Spec{
		Name: name, Summary: "s", Kind: kind, Resource: "t.thing",
		Scopes: []string{"t.manage"}, Events: []string{"thing.create"}, UndoEvents: []string{"thing.delete"},
		UndoSummary: "delete", GoneCheck: "GET -> 404",
	}
}

// doOnly has Do and nothing else.
type doOnly struct{ s provider.Spec }

func (o doOnly) Spec() provider.Spec { return o.s }
func (doOnly) Do(context.Context, *provider.Call) (provider.Result, error) {
	return provider.Result{}, nil
}

type withUndo struct{ doOnly }

func (withUndo) Undo(context.Context, *provider.Call, provider.Record) error { return nil }

type withGone struct{ withUndo }

func (withGone) Gone(context.Context, *provider.Call, provider.Record) (bool, error) {
	return true, nil
}

type complete struct{ withGone }

func (complete) Locate(context.Context, *provider.Call) (provider.Result, bool, error) {
	return provider.Result{}, false, nil
}

type completeModify struct{ withGone }

func (completeModify) Prior(context.Context, *provider.Call) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}

func register(ops ...provider.Op) error {
	return provider.NewRegistry().Register(testProvider{name: "t", ops: ops})
}

func TestRegistrationRequiresInverseAndProof(t *testing.T) {
	create := spec("t.thing.create", provider.KindCreate)
	modify := spec("t.thing.modify", provider.KindModify)
	cases := []struct {
		name string
		op   provider.Op
		want string
	}{
		{"no inverse", doOnly{create}, "has no inverse"},
		{"no gone check", withUndo{doOnly{create}}, "has no gone check"},
		{"create without locate", withGone{withUndo{doOnly{create}}}, "must implement Locate"},
		{"modify without prior", withGone{withUndo{doOnly{modify}}}, "must implement Prior"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := register(c.op)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Register = %v; want an error containing %q", err, c.want)
			}
		})
	}
	if err := register(complete{withGone{withUndo{doOnly{create}}}}); err != nil {
		t.Fatalf("a complete create op must register: %v", err)
	}
	if err := register(complete{withGone{withUndo{doOnly{create}}}}, completeModify{withGone{withUndo{doOnly{modify}}}}); err != nil {
		t.Fatalf("a complete modify op must register: %v", err)
	}
}

func TestRegistrationValidatesSpecs(t *testing.T) {
	good := func(mut func(*provider.Spec)) provider.Op {
		s := spec("t.thing.create", provider.KindCreate)
		mut(&s)
		return complete{withGone{withUndo{doOnly{s}}}}
	}
	cases := []struct {
		name string
		mut  func(*provider.Spec)
		want string
	}{
		{"bad name", func(s *provider.Spec) { s.Name = "Thing" }, "<provider>.<object>.<verb>"},
		{"foreign namespace", func(s *provider.Spec) { s.Name = "okta.user.create" }, "must start with the provider name"},
		{"no scopes", func(s *provider.Spec) { s.Scopes = nil }, "no scopes"},
		{"no events", func(s *provider.Spec) { s.Events = nil }, "no expected audit events"},
		{"no undo events", func(s *provider.Spec) { s.UndoEvents = nil }, "audit events for its inverse"},
		{"undescribed inverse", func(s *provider.Spec) { s.GoneCheck = "" }, "must describe its inverse"},
		{"bad kind", func(s *provider.Spec) { s.Kind = "delete" }, "kind must be"},
		{"bad resource", func(s *provider.Spec) { s.Resource = "other.thing" }, "resource"},
		{"string param without example", func(s *provider.Spec) {
			s.Params = []provider.Param{{Name: "x", Type: provider.ParamString}}
		}, "need an Example"},
		{"dangling ref", func(s *provider.Spec) {
			s.Params = []provider.Param{{Name: "u", Type: provider.ParamRef, Ref: "t.user"}}
		}, "which no create op produces"},
		{"unknown param type", func(s *provider.Spec) {
			s.Params = []provider.Param{{Name: "u", Type: "url"}}
		}, "unknown type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := register(good(c.mut))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Register = %v; want %q", err, c.want)
			}
		})
	}
}

func TestRegistrationIsAllOrNothing(t *testing.T) {
	r := provider.NewRegistry()
	good := complete{withGone{withUndo{doOnly{spec("t.thing.create", provider.KindCreate)}}}}
	bad := doOnly{spec("t.thing.update", provider.KindModify)}
	if err := r.Register(testProvider{name: "t", ops: []provider.Op{good, bad}}); err == nil {
		t.Fatal("want error")
	}
	if _, ok := r.Op("t.thing.create"); ok {
		t.Fatal("a provider with one invalid op must register none of its ops")
	}
	if err := r.Register(testProvider{name: "t", ops: []provider.Op{good}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(testProvider{name: "t", ops: []provider.Op{good}}); err == nil {
		t.Fatal("registering a provider twice must fail")
	}
	if err := r.Register(testProvider{name: "t", ops: []provider.Op{good, good}}); err == nil {
		t.Fatal("duplicate ops must fail")
	}
}

func TestRegisterPanicsLoudly(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "has no inverse") {
			t.Fatalf("Register must panic naming the missing inverse, got %v", r)
		}
	}()
	provider.Register(testProvider{name: "panicky", ops: []provider.Op{doOnly{spec("panicky.thing.create", provider.KindCreate)}}})
}

func TestUserAgentFromContext(t *testing.T) {
	ctx := context.Background()
	if ua := provider.UserAgent(ctx); !strings.HasPrefix(ua, "saashound/") {
		t.Fatalf("default UA %q must identify the tool", ua)
	}
	ctx = provider.WithUserAgent(ctx, "saashound/1 (run=abcdef; phase=detonate)")
	if ua := provider.UserAgent(ctx); ua != "saashound/1 (run=abcdef; phase=detonate)" {
		t.Fatalf("UA = %q", ua)
	}
}
