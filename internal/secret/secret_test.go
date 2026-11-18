package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const canary = "CANARY-sk_live_5f2b9c7e1a"

func TestValueNeverFormats(t *testing.T) {
	v := New(canary)
	type holder struct {
		Token Value
		Ptr   *Value
	}
	h := holder{Token: v, Ptr: &v}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
		outputs = append(outputs, fmt.Sprintf(verb, v), fmt.Sprintf(verb, h), fmt.Sprintf(verb, &v))
	}
	outputs = append(outputs, fmt.Sprint(v), fmt.Sprintln(v, h), v.String(), v.GoString())
	outputs = append(outputs, fmt.Errorf("wrapped: %w", errors.New(fmt.Sprint(v))).Error())
	jb, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(jb))
	mb, _ := json.Marshal(map[string]any{"v": v})
	outputs = append(outputs, string(mb))
	yb, err := yaml.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(yb))
	var logs bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logs, nil))
	l.Info("token", "value", v, "holder", h)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("token", "value", v)
	outputs = append(outputs, logs.String())
	for _, o := range outputs {
		if strings.Contains(o, canary) || strings.Contains(o, fmt.Sprintf("%x", canary)) {
			t.Fatalf("secret leaked through formatting: %q", o)
		}
	}
	if v.Reveal() != canary {
		t.Fatal("Reveal must return the raw value")
	}
	v.Wipe()
	if !v.Empty() || v.Reveal() != "" {
		t.Fatal("Wipe must clear the value")
	}
}

func TestRefValidation(t *testing.T) {
	for _, r := range []Ref{{Env: "A", File: "b"}, {Env: "1BAD"}, {Env: "A B"}} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	if err := (Ref{Env: "SAASHOUND_TOKEN"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if s := (Ref{Env: "X"}).String(); s != "env:X" {
		t.Fatalf("Ref.String = %q", s)
	}
}

func TestDefaultSource(t *testing.T) {
	ctx := context.Background()
	src := DefaultSource{LookupEnv: func(k string) (string, bool) {
		if k == "TOK" {
			return " " + canary + "\n", true
		}
		return "", false
	}}
	v, err := src.Resolve(ctx, Ref{Env: "TOK"})
	if err != nil || v.Reveal() != canary {
		t.Fatalf("env resolve = %v", err)
	}
	if _, err := src.Resolve(ctx, Ref{Env: "MISSING"}); err == nil {
		t.Fatal("missing env accepted")
	}
	if _, err := src.Resolve(ctx, Ref{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("zero ref = %v", err)
	}
	if _, err := src.Resolve(ctx, Ref{Keychain: "saashound/x"}); err == nil {
		t.Fatal("keychain is not supported in this build and must say so")
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	if err := os.WriteFile(p, []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err = src.Resolve(ctx, Ref{File: p})
	if err != nil || v.Reveal() != canary {
		t.Fatalf("file resolve = %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := src.Resolve(ctx, Ref{File: p})
		if err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("a world-readable key file must be refused: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("the error leaked the key")
		}
	}
}
