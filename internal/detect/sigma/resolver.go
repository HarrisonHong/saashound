package sigma

import (
	"bytes"
	"encoding/json"
	"strconv"

	sigmalite "github.com/runreveal/sigmalite"
)

// resolver maps a raw audit event, decoded as a generic JSON document, to the
// fields a Sigma rule keys on.
//
// SigmaHQ's identity-provider rules reference event fields by their raw path:
// `eventType`, `displayMessage`, `outcome.result`, `actor.alternateId`,
// `target.displayName`. The Okta System Log emits exactly those paths, and the
// simulated `fake` platform mirrors that shape, so the mapping is the JSON
// document itself: a dotted field name is walked segment by segment, fanning
// out over every array it crosses. `target.displayName` therefore yields the
// displayName of every element of the `target` array, which is what a rule
// written against `target.displayName` means.
//
// resolver implements sigmalite.FieldResolver, so field modifiers (contains,
// startswith, re, ...) still apply to the resolved values.
type resolver struct {
	doc any
}

// newEntry decodes one raw event into a sigmalite log entry backed by a
// resolver. Message is the whole raw event, so a field-less Sigma keyword
// search matches anywhere in the event, as Sigma's "search the full log line"
// semantics require; all structured field lookups go through the resolver.
func newEntry(raw json.RawMessage) (*sigmalite.LogEntry, *sigmalite.MatchOptions, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	r := &resolver{doc: doc}
	entry := &sigmalite.LogEntry{Message: string(raw)}
	return entry, &sigmalite.MatchOptions{FieldResolver: r}, nil
}

// Resolve implements sigmalite.FieldResolver.
func (r *resolver) Resolve(field string, _ *sigmalite.LogEntry) []string {
	return values(r.doc, field)
}

// values returns every scalar at the dotted field path in doc, fanning out
// over any array encountered. Missing fields and unexpected types yield
// nothing rather than an error: audit events are untrusted input.
func values(doc any, field string) []string {
	cur := []any{doc}
	for _, seg := range splitDots(field) {
		var next []any
		for _, v := range cur {
			for _, item := range flatten(v) {
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if child, ok := obj[seg]; ok {
					next = append(next, child)
				}
			}
		}
		cur = next
	}
	out := make([]string, 0, len(cur))
	for _, v := range cur {
		for _, item := range flatten(v) {
			if s, ok := scalar(item); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// flatten expands nested arrays into a flat list of their elements; a
// non-array value is returned as a single-element list.
func flatten(v any) []any {
	arr, ok := v.([]any)
	if !ok {
		return []any{v}
	}
	out := make([]any, 0, len(arr))
	for _, e := range arr {
		out = append(out, flatten(e)...)
	}
	return out
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

// splitDots splits a Sigma field name on ".". Sigma field names never carry
// the "[]" array marker the telemetry matcher uses; arrays are crossed
// implicitly by values.
func splitDots(field string) []string {
	var out []string
	start := 0
	for i := 0; i < len(field); i++ {
		if field[i] == '.' {
			out = append(out, field[start:i])
			start = i + 1
		}
	}
	return append(out, field[start:])
}
