package telemetry

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Values returns every value at path in a decoded JSON document. Path
// segments are separated by "."; a segment ending in "[]" fans out over an
// array, so "target[].id" yields the id of every target. Missing fields and
// unexpected types yield nothing rather than an error or a panic: audit
// events are untrusted input.
func Values(doc any, path string) []string {
	cur := []any{doc}
	for _, seg := range strings.Split(path, ".") {
		fan := strings.HasSuffix(seg, "[]")
		key := strings.TrimSuffix(seg, "[]")
		var next []any
		for _, v := range cur {
			obj, ok := v.(map[string]any)
			if !ok {
				continue
			}
			child, ok := obj[key]
			if !ok {
				continue
			}
			if fan {
				arr, ok := child.([]any)
				if !ok {
					continue
				}
				next = append(next, arr...)
			} else {
				next = append(next, child)
			}
		}
		cur = next
	}
	out := make([]string, 0, len(cur))
	for _, v := range cur {
		if s, ok := scalar(v); ok {
			out = append(out, s)
		}
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
	case nil:
		return "", false
	}
	return "", false
}

// Decode parses a raw event for matching, keeping numbers exact.
func Decode(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// Matches reports whether every path in match has the wanted value.
func Matches(doc any, match map[string]string) bool {
	for path, want := range match {
		found := false
		for _, got := range Values(doc, path) {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
