package provider_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// TestDecodeEvent: an oddly typed field is left zero and the rest of the
// event is kept; only an event that is not JSON is lost.
func TestDecodeEvent(t *testing.T) {
	type wire struct {
		ID     string `json:"id"`
		Repo   string `json:"repo"`
		Target []struct {
			Name string `json:"name"`
		} `json:"target"`
	}
	var w wire
	if !provider.DecodeEvent(json.RawMessage(`{"id":"e1","repo":{"odd":true},"target":[{"name":7},{"name":"saashound-k3v9q2-a"}]}`), &w) {
		t.Fatal("an oddly typed field lost the whole event")
	}
	if w.ID != "e1" || w.Repo != "" || len(w.Target) != 2 || w.Target[1].Name != "saashound-k3v9q2-a" {
		t.Fatalf("decoded %+v", w)
	}
	type stamped struct {
		ID        string             `json:"id"`
		Published provider.EventTime `json:"published"`
		Type      string             `json:"type"`
	}
	for _, published := range []string{`""`, `"yesterday"`, `1731585600000`, `{"odd":true}`, `null`} {
		var s stamped
		if !provider.DecodeEvent(json.RawMessage(`{"id":"e1","published":`+published+`,"type":"x"}`), &s) {
			t.Errorf("published %s lost the whole event", published)
			continue
		}
		if s.ID != "e1" || s.Type != "x" || !s.Published.IsZero() {
			t.Errorf("published %s decoded %+v; want the rest of the event and a zero time", published, s)
		}
	}
	var s stamped
	if !provider.DecodeEvent(json.RawMessage(`{"id":"e1","published":"2026-11-14T12:00:05.25Z","type":"x"}`), &s) {
		t.Fatal("a well-formed timestamp lost the whole event")
	}
	if want := time.Date(2026, 11, 14, 12, 0, 5, 250000000, time.UTC); !s.Published.Equal(want) {
		t.Errorf("published decoded %v; want %v", s.Published.Time, want)
	}
	for _, bad := range []string{``, `not json`, `{"id":"e1"`} {
		var w wire
		if provider.DecodeEvent(json.RawMessage(bad), &w) {
			t.Errorf("DecodeEvent(%q) = true; want false for a malformed event", bad)
		}
	}
}
