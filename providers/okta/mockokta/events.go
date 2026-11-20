package mockokta

import (
	"encoding/json"
	"net/http"
	"time"
)

// target is one System Log target entry.
type target struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// actor is the System Log actor: who performed the action.
type actor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

// emit appends one System Log event for a call the service app made, with the
// request's User-Agent, the way Okta records client.userAgent.rawUserAgent for
// the request that caused it.
func (s *Server) emit(st *State, ua, eventType, message string, targets ...target) {
	s.emitAs(st, s.appActor(), ua, eventType, message, targets...)
}

// emitAs appends one System Log event performed by a. A dropped event type is
// silently not logged (a platform coverage gap); a lagged one is published now
// but not visible to /logs until later.
func (s *Server) emitAs(st *State, a actor, ua, eventType, message string, targets ...target) {
	if s.drop[eventType] {
		return
	}
	now := s.now().UTC()
	lag := s.lag
	if d, ok := s.lagByType[eventType]; ok {
		lag = d
	}
	if targets == nil {
		targets = []target{}
	}
	ev := map[string]any{
		"uuid":           st.newID("evt"),
		"published":      now.Format(time.RFC3339Nano),
		"eventType":      eventType,
		"displayMessage": message,
		"severity":       "INFO",
		"actor":          a,
		"client":         map[string]any{"userAgent": map[string]string{"rawUserAgent": ua}},
		"outcome":        map[string]string{"result": "SUCCESS"},
		"target":         targets,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err) // only plain data
	}
	st.Log = append(st.Log, LogEntry{VisibleAt: now.Add(lag), Event: b})
}

// appActor is the service app, the actor Okta attributes a call made with
// its access token to.
func (s *Server) appActor() actor {
	return actor{ID: s.app.clientID, Type: "PublicClientApp", AlternateID: s.app.clientID, DisplayName: s.app.label}
}

// adminActor is the seeded human admin, acting in the Admin Console.
func (s *Server) adminActor(st *State) actor {
	for _, u := range sortedUsers(st.Users) {
		if u.Profile.Login == AdminLogin {
			return actor{ID: u.ID, Type: "User", AlternateID: u.Profile.Login, DisplayName: "Mock Admin"}
		}
	}
	return actor{ID: "unknown", Type: "User", AlternateID: AdminLogin, DisplayName: AdminLogin}
}

// routeLogs serves GET /api/v1/logs, filtered to the since/until window and to
// events that are already visible, paginated like the real System Log.
func (s *Server) routeLogs(w http.ResponseWriter, r *http.Request, st *State) {
	since := parseTime(queryParam(r, "since"))
	until := parseTime(queryParam(r, "until"))
	now := s.now()
	var items []json.RawMessage
	for _, le := range st.Log {
		if le.VisibleAt.After(now) {
			continue // not ingested yet
		}
		var head struct {
			Published time.Time `json:"published"`
		}
		if json.Unmarshal(le.Event, &head) != nil {
			continue
		}
		if !since.IsZero() && head.Published.Before(since) {
			continue
		}
		if !until.IsZero() && head.Published.After(until) {
			continue
		}
		items = append(items, le.Event)
	}
	s.paginate(w, r, items)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, s); err != nil {
			return time.Time{}
		}
	}
	return t
}
