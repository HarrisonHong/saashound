package mockgithub

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// emit appends one audit-log event with the request's User-Agent, the way
// GitHub records user_agent for the request that caused it. A dropped action
// is silently not logged (a platform coverage gap); a lagged one is published
// now but not visible to the audit-log API until later.
func (s *Server) emit(st *State, ua, action string, fields map[string]any) {
	if s.drop[action] {
		return
	}
	now := s.now().UTC()
	lag := s.lag
	if d, ok := s.lagByType[action]; ok {
		lag = d
	}
	ev := map[string]any{
		"_document_id": st.newDocID(),
		"@timestamp":   now.UnixMilli(),
		"created_at":   now.UnixMilli(),
		"action":       action,
		"actor":        s.principal,
		"org":          st.Org.Login,
		"user_agent":   ua,
	}
	for k, v := range fields {
		ev[k] = v
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err) // only plain data
	}
	st.Log = append(st.Log, LogEntry{VisibleAt: now.Add(lag), Event: b})
}

// repoFields are the repo-scoped fields every repository audit event carries.
func repoFields(st *State, r *Repo) map[string]any {
	return map[string]any{"repo": st.Org.Login + "/" + r.Name, "repo_id": r.ID}
}

// handleAuditLog serves GET /orgs/{org}/audit-log, filtered to the phrase's
// created:>= date and to events already visible, paginated like the real API.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request, st *State) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	since := phraseSince(queryParam(r, "phrase"))
	now := s.now()
	var items []json.RawMessage
	for _, le := range st.Log {
		if le.VisibleAt.After(now) {
			continue // not ingested yet
		}
		var head struct {
			Timestamp int64 `json:"@timestamp"`
		}
		if json.Unmarshal(le.Event, &head) != nil {
			continue
		}
		if !since.IsZero() && time.UnixMilli(head.Timestamp).UTC().Before(since) {
			continue
		}
		items = append(items, le.Event)
	}
	s.paginate(w, r, items)
}

// phraseSince extracts the created:>= date from an audit-log phrase, returning
// the start of that UTC day, or the zero time when absent.
func phraseSince(phrase string) time.Time {
	for _, part := range strings.Fields(phrase) {
		if v := strings.TrimPrefix(part, "created:>="); v != part {
			if t, err := time.Parse("2006-01-02", v); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}
