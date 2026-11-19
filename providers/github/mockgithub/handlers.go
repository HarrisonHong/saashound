package mockgithub

import (
	"encoding/json"
	"net/http"
	"sort"
)

// membershipJSON renders a member's org membership.
func membershipJSON(login, role string) map[string]any {
	return map[string]any{
		"state": "active",
		"role":  role,
		"user":  map[string]any{"login": login},
	}
}

// repoJSON renders a repository in the shape the provider decodes.
func repoJSON(st *State, r *Repo) map[string]any {
	vis := "private"
	if !r.Private {
		vis = "public"
	}
	return map[string]any{
		"id": r.ID, "name": r.Name, "full_name": st.Org.Login + "/" + r.Name,
		"private": r.Private, "visibility": vis, "default_branch": "main",
		"security_and_analysis": map[string]any{
			"secret_scanning":                 map[string]any{"status": r.SecretScanning},
			"secret_scanning_push_protection": map[string]any{"status": r.PushProtection},
		},
	}
}

// handleUser serves GET /user: the authenticated principal.
func (s *Server) handleUser(w http.ResponseWriter, r *http.Request, st *State) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	m := st.Members[s.principal]
	id := int64(0)
	if m != nil {
		id = m.ID
	}
	writeJSON(w, 200, map[string]any{"login": s.principal, "id": id, "type": "User"})
}

// handleSelfMembership serves GET /user/memberships/orgs/{org}.
func (s *Server) handleSelfMembership(w http.ResponseWriter, r *http.Request, st *State, org string) {
	if org != s.org {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	m := st.Members[s.principal]
	if m == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, 200, membershipJSON(m.Login, m.Role))
}

// handleMembers serves GET /orgs/{org}/members, paginated.
func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request, st *State) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	logins := make([]string, 0, len(st.Members))
	for login := range st.Members {
		logins = append(logins, login)
	}
	sort.Strings(logins)
	items := make([]json.RawMessage, 0, len(logins))
	for _, login := range logins {
		m := st.Members[login]
		b, _ := json.Marshal(map[string]any{"login": m.Login, "id": m.ID})
		items = append(items, b)
	}
	s.paginate(w, r, items)
}

// handleMembership serves GET/PUT /orgs/{org}/memberships/{user}.
func (s *Server) handleMembership(w http.ResponseWriter, r *http.Request, st *State, ua, user string) {
	m := st.Members[user]
	switch r.Method {
	case http.MethodGet:
		if m == nil {
			writeErr(w, http.StatusNotFound, "Not Found")
			return
		}
		writeJSON(w, 200, membershipJSON(m.Login, m.Role))
	case http.MethodPut:
		if m == nil {
			// The op only ever promotes an existing operator-owned member.
			writeErr(w, http.StatusNotFound, "Not Found")
			return
		}
		var body struct {
			Role string `json:"role"`
		}
		if !decodeBody(r, &body) || (body.Role != roleAdmin && body.Role != roleMember) {
			writeErr(w, http.StatusUnprocessableEntity, "role must be admin or member")
			return
		}
		m.Role = body.Role
		s.emit(st, ua, "org.update_member", map[string]any{"user": m.Login})
		writeJSON(w, 200, membershipJSON(m.Login, m.Role))
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

// handleOrgRepos serves GET /orgs/{org}/repos (list) and POST (create).
func (s *Server) handleOrgRepos(w http.ResponseWriter, r *http.Request, st *State, ua string) {
	switch r.Method {
	case http.MethodGet:
		names := make([]string, 0, len(st.Repos))
		for name := range st.Repos {
			names = append(names, name)
		}
		sort.Strings(names)
		items := make([]json.RawMessage, 0, len(names))
		for _, name := range names {
			b, _ := json.Marshal(repoJSON(st, st.Repos[name]))
			items = append(items, b)
		}
		s.paginate(w, r, items)
	case http.MethodPost:
		var body struct {
			Name     string `json:"name"`
			Private  *bool  `json:"private"`
			AutoInit bool   `json:"auto_init"`
		}
		if !decodeBody(r, &body) || body.Name == "" {
			writeErr(w, http.StatusUnprocessableEntity, "name is required")
			return
		}
		if _, exists := st.Repos[body.Name]; exists {
			writeErr(w, http.StatusUnprocessableEntity, "name already exists on this account")
			return
		}
		private := true
		if body.Private != nil {
			private = *body.Private
		}
		repo := newRepo(st, body.Name, private)
		st.Repos[body.Name] = repo
		s.emit(st, ua, "repo.create", repoFields(st, repo))
		writeJSON(w, http.StatusCreated, repoJSON(st, repo))
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}
