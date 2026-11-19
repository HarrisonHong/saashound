package mockgithub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
)

// handleRepo serves GET/PATCH/DELETE /repos/{org}/{repo}.
func (s *Server) handleRepo(w http.ResponseWriter, r *http.Request, st *State, ua, name string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, repoJSON(st, repo))
	case http.MethodPatch:
		s.patchRepo(w, r, st, ua, repo)
	case http.MethodDelete:
		delete(st.Repos, name)
		s.emit(st, ua, "repo.destroy", repoFields(st, repo))
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func (s *Server) patchRepo(w http.ResponseWriter, r *http.Request, st *State, ua string, repo *Repo) {
	var body struct {
		Private             *bool   `json:"private"`
		Visibility          *string `json:"visibility"`
		SecurityAndAnalysis *struct {
			SecretScanning *struct {
				Status string `json:"status"`
			} `json:"secret_scanning"`
			SecretScanningPushProtection *struct {
				Status string `json:"status"`
			} `json:"secret_scanning_push_protection"`
		} `json:"security_and_analysis"`
	}
	if !decodeBody(r, &body) {
		writeErr(w, http.StatusUnprocessableEntity, "invalid body")
		return
	}
	if body.Private != nil || body.Visibility != nil {
		newPriv := repo.Private
		if body.Private != nil {
			newPriv = *body.Private
		}
		if body.Visibility != nil {
			newPriv = *body.Visibility != "public"
		}
		if newPriv != repo.Private {
			repo.Private = newPriv
			s.emit(st, ua, "repo.access", repoFields(st, repo))
		}
	}
	if sa := body.SecurityAndAnalysis; sa != nil {
		if sa.SecretScanning != nil {
			s.toggleFeature(st, ua, repo, &repo.SecretScanning, sa.SecretScanning.Status, "repository_secret_scanning")
		}
		if sa.SecretScanningPushProtection != nil {
			s.toggleFeature(st, ua, repo, &repo.PushProtection, sa.SecretScanningPushProtection.Status, "repository_secret_scanning_push_protection")
		}
	}
	writeJSON(w, 200, repoJSON(st, repo))
}

// toggleFeature changes a security feature's status if it differs, emitting the
// matching .enable or .disable action.
func (s *Server) toggleFeature(st *State, ua string, r *Repo, cur *string, want, prefix string) {
	if want == "" || want == *cur {
		return
	}
	action := prefix + ".enable"
	if want == statusDisabled {
		action = prefix + ".disable"
	}
	*cur = want
	s.emit(st, ua, action, repoFields(st, r))
}

// handleKeys serves /repos/{org}/{repo}/keys[/{id}].
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, st *State, ua, name string, rest []string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		var body struct {
			Title string `json:"title"`
			Key   string `json:"key"`
		}
		if !decodeBody(r, &body) || body.Title == "" || body.Key == "" {
			writeErr(w, http.StatusUnprocessableEntity, "title and key are required")
			return
		}
		k := &Key{ID: st.newID(), Title: body.Title, Key: body.Key}
		repo.Keys[k.ID] = k
		s.emit(st, ua, "public_key.create", repoFields(st, repo))
		writeJSON(w, http.StatusCreated, map[string]any{"id": k.ID, "title": k.Title, "key": k.Key})
	case len(rest) == 0 && r.Method == http.MethodGet:
		s.paginate(w, r, keyList(repo))
	case len(rest) == 1 && r.Method == http.MethodGet:
		if k := repo.Keys[parseID(rest[0])]; k != nil {
			writeJSON(w, 200, map[string]any{"id": k.ID, "title": k.Title, "key": k.Key})
		} else {
			writeErr(w, http.StatusNotFound, "Not Found")
		}
	case len(rest) == 1 && r.Method == http.MethodDelete:
		id := parseID(rest[0])
		if _, ok := repo.Keys[id]; !ok {
			writeErr(w, http.StatusNotFound, "Not Found")
			return
		}
		delete(repo.Keys, id)
		s.emit(st, ua, "public_key.delete", repoFields(st, repo))
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func keyList(repo *Repo) []json.RawMessage {
	ids := make([]int64, 0, len(repo.Keys))
	for id := range repo.Keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		k := repo.Keys[id]
		b, _ := json.Marshal(map[string]any{"id": k.ID, "title": k.Title, "key": k.Key})
		out = append(out, b)
	}
	return out
}

// handleHooks serves /repos/{org}/{repo}/hooks[/{id}].
func (s *Server) handleHooks(w http.ResponseWriter, r *http.Request, st *State, ua, name string, rest []string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name   string `json:"name"`
			Active bool   `json:"active"`
			Config struct {
				URL string `json:"url"`
			} `json:"config"`
		}
		if !decodeBody(r, &body) || body.Config.URL == "" {
			writeErr(w, http.StatusUnprocessableEntity, "config.url is required")
			return
		}
		h := &Hook{ID: st.newID(), Name: body.Name, URL: body.Config.URL, Active: body.Active}
		if h.Name == "" {
			h.Name = "web"
		}
		repo.Hooks[h.ID] = h
		s.emit(st, ua, "hook.create", repoFields(st, repo))
		writeJSON(w, http.StatusCreated, hookJSON(h))
	case len(rest) == 0 && r.Method == http.MethodGet:
		s.paginate(w, r, hookList(repo))
	case len(rest) == 1 && r.Method == http.MethodGet:
		if h := repo.Hooks[parseID(rest[0])]; h != nil {
			writeJSON(w, 200, hookJSON(h))
		} else {
			writeErr(w, http.StatusNotFound, "Not Found")
		}
	case len(rest) == 1 && r.Method == http.MethodDelete:
		id := parseID(rest[0])
		if _, ok := repo.Hooks[id]; !ok {
			writeErr(w, http.StatusNotFound, "Not Found")
			return
		}
		delete(repo.Hooks, id)
		s.emit(st, ua, "hook.destroy", repoFields(st, repo))
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func hookJSON(h *Hook) map[string]any {
	return map[string]any{"id": h.ID, "name": h.Name, "active": h.Active,
		"config": map[string]any{"url": h.URL}}
}

func hookList(repo *Repo) []json.RawMessage {
	ids := make([]int64, 0, len(repo.Hooks))
	for id := range repo.Hooks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		out = append(out, mustJSON(hookJSON(repo.Hooks[id])))
	}
	return out
}

// handleCollaborator serves PUT/GET/DELETE /repos/{org}/{repo}/collaborators/{user}.
//
// As on real GitHub, adding a user who is not already a collaborator creates a
// pending repository invitation (201) that the user must accept rather than
// granting access immediately; GET answers 204 only for an accepted
// collaborator. The pending invitation is visible through the invitations
// endpoint, and cleanup cancels it there.
func (s *Server) handleCollaborator(w http.ResponseWriter, r *http.Request, st *State, ua, name, user string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if repo.Collaborators[user] {
			writeNoContent(w)
		} else {
			writeErr(w, http.StatusNotFound, "Not Found")
		}
	case http.MethodPut:
		if repo.Collaborators[user] {
			writeNoContent(w) // already an accepted collaborator
			return
		}
		for id, invitee := range repo.Invitations {
			if invitee == user { // already invited: idempotent, no new event
				writeJSON(w, http.StatusCreated, invitationJSON(id, user))
				return
			}
		}
		id := st.newID()
		repo.Invitations[id] = user
		s.emit(st, ua, "repo.add_member", repoFields(st, repo))
		writeJSON(w, http.StatusCreated, invitationJSON(id, user))
	case http.MethodDelete:
		if repo.Collaborators[user] {
			delete(repo.Collaborators, user)
			s.emit(st, ua, "repo.remove_member", repoFields(st, repo))
		}
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

// handleInvitations serves GET /repos/{org}/{repo}/invitations and
// DELETE /repos/{org}/{repo}/invitations/{id}.
func (s *Server) handleInvitations(w http.ResponseWriter, r *http.Request, st *State, ua, name string, rest []string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		ids := make([]int64, 0, len(repo.Invitations))
		for id := range repo.Invitations {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		items := make([]json.RawMessage, 0, len(ids))
		for _, id := range ids {
			items = append(items, mustJSON(invitationJSON(id, repo.Invitations[id])))
		}
		s.paginate(w, r, items)
	case len(rest) == 1 && r.Method == http.MethodDelete:
		id := parseID(rest[0])
		if _, ok := repo.Invitations[id]; !ok {
			writeErr(w, http.StatusNotFound, "Not Found")
			return
		}
		delete(repo.Invitations, id)
		s.emit(st, ua, "repo.remove_member", repoFields(st, repo))
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func invitationJSON(id int64, login string) map[string]any {
	return map[string]any{"id": id, "invitee": map[string]any{"login": login}}
}

// handleProtection serves /repos/{org}/{repo}/branches/{branch}/protection.
func (s *Server) handleProtection(w http.ResponseWriter, r *http.Request, st *State, ua, name, branch string) {
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	_ = branch // the mock models a single protected branch per repo
	switch r.Method {
	case http.MethodGet:
		if !repo.Protected {
			writeErr(w, http.StatusNotFound, "Branch not protected")
			return
		}
		writeJSON(w, 200, protectionJSON(repo))
	case http.MethodPut:
		var body struct {
			RequiredStatusChecks *struct {
				Contexts []string `json:"contexts"`
			} `json:"required_status_checks"`
		}
		_ = decodeBody(r, &body)
		repo.Protected = true
		repo.ProtectionContexts = nil
		if body.RequiredStatusChecks != nil {
			repo.ProtectionContexts = body.RequiredStatusChecks.Contexts
		}
		s.emit(st, ua, "protected_branch.create", repoFields(st, repo))
		writeJSON(w, 200, protectionJSON(repo))
	case http.MethodDelete:
		if !repo.Protected {
			writeErr(w, http.StatusNotFound, "Branch not protected")
			return
		}
		repo.Protected = false
		repo.ProtectionContexts = nil
		s.emit(st, ua, "protected_branch.destroy", repoFields(st, repo))
		writeNoContent(w)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

func protectionJSON(repo *Repo) map[string]any {
	contexts := repo.ProtectionContexts
	if contexts == nil {
		contexts = []string{}
	}
	return map[string]any{
		"required_status_checks": map[string]any{"strict": false, "contexts": contexts},
		"enforce_admins":         map[string]any{"enabled": true},
	}
}

// handleContents serves GET /repos/{org}/{repo}/contents/{path}: the ownership
// marker file reader's one endpoint.
func (s *Server) handleContents(w http.ResponseWriter, r *http.Request, st *State, name, path string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}
	repo := st.Repos[name]
	if repo == nil {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	content, ok := repo.Contents[path]
	if !ok {
		writeErr(w, http.StatusNotFound, "Not Found")
		return
	}
	// GitHub wraps base64 content at 60 columns; mirror that so the provider's
	// whitespace stripping is exercised.
	encoded := wrap60(base64.StdEncoding.EncodeToString([]byte(content)))
	writeJSON(w, 200, map[string]any{"name": path, "path": path, "type": "file",
		"encoding": "base64", "content": encoded})
}

func wrap60(s string) string {
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && i%60 == 0 {
			out = append(out, '\n')
		}
		out = append(out, c)
	}
	return string(out)
}

func parseID(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
