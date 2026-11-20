package mockokta

import (
	"net/http"
	"strings"
)

// ---- users -------------------------------------------------------------

func (s *Server) routeUsers(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		s.listUsers(w, r, st)
	case len(seg) == 0 && r.Method == http.MethodPost:
		s.createUser(w, r, st, ua)
	case len(seg) == 1 && seg[0] == "me" && r.Method == http.MethodGet:
		// A client credentials token has no user behind it.
		writeErr(w, 404, "E0000007", "Not found: Resource not found: me (User)")
	case len(seg) == 1 && r.Method == http.MethodGet:
		if u := findUser(st, seg[0]); u != nil {
			writeJSON(w, 200, u)
		} else {
			writeErr(w, 404, "E0000007", "user not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		s.deleteUser(w, st, ua, seg[0])
	case len(seg) == 3 && seg[1] == "lifecycle" && r.Method == http.MethodPost:
		s.userLifecycle(w, st, ua, seg[0], seg[2])
	case len(seg) == 2 && seg[1] == "factors" && r.Method == http.MethodGet:
		s.listFactors(w, r, st, seg[0])
	case len(seg) == 2 && seg[1] == "factors" && r.Method == http.MethodPost:
		s.enrollFactor(w, r, st, ua, seg[0])
	case len(seg) == 3 && seg[1] == "factors" && r.Method == http.MethodGet:
		if f := st.Factors[seg[2]]; f != nil && f.userID == resolveUserID(st, seg[0]) {
			writeJSON(w, 200, f)
		} else {
			writeErr(w, 404, "E0000007", "factor not found")
		}
	case len(seg) == 3 && seg[1] == "factors" && r.Method == http.MethodDelete:
		s.deleteFactor(w, st, ua, seg[0], seg[2])
	case len(seg) == 2 && seg[1] == "roles" && r.Method == http.MethodGet:
		s.listUserRoles(w, r, st, seg[0])
	case len(seg) == 2 && seg[1] == "roles" && r.Method == http.MethodPost:
		s.assignRole(w, r, st, ua, seg[0])
	case len(seg) == 3 && seg[1] == "roles" && r.Method == http.MethodDelete:
		s.revokeRole(w, st, ua, seg[0], seg[2])
	default:
		writeErr(w, 404, "E0000007", "user route not found")
	}
}

func findUser(st *State, idOrLogin string) *User {
	if u := st.Users[idOrLogin]; u != nil {
		return u
	}
	for _, u := range st.Users {
		if u.Profile.Login == idOrLogin {
			return u
		}
	}
	return nil
}

func resolveUserID(st *State, idOrLogin string) string {
	if u := findUser(st, idOrLogin); u != nil {
		return u.ID
	}
	return idOrLogin
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, st *State) {
	search := queryParam(r, "search")
	filter := queryParam(r, "filter")
	prefix := swValue(search, "profile.login")
	activeOnly := strings.Contains(search+filter, `status eq "ACTIVE"`)
	var out []*User
	for _, u := range sortedUsers(st.Users) {
		if prefix != "" && !hasPrefix(u.Profile.Login, prefix) {
			continue
		}
		if activeOnly && u.Status != statusActive {
			continue
		}
		out = append(out, u)
	}
	items := make([]jsonItem, 0, len(out))
	for _, u := range out {
		items = append(items, u)
	}
	s.paginate(w, r, toRaw(items))
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, st *State, ua string) {
	var body struct {
		Profile UserProfile `json:"profile"`
	}
	if !decodeBody(r, &body) || body.Profile.Login == "" {
		writeErr(w, 400, "E0000001", "a login is required")
		return
	}
	for _, u := range st.Users {
		if u.Profile.Login == body.Profile.Login {
			writeErr(w, 400, "E0000001", "login already exists: "+body.Profile.Login)
			return
		}
	}
	u := &User{ID: st.newID("00u"), Status: statusActive, Created: s.now().UTC(), Profile: body.Profile}
	if u.Profile.Email == "" {
		u.Profile.Email = u.Profile.Login
	}
	st.Users[u.ID] = u
	s.emit(st, ua, "user.lifecycle.create", "Create okta user", userTarget(u))
	writeJSON(w, 200, u)
}

func (s *Server) deleteUser(w http.ResponseWriter, st *State, ua, idOrLogin string) {
	u := findUser(st, idOrLogin)
	if u == nil {
		writeErr(w, 404, "E0000007", "user not found")
		return
	}
	// Okta refuses to delete an active user; it must be deactivated first.
	if u.Status == statusActive {
		writeErr(w, 400, "E0000001", "cannot delete an active user; deactivate first")
		return
	}
	for id, f := range st.Factors {
		if f.userID == u.ID {
			delete(st.Factors, id)
		}
	}
	for id, g := range st.Roles {
		if g.userID == u.ID {
			delete(st.Roles, id)
		}
	}
	delete(st.Users, u.ID)
	s.emit(st, ua, "user.lifecycle.delete", "Delete Okta user", userTarget(u))
	writeJSON(w, 204, nil)
}

func (s *Server) userLifecycle(w http.ResponseWriter, st *State, ua, idOrLogin, action string) {
	u := findUser(st, idOrLogin)
	if u == nil {
		writeErr(w, 404, "E0000007", "user not found")
		return
	}
	switch action {
	case "deactivate":
		if u.Status != "DEPROVISIONED" {
			u.Status = "DEPROVISIONED"
			s.emit(st, ua, "user.lifecycle.deactivate", "Deactivate Okta user", userTarget(u))
		}
		writeJSON(w, 200, map[string]any{})
	case "reset_factors":
		for id, f := range st.Factors {
			if f.userID == u.ID {
				delete(st.Factors, id)
			}
		}
		u.factorsReset = true
		s.emit(st, ua, "user.mfa.factor.reset_all", "Reset all factors for user", userTarget(u))
		writeJSON(w, 200, map[string]any{})
	default:
		writeErr(w, 400, "E0000001", "unknown user lifecycle action: "+action)
	}
}

// ---- factors -----------------------------------------------------------

func (s *Server) listFactors(w http.ResponseWriter, r *http.Request, st *State, idOrLogin string) {
	uid := resolveUserID(st, idOrLogin)
	var items []jsonItem
	for _, f := range sortedFactors(st.Factors) {
		if f.userID == uid {
			items = append(items, f)
		}
	}
	writeJSON(w, 200, rawArray(items))
}

func (s *Server) enrollFactor(w http.ResponseWriter, r *http.Request, st *State, ua, idOrLogin string) {
	u := findUser(st, idOrLogin)
	if u == nil {
		writeErr(w, 404, "E0000007", "user not found")
		return
	}
	if u.Status != statusActive {
		writeErr(w, 400, "E0000001", "user is not active")
		return
	}
	var body struct {
		FactorType string        `json:"factorType"`
		Provider   string        `json:"provider"`
		Profile    FactorProfile `json:"profile"`
	}
	if !decodeBody(r, &body) {
		writeErr(w, 400, "E0000001", "a factor body is required")
		return
	}
	f := &Factor{ID: st.newID("ufs"), FactorType: "token:software:totp", Provider: "FIDO",
		Status: statusActive, Profile: body.Profile, userID: u.ID}
	if body.FactorType != "" {
		f.FactorType = body.FactorType
	}
	st.Factors[f.ID] = f
	u.factorsReset = false
	s.emit(st, ua, "user.mfa.factor.activate", "User set up MFA factor", userTarget(u),
		target{ID: f.ID, Type: "AuthenticatorEnrollment", DisplayName: f.FactorType})
	writeJSON(w, 200, f)
}

func (s *Server) deleteFactor(w http.ResponseWriter, st *State, ua, idOrLogin, fid string) {
	uid := resolveUserID(st, idOrLogin)
	f := st.Factors[fid]
	if f == nil || f.userID != uid {
		writeErr(w, 404, "E0000007", "factor not found")
		return
	}
	delete(st.Factors, fid)
	tgts := []target{{ID: fid, Type: "AuthenticatorEnrollment", DisplayName: f.FactorType}}
	if u := st.Users[uid]; u != nil {
		tgts = append([]target{userTarget(u)}, tgts...)
	}
	s.emit(st, ua, "user.mfa.factor.deactivate", "Reset factor for user", tgts...)
	writeJSON(w, 204, nil)
}

// ---- roles -------------------------------------------------------------

func (s *Server) listUserRoles(w http.ResponseWriter, r *http.Request, st *State, idOrLogin string) {
	uid := resolveUserID(st, idOrLogin)
	var items []jsonItem
	for _, g := range sortedRoles(st.Roles) {
		if g.userID == uid {
			items = append(items, g)
		}
	}
	writeJSON(w, 200, rawArray(items))
}

func (s *Server) assignRole(w http.ResponseWriter, r *http.Request, st *State, ua, idOrLogin string) {
	u := findUser(st, idOrLogin)
	if u == nil {
		writeErr(w, 404, "E0000007", "user not found")
		return
	}
	var body struct {
		Type string `json:"type"`
	}
	if !decodeBody(r, &body) || body.Type == "" {
		writeErr(w, 400, "E0000001", "a role type is required")
		return
	}
	for _, g := range st.Roles {
		if g.userID == u.ID && g.Type == body.Type {
			writeErr(w, 400, "E0000001", "role already assigned")
			return
		}
	}
	g := &RoleAssignment{ID: st.newID("ra"), Type: body.Type, Status: statusActive, userID: u.ID}
	st.Roles[g.ID] = g
	s.emit(st, ua, "user.account.privilege.grant", "Grant user privilege", userTarget(u),
		target{ID: g.ID, Type: "RoleAssignment", DisplayName: g.Type})
	writeJSON(w, 200, g)
}

func (s *Server) revokeRole(w http.ResponseWriter, st *State, ua, idOrLogin, rid string) {
	uid := resolveUserID(st, idOrLogin)
	g := st.Roles[rid]
	if g == nil || g.userID != uid {
		writeErr(w, 404, "E0000007", "role assignment not found")
		return
	}
	delete(st.Roles, rid)
	tgts := []target{{ID: rid, Type: "RoleAssignment", DisplayName: g.Type}}
	if u := st.Users[uid]; u != nil {
		tgts = append([]target{userTarget(u)}, tgts...)
	}
	s.emit(st, ua, "user.account.privilege.revoke", "Revoke user privilege", tgts...)
	writeJSON(w, 204, nil)
}

// ---- groups (marker) ---------------------------------------------------

func (s *Server) routeGroups(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		q := queryParam(r, "q")
		var items []jsonItem
		for _, g := range sortedGroups(st.Groups) {
			if q == "" || strings.Contains(g.Profile.Name, q) {
				items = append(items, g)
			}
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Profile GroupProfile `json:"profile"`
		}
		if !decodeBody(r, &body) || body.Profile.Name == "" {
			writeErr(w, 400, "E0000001", "a group name is required")
			return
		}
		for _, g := range st.Groups {
			if g.Profile.Name == body.Profile.Name {
				writeErr(w, 400, "E0000001", "group name already exists")
				return
			}
		}
		g := &Group{ID: st.newID("00g"), Type: "OKTA_GROUP", Profile: body.Profile}
		st.Groups[g.ID] = g
		s.emit(st, ua, "group.lifecycle.create", "Add group", target{ID: g.ID, Type: "UserGroup", DisplayName: g.Profile.Name})
		writeJSON(w, 200, g)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if g := st.Groups[seg[0]]; g != nil {
			writeJSON(w, 200, g)
		} else {
			writeErr(w, 404, "E0000007", "group not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		g := st.Groups[seg[0]]
		if g == nil {
			writeErr(w, 404, "E0000007", "group not found")
			return
		}
		delete(st.Groups, g.ID)
		s.emit(st, ua, "group.lifecycle.delete", "Delete group", target{ID: g.ID, Type: "UserGroup", DisplayName: g.Profile.Name})
		writeJSON(w, 204, nil)
	default:
		writeErr(w, 404, "E0000007", "group route not found")
	}
}

func userTarget(u *User) target {
	return target{ID: u.ID, Type: "User", AlternateID: u.Profile.Login, DisplayName: u.Profile.Login}
}

// swValue extracts the value X from a SCIM-style `<field> sw "X"` clause.
func swValue(expr, field string) string {
	i := strings.Index(expr, field+" sw \"")
	if i < 0 {
		return ""
	}
	rest := expr[i+len(field)+len(" sw \""):]
	j := strings.Index(rest, "\"")
	if j < 0 {
		return ""
	}
	return rest[:j]
}
