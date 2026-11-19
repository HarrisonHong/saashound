package mockokta

import (
	"net/http"
)

// routeIam serves the custom-admin-role surface: custom roles, resource sets
// and the bindings that tie a role to a resource set for a member.
func (s *Server) routeIam(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) >= 1 && seg[0] == "roles":
		s.routeIamRoles(w, r, st, ua, seg[1:])
	case len(seg) >= 1 && seg[0] == "resource-sets":
		s.routeResourceSets(w, r, st, ua, seg[1:])
	default:
		writeErr(w, 404, "E0000007", "iam route not found")
	}
}

func (s *Server) routeIamRoles(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		for _, cr := range sortedCustomRoles(st.CustomRoles) {
			items = append(items, cr)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Label       string   `json:"label"`
			Description string   `json:"description"`
			Permissions []string `json:"permissions"`
		}
		if !decodeBody(r, &body) || body.Label == "" {
			writeErr(w, 400, "E0000001", "a role label is required")
			return
		}
		for _, cr := range st.CustomRoles {
			if cr.Label == body.Label {
				writeErr(w, 400, "E0000001", "role label already exists")
				return
			}
		}
		cr := &CustomRole{ID: st.newID("cr"), Label: body.Label, Description: body.Description, Permissions: body.Permissions}
		st.CustomRoles[cr.ID] = cr
		s.emit(st, ua, "iam.role.create", "Create custom admin role", target{ID: cr.ID, Type: "IamCustomRole", DisplayName: cr.Label})
		writeJSON(w, 200, cr)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if cr := st.CustomRoles[seg[0]]; cr != nil {
			writeJSON(w, 200, cr)
		} else {
			writeErr(w, 404, "E0000007", "custom role not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		cr := st.CustomRoles[seg[0]]
		if cr == nil {
			writeErr(w, 404, "E0000007", "custom role not found")
			return
		}
		delete(st.CustomRoles, cr.ID)
		s.emit(st, ua, "iam.role.delete", "Delete custom admin role", target{ID: cr.ID, Type: "IamCustomRole", DisplayName: cr.Label})
		writeJSON(w, 204, nil)
	default:
		writeErr(w, 404, "E0000007", "iam role route not found")
	}
}

func (s *Server) routeResourceSets(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		for _, rs := range sortedResourceSets(st.ResourceSets) {
			items = append(items, rs)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Label       string `json:"label"`
			Description string `json:"description"`
		}
		if !decodeBody(r, &body) || body.Label == "" {
			writeErr(w, 400, "E0000001", "a resource-set label is required")
			return
		}
		for _, rs := range st.ResourceSets {
			if rs.Label == body.Label {
				writeErr(w, 400, "E0000001", "resource-set label already exists")
				return
			}
		}
		rs := &ResourceSet{ID: st.newID("iamrs"), Label: body.Label, Description: body.Description}
		st.ResourceSets[rs.ID] = rs
		s.emit(st, ua, "iam.resourceset.create", "Create resource set", target{ID: rs.ID, Type: "IamResourceSet", DisplayName: rs.Label})
		writeJSON(w, 200, rs)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if rs := st.ResourceSets[seg[0]]; rs != nil {
			writeJSON(w, 200, rs)
		} else {
			writeErr(w, 404, "E0000007", "resource set not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		rs := st.ResourceSets[seg[0]]
		if rs == nil {
			writeErr(w, 404, "E0000007", "resource set not found")
			return
		}
		for id, b := range st.Bindings {
			if b.ResourceSetID == rs.ID {
				delete(st.Bindings, id)
			}
		}
		delete(st.ResourceSets, rs.ID)
		s.emit(st, ua, "iam.resourceset.delete", "Delete resource set", target{ID: rs.ID, Type: "IamResourceSet", DisplayName: rs.Label})
		writeJSON(w, 204, nil)
	case len(seg) == 2 && seg[1] == "bindings" && r.Method == http.MethodGet:
		var items []jsonItem
		for _, b := range sortedBindings(st.Bindings) {
			if b.ResourceSetID == seg[0] {
				items = append(items, b)
			}
		}
		writeJSON(w, 200, rawArray(items))
	case len(seg) == 2 && seg[1] == "bindings" && r.Method == http.MethodPost:
		rs := st.ResourceSets[seg[0]]
		if rs == nil {
			writeErr(w, 404, "E0000007", "resource set not found")
			return
		}
		var body struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		}
		if !decodeBody(r, &body) || body.Role == "" || len(body.Members) == 0 {
			writeErr(w, 400, "E0000001", "a role and at least one member are required")
			return
		}
		member := body.Members[0]
		for _, b := range st.Bindings {
			if b.ResourceSetID == rs.ID && b.Role == body.Role && b.MemberID == member {
				writeErr(w, 400, "E0000001", "binding already exists")
				return
			}
		}
		b := &Binding{ID: st.newID("iab"), Role: body.Role, ResourceSetID: rs.ID, MemberID: member}
		st.Bindings[b.ID] = b
		s.emit(st, ua, "iam.resourceset.bindings.add", "Add resource-set role binding",
			target{ID: rs.ID, Type: "IamResourceSet", DisplayName: rs.Label},
			target{ID: body.Role, Type: "IamCustomRole"})
		writeJSON(w, 200, b)
	case len(seg) == 3 && seg[1] == "bindings" && r.Method == http.MethodDelete:
		// DELETE /iam/resource-sets/{id}/bindings/{roleId}
		rs := st.ResourceSets[seg[0]]
		if rs == nil {
			writeErr(w, 404, "E0000007", "resource set not found")
			return
		}
		removed := false
		for id, b := range st.Bindings {
			if b.ResourceSetID == rs.ID && b.Role == seg[2] {
				delete(st.Bindings, id)
				removed = true
			}
		}
		if !removed {
			writeErr(w, 404, "E0000007", "binding not found")
			return
		}
		s.emit(st, ua, "iam.resourceset.bindings.delete", "Delete resource-set role binding",
			target{ID: rs.ID, Type: "IamResourceSet", DisplayName: rs.Label},
			target{ID: seg[2], Type: "IamCustomRole"})
		writeJSON(w, 204, nil)
	default:
		writeErr(w, 404, "E0000007", "resource set route not found")
	}
}
