package mockokta

import (
	"net/http"
)

// ---- zones -------------------------------------------------------------

func (s *Server) routeZones(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		name := queryParam(r, "filter")
		for _, z := range sortedZones(st.Zones) {
			if name != "" && !contains(name, z.Name) {
				continue
			}
			items = append(items, z)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name     string        `json:"name"`
			Type     string        `json:"type"`
			Gateways []ZoneAddress `json:"gateways"`
		}
		if !decodeBody(r, &body) || body.Name == "" {
			writeErr(w, 400, "E0000001", "a zone name is required")
			return
		}
		for _, z := range st.Zones {
			if z.Name == body.Name {
				writeErr(w, 400, "E0000001", "zone name already exists")
				return
			}
		}
		z := &Zone{ID: st.newID("nzo"), Name: body.Name, Status: statusActive, Type: "IP", Gateways: body.Gateways}
		if body.Type != "" {
			z.Type = body.Type
		}
		st.Zones[z.ID] = z
		s.emit(st, ua, "zone.create", "Create network zone", target{ID: z.ID, Type: "NetworkZone", DisplayName: z.Name})
		writeJSON(w, 200, z)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if z := st.Zones[seg[0]]; z != nil {
			writeJSON(w, 200, z)
		} else {
			writeErr(w, 404, "E0000007", "zone not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		z := st.Zones[seg[0]]
		if z == nil {
			writeErr(w, 404, "E0000007", "zone not found")
			return
		}
		if z.Status == statusActive {
			writeErr(w, 400, "E0000001", "cannot delete an active zone; deactivate first")
			return
		}
		delete(st.Zones, z.ID)
		s.emit(st, ua, "zone.delete", "Delete network zone", target{ID: z.ID, Type: "NetworkZone", DisplayName: z.Name})
		writeJSON(w, 204, nil)
	case len(seg) == 3 && seg[1] == "lifecycle" && r.Method == http.MethodPost:
		z := st.Zones[seg[0]]
		if z == nil {
			writeErr(w, 404, "E0000007", "zone not found")
			return
		}
		switch seg[2] {
		case "deactivate":
			if z.Status != statusInactive {
				z.Status = statusInactive
				s.emit(st, ua, "zone.deactivate", "Deactivate network zone", target{ID: z.ID, Type: "NetworkZone", DisplayName: z.Name})
			}
			writeJSON(w, 200, z)
		case "activate":
			if z.Status != statusActive {
				z.Status = statusActive
				s.emit(st, ua, "zone.activate", "Activate network zone", target{ID: z.ID, Type: "NetworkZone", DisplayName: z.Name})
			}
			writeJSON(w, 200, z)
		default:
			writeErr(w, 400, "E0000001", "unknown zone lifecycle action")
		}
	default:
		writeErr(w, 404, "E0000007", "zone route not found")
	}
}

// ---- idps --------------------------------------------------------------

func (s *Server) routeIdps(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		for _, i := range sortedIdps(st.IdPs) {
			items = append(items, i)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if !decodeBody(r, &body) || body.Name == "" {
			writeErr(w, 400, "E0000001", "an idp name is required")
			return
		}
		for _, i := range st.IdPs {
			if i.Name == body.Name {
				writeErr(w, 400, "E0000001", "idp name already exists")
				return
			}
		}
		idp := &IdP{ID: st.newID("0oa"), Name: body.Name, Type: "SAML2", Status: statusActive}
		if body.Type != "" {
			idp.Type = body.Type
		}
		st.IdPs[idp.ID] = idp
		s.emit(st, ua, "system.idp.lifecycle.create", "Create identity provider", target{ID: idp.ID, Type: "IdentityProvider", DisplayName: idp.Name})
		writeJSON(w, 200, idp)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if idp := st.IdPs[seg[0]]; idp != nil {
			writeJSON(w, 200, idp)
		} else {
			writeErr(w, 404, "E0000007", "idp not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		idp := st.IdPs[seg[0]]
		if idp == nil {
			writeErr(w, 404, "E0000007", "idp not found")
			return
		}
		if idp.Status == statusActive {
			writeErr(w, 400, "E0000001", "cannot delete an active idp; deactivate first")
			return
		}
		delete(st.IdPs, idp.ID)
		s.emit(st, ua, "system.idp.lifecycle.delete", "Delete identity provider", target{ID: idp.ID, Type: "IdentityProvider", DisplayName: idp.Name})
		writeJSON(w, 204, nil)
	case len(seg) == 3 && seg[1] == "lifecycle" && seg[2] == "deactivate" && r.Method == http.MethodPost:
		idp := st.IdPs[seg[0]]
		if idp == nil {
			writeErr(w, 404, "E0000007", "idp not found")
			return
		}
		if idp.Status != statusInactive {
			idp.Status = statusInactive
			s.emit(st, ua, "system.idp.lifecycle.deactivate", "Deactivate identity provider", target{ID: idp.ID, Type: "IdentityProvider", DisplayName: idp.Name})
		}
		writeJSON(w, 200, idp)
	default:
		writeErr(w, 404, "E0000007", "idp route not found")
	}
}

// ---- apps and grants ---------------------------------------------------

func (s *Server) routeApps(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		for _, a := range sortedApps(st.Apps) {
			items = append(items, a)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Label string `json:"label"`
		}
		if !decodeBody(r, &body) || body.Label == "" {
			writeErr(w, 400, "E0000001", "an app label is required")
			return
		}
		for _, a := range st.Apps {
			if a.Label == body.Label {
				writeErr(w, 400, "E0000001", "app label already exists")
				return
			}
		}
		a := &App{ID: st.newID("0oa"), Name: "oidc_client", Label: body.Label, Status: statusActive, SignOnMode: "OPENID_CONNECT"}
		st.Apps[a.ID] = a
		s.emit(st, ua, "application.lifecycle.create", "Create application", appTarget(a))
		s.emit(st, ua, "app.oauth2.client.lifecycle.create", "Create OAuth client", appTarget(a))
		// The response carries a client secret, which the provider must use
		// once and never journal.
		writeJSON(w, 200, map[string]any{
			"id": a.ID, "name": a.Name, "label": a.Label, "status": a.Status, "signOnMode": a.SignOnMode,
			"credentials": map[string]any{"oauthClient": map[string]any{
				"client_id": "0oaclient" + a.ID, "client_secret": "sECReT-" + a.ID + "-do-not-log"}},
		})
	case len(seg) == 1 && r.Method == http.MethodGet:
		if a := st.Apps[seg[0]]; a != nil {
			writeJSON(w, 200, a)
		} else {
			writeErr(w, 404, "E0000007", "app not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		a := st.Apps[seg[0]]
		if a == nil {
			writeErr(w, 404, "E0000007", "app not found")
			return
		}
		if a.Status == statusActive {
			writeErr(w, 400, "E0000001", "cannot delete an active app; deactivate first")
			return
		}
		for id, g := range st.Grants {
			if g.appID == a.ID {
				delete(st.Grants, id)
			}
		}
		delete(st.Apps, a.ID)
		s.emit(st, ua, "application.lifecycle.delete", "Delete application", appTarget(a))
		writeJSON(w, 204, nil)
	case len(seg) == 3 && seg[1] == "lifecycle" && seg[2] == "deactivate" && r.Method == http.MethodPost:
		a := st.Apps[seg[0]]
		if a == nil {
			writeErr(w, 404, "E0000007", "app not found")
			return
		}
		if a.Status != statusInactive {
			a.Status = statusInactive
			s.emit(st, ua, "application.lifecycle.deactivate", "Deactivate application", appTarget(a))
		}
		writeJSON(w, 200, a)
	case len(seg) == 2 && seg[1] == "grants" && r.Method == http.MethodGet:
		var items []jsonItem
		for _, g := range sortedGrants(st.Grants) {
			if g.appID == seg[0] {
				items = append(items, g)
			}
		}
		writeJSON(w, 200, rawArray(items))
	case len(seg) == 2 && seg[1] == "grants" && r.Method == http.MethodPost:
		a := st.Apps[seg[0]]
		if a == nil {
			writeErr(w, 404, "E0000007", "app not found")
			return
		}
		var body struct {
			ScopeID string `json:"scopeId"`
		}
		if !decodeBody(r, &body) || body.ScopeID == "" {
			writeErr(w, 400, "E0000001", "a scopeId is required")
			return
		}
		for _, g := range st.Grants {
			if g.appID == a.ID && g.Scopeid == body.ScopeID {
				writeErr(w, 400, "E0000001", "scope already granted")
				return
			}
		}
		g := &AppGrant{ID: st.newID("oag"), Scopeid: body.ScopeID, Status: statusActive, appID: a.ID}
		st.Grants[g.ID] = g
		s.emit(st, ua, "app.oauth2.client.privilege.grant", "Grant app OAuth scope", appTarget(a),
			target{ID: g.ID, Type: "OAuth2ScopeConsentGrant", DisplayName: g.Scopeid})
		writeJSON(w, 200, g)
	case len(seg) == 3 && seg[1] == "grants" && r.Method == http.MethodDelete:
		g := st.Grants[seg[2]]
		if g == nil || g.appID != seg[0] {
			writeErr(w, 404, "E0000007", "grant not found")
			return
		}
		delete(st.Grants, g.ID)
		tgts := []target{{ID: g.ID, Type: "OAuth2ScopeConsentGrant", DisplayName: g.Scopeid}}
		if a := st.Apps[seg[0]]; a != nil {
			tgts = append([]target{appTarget(a)}, tgts...)
		}
		s.emit(st, ua, "app.oauth2.client.privilege.revoke", "Revoke app OAuth scope", tgts...)
		writeJSON(w, 204, nil)
	default:
		writeErr(w, 404, "E0000007", "app route not found")
	}
}

func appTarget(a *App) target {
	return target{ID: a.ID, Type: "AppInstance", AlternateID: a.Name, DisplayName: a.Label}
}

// ---- policies and rules ------------------------------------------------

func (s *Server) routePolicies(w http.ResponseWriter, r *http.Request, st *State, ua string, seg []string) {
	switch {
	case len(seg) == 0 && r.Method == http.MethodGet:
		var items []jsonItem
		for _, p := range sortedPolicies(st.Policies) {
			items = append(items, p)
		}
		s.paginate(w, r, toRaw(items))
	case len(seg) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if !decodeBody(r, &body) || body.Name == "" {
			writeErr(w, 400, "E0000001", "a policy name is required")
			return
		}
		for _, p := range st.Policies {
			if p.Name == body.Name {
				writeErr(w, 400, "E0000001", "policy name already exists")
				return
			}
		}
		p := &Policy{ID: st.newID("rst"), Name: body.Name, Type: "ACCESS_POLICY", Status: statusActive}
		if body.Type != "" {
			p.Type = body.Type
		}
		st.Policies[p.ID] = p
		s.emit(st, ua, "policy.lifecycle.create", "Create policy", target{ID: p.ID, Type: "PolicyEntity", DisplayName: p.Name})
		writeJSON(w, 200, p)
	case len(seg) == 1 && r.Method == http.MethodGet:
		if p := st.Policies[seg[0]]; p != nil {
			writeJSON(w, 200, p)
		} else {
			writeErr(w, 404, "E0000007", "policy not found")
		}
	case len(seg) == 1 && r.Method == http.MethodDelete:
		p := st.Policies[seg[0]]
		if p == nil {
			writeErr(w, 404, "E0000007", "policy not found")
			return
		}
		for id, rule := range st.Rules {
			if rule.policyID == p.ID {
				delete(st.Rules, id)
			}
		}
		delete(st.Policies, p.ID)
		s.emit(st, ua, "policy.lifecycle.delete", "Delete policy", target{ID: p.ID, Type: "PolicyEntity", DisplayName: p.Name})
		writeJSON(w, 204, nil)
	case len(seg) == 2 && seg[1] == "rules" && r.Method == http.MethodGet:
		var items []jsonItem
		for _, rule := range sortedRules(st.Rules) {
			if rule.policyID == seg[0] {
				items = append(items, ruleView(rule))
			}
		}
		writeJSON(w, 200, rawArray(items))
	case len(seg) == 2 && seg[1] == "rules" && r.Method == http.MethodPost:
		p := st.Policies[seg[0]]
		if p == nil {
			writeErr(w, 404, "E0000007", "policy not found")
			return
		}
		var body struct {
			Name    string `json:"name"`
			Actions struct {
				AppSignOn struct {
					VerificationMethod struct {
						FactorMode string `json:"factorMode"`
					} `json:"verificationMethod"`
				} `json:"appSignOn"`
			} `json:"actions"`
		}
		if !decodeBody(r, &body) || body.Name == "" {
			writeErr(w, 400, "E0000001", "a rule name is required")
			return
		}
		rule := &PolicyRule{ID: st.newID("rul"), Name: body.Name, Status: statusActive, RequireFactor: true, policyID: p.ID}
		if body.Actions.AppSignOn.VerificationMethod.FactorMode == "1FA" {
			rule.RequireFactor = false
		}
		st.Rules[rule.ID] = rule
		s.emit(st, ua, "policy.rule.add", "Add policy rule", target{ID: rule.ID, Type: "PolicyRule", DisplayName: rule.Name})
		writeJSON(w, 200, ruleView(rule))
	case len(seg) == 3 && seg[1] == "rules" && r.Method == http.MethodGet:
		if rule := st.Rules[seg[2]]; rule != nil && rule.policyID == seg[0] {
			writeJSON(w, 200, ruleView(rule))
		} else {
			writeErr(w, 404, "E0000007", "rule not found")
		}
	case len(seg) == 3 && seg[1] == "rules" && r.Method == http.MethodPut:
		rule := st.Rules[seg[2]]
		if rule == nil || rule.policyID != seg[0] {
			writeErr(w, 404, "E0000007", "rule not found")
			return
		}
		var body struct {
			Actions struct {
				AppSignOn struct {
					VerificationMethod struct {
						FactorMode string `json:"factorMode"`
					} `json:"verificationMethod"`
				} `json:"appSignOn"`
			} `json:"actions"`
		}
		if !decodeBody(r, &body) {
			writeErr(w, 400, "E0000001", "a rule body is required")
			return
		}
		rule.RequireFactor = body.Actions.AppSignOn.VerificationMethod.FactorMode != "1FA"
		s.emit(st, ua, "policy.rule.update", "Update policy rule", target{ID: rule.ID, Type: "PolicyRule", DisplayName: rule.Name})
		writeJSON(w, 200, ruleView(rule))
	case len(seg) == 3 && seg[1] == "rules" && r.Method == http.MethodDelete:
		rule := st.Rules[seg[2]]
		if rule == nil || rule.policyID != seg[0] {
			writeErr(w, 404, "E0000007", "rule not found")
			return
		}
		delete(st.Rules, rule.ID)
		s.emit(st, ua, "policy.rule.delete", "Delete policy rule", target{ID: rule.ID, Type: "PolicyRule", DisplayName: rule.Name})
		writeJSON(w, 204, nil)
	default:
		writeErr(w, 404, "E0000007", "policy route not found")
	}
}

// ruleView renders a rule with its MFA requirement in the Okta action shape,
// so the provider reads the requirement back the way it wrote it.
func ruleView(rule *PolicyRule) map[string]any {
	mode := "2FA"
	if !rule.RequireFactor {
		mode = "1FA"
	}
	return map[string]any{
		"id": rule.ID, "name": rule.Name, "status": rule.Status,
		"actions": map[string]any{"appSignOn": map[string]any{
			"verificationMethod": map[string]any{"factorMode": mode}}},
	}
}

func contains(haystack, needle string) bool {
	return needle != "" && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
