package fake

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/secret"
)

// Op names and resource types.
const (
	opUserCreate     = "fake.user.create"
	opFactorEnroll   = "fake.factor.enroll"
	opRoleAssign     = "fake.role.assign"
	opZoneCreate     = "fake.zone.create"
	opZoneDeactivate = "fake.zone.deactivate"
	opOrgSettingSet  = "fake.org_setting.set"

	resUser       = "fake.user"
	resFactor     = "fake.factor"
	resRoleGrant  = "fake.role_grant"
	resZone       = "fake.zone"
	resOrgSetting = "fake.org_setting"
)

var adminRoles = []string{"SUPER_ADMIN", "ORG_ADMIN", "HELP_DESK_ADMIN", "READ_ONLY_ADMIN"}

var orgSettings = []string{"session.mfa_required", "password.lockout"}

func allScopes() []string {
	return []string{"fake.logs.read", "fake.org.manage", "fake.roles.manage", "fake.users.manage", "fake.zones.manage"}
}

func tenantOf(c *provider.Call) (*Tenant, error) {
	t, ok := c.Tenant.(*Tenant)
	if !ok {
		return nil, fmt.Errorf("fake op called with a %T tenant", c.Tenant)
	}
	return t, nil
}

// generate returns n random bytes as an inert, in-memory-only secret.
func generate(n int) (secret.Value, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return secret.Value{}, err
	}
	return secret.New(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

func userTarget(u *User) eventTarget {
	return eventTarget{ID: u.ID, Type: "User", AlternateID: u.Login, DisplayName: u.DisplayName}
}

// --- fake.user.create ---------------------------------------------------

type userCreate struct{}

func (userCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opUserCreate,
		Summary:  "Create an active synthetic user",
		Kind:     provider.KindCreate,
		Resource: resUser,
		Params: []provider.Param{
			{Name: "display_name", Type: provider.ParamString, Example: "Synthetic victim", Doc: "Display name; defaults to the object name."},
		},
		Outputs:     []string{"login"},
		Scopes:      []string{"fake.users.manage"},
		Events:      []string{"user.lifecycle.create"},
		UndoEvents:  []string{"user.lifecycle.deactivate", "user.lifecycle.delete"},
		Request:     "POST /api/v1/users?activate=true",
		UndoSummary: "deactivate + delete user",
		GoneCheck:   "GET /api/v1/users/{id} -> 404",
		Note:        "password generated and discarded",
	}
}

func (userCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	// The password exists only in memory for the one call that sets it, so
	// a user left behind by a failed cleanup has no usable credential.
	pw, err := generate(20)
	if err != nil {
		return provider.Result{}, err
	}
	defer pw.Wipe()
	login := c.Name + "@" + c.Target.TestDomain
	display := c.Params["display_name"]
	if display == "" {
		display = c.Name
	}
	var id string
	err = t.call(ctx, "POST", "/api/v1/users?activate=true", func(s *State, e *emitter) error {
		for _, u := range s.Users {
			if u.Name == c.Name || u.Login == login {
				return badRequest("login %s already exists", login)
			}
		}
		u := &User{ID: s.newID("00u"), Name: c.Name, Login: login, DisplayName: display,
			Status: statusActive, PasswordSet: !pw.Empty(), Created: e.now}
		s.Users[u.ID] = u
		id = u.ID
		e.emit("user.lifecycle.create", "Create okta user", userTarget(u))
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id, Outputs: map[string]string{"login": login}}, nil
}

func (userCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	var res provider.Result
	found := false
	err = t.call(ctx, "GET", "/api/v1/users?filter=profile.login+eq+"+c.Name, func(s *State, _ *emitter) error {
		for _, u := range s.Users {
			if u.Name == c.Name { // exact name, never a substring
				res = provider.Result{ID: u.ID, Outputs: map[string]string{"login": u.Login}}
				found = true
			}
		}
		return nil
	})
	return res, found, err
}

func (userCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	return t.call(ctx, "DELETE", "/api/v1/users/"+r.ID, func(s *State, e *emitter) error {
		u, ok := s.Users[r.ID]
		if !ok {
			return notFound("user " + r.ID)
		}
		if u.Status == statusActive {
			u.Status = "DEPROVISIONED"
			e.emit("user.lifecycle.deactivate", "Deactivate Okta user", userTarget(u))
		}
		// Deleting a user removes its factors and role grants, as Okta does.
		for id, f := range s.Factors {
			if f.UserID == u.ID {
				delete(s.Factors, id)
			}
		}
		for id, g := range s.Grants {
			if g.UserID == u.ID {
				delete(s.Grants, id)
			}
		}
		delete(s.Users, u.ID)
		e.emit("user.lifecycle.delete", "Delete Okta user", userTarget(u))
		return nil
	})
}

func (userCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	gone := false
	err = t.call(ctx, "GET", "/api/v1/users/"+r.ID, func(s *State, _ *emitter) error {
		_, exists := s.Users[r.ID]
		gone = !exists
		return nil
	})
	return gone, err
}

// --- fake.factor.enroll -------------------------------------------------

type factorEnroll struct{}

func (factorEnroll) Spec() provider.Spec {
	return provider.Spec{
		Name:     opFactorEnroll,
		Summary:  "Enroll and activate a TOTP factor on a user",
		Kind:     provider.KindCreate,
		Resource: resFactor,
		Params: []provider.Param{
			{Name: "user", Type: provider.ParamRef, Ref: resUser, Required: true, Doc: "The user to enroll."},
		},
		Scopes:      []string{"fake.users.manage"},
		Events:      []string{"user.mfa.factor.activate"},
		UndoEvents:  []string{"user.mfa.factor.deactivate"},
		Request:     "POST /api/v1/users/{user}/factors?activate=true",
		UndoSummary: "delete factor",
		GoneCheck:   "GET /api/v1/users/{user}/factors/{id} -> 404",
		Note:        "seed used once to activate, then discarded",
	}
}

func (factorEnroll) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	// The TOTP seed activates the factor and is then dropped: a factor left
	// behind cannot generate a code for anyone.
	seed, err := generate(20)
	if err != nil {
		return provider.Result{}, err
	}
	defer seed.Wipe()
	userID := c.Params["user"]
	var id string
	err = t.call(ctx, "POST", "/api/v1/users/"+userID+"/factors?activate=true", func(s *State, e *emitter) error {
		u, ok := s.Users[userID]
		if !ok {
			return notFound("user " + userID)
		}
		if u.Status != statusActive {
			return badRequest("user %s is not active", userID)
		}
		if seed.Empty() {
			return badRequest("activation requires a passcode")
		}
		for _, f := range s.Factors {
			if f.Name == c.Name {
				return badRequest("factor %s already exists", c.Name)
			}
		}
		f := &Factor{ID: s.newID("mfa"), Name: c.Name, UserID: userID, Type: "token:software:totp", Status: statusActive}
		s.Factors[f.ID] = f
		id = f.ID
		e.emit("user.mfa.factor.activate", "User set up MFA factor", userTarget(u),
			eventTarget{ID: f.ID, Type: "Factor", DisplayName: f.Name})
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id}, nil
}

func (factorEnroll) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	var res provider.Result
	found := false
	err = t.call(ctx, "GET", "/api/v1/users/"+c.Params["user"]+"/factors", func(s *State, _ *emitter) error {
		for _, f := range s.Factors {
			if f.Name == c.Name && f.UserID == c.Params["user"] {
				res, found = provider.Result{ID: f.ID}, true
			}
		}
		return nil
	})
	return res, found, err
}

func (factorEnroll) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	return t.call(ctx, "DELETE", "/api/v1/users/"+c.Params["user"]+"/factors/"+r.ID, func(s *State, e *emitter) error {
		f, ok := s.Factors[r.ID]
		if !ok {
			return notFound("factor " + r.ID)
		}
		delete(s.Factors, f.ID)
		targets := []eventTarget{{ID: f.ID, Type: "Factor", DisplayName: f.Name}}
		if u, ok := s.Users[f.UserID]; ok {
			targets = append([]eventTarget{userTarget(u)}, targets...)
		}
		e.emit("user.mfa.factor.deactivate", "Reset factor for user", targets...)
		return nil
	})
}

func (factorEnroll) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	gone := false
	err = t.call(ctx, "GET", "/api/v1/users/"+c.Params["user"]+"/factors/"+r.ID, func(s *State, _ *emitter) error {
		_, exists := s.Factors[r.ID]
		gone = !exists
		return nil
	})
	return gone, err
}

// --- fake.role.assign ---------------------------------------------------

type roleAssign struct{}

func (roleAssign) Spec() provider.Spec {
	return provider.Spec{
		Name:     opRoleAssign,
		Summary:  "Assign an admin role to a user",
		Kind:     provider.KindCreate,
		Resource: resRoleGrant,
		Params: []provider.Param{
			{Name: "user", Type: provider.ParamRef, Ref: resUser, Required: true, Doc: "The user to grant the role to."},
			{Name: "role", Type: provider.ParamEnum, Enum: adminRoles, Example: "READ_ONLY_ADMIN", Required: true, Doc: "The admin role."},
		},
		Outputs:     []string{"role"},
		Scopes:      []string{"fake.roles.manage"},
		Events:      []string{"user.account.privilege.grant"},
		UndoEvents:  []string{"user.account.privilege.revoke"},
		Request:     "POST /api/v1/users/{user}/roles",
		UndoSummary: "revoke role assignment",
		GoneCheck:   "GET /api/v1/users/{user}/roles/{id} -> 404",
	}
}

func (roleAssign) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	userID, role := c.Params["user"], c.Params["role"]
	var id string
	err = t.call(ctx, "POST", "/api/v1/users/"+userID+"/roles", func(s *State, e *emitter) error {
		u, ok := s.Users[userID]
		if !ok {
			return notFound("user " + userID)
		}
		if !contains(adminRoles, role) {
			return badRequest("unknown role %q", role)
		}
		for _, g := range s.Grants {
			if g.Name == c.Name {
				return badRequest("role assignment %s already exists", c.Name)
			}
		}
		g := &RoleGrant{ID: s.newID("ra"), Name: c.Name, UserID: userID, Role: role}
		s.Grants[g.ID] = g
		id = g.ID
		e.emit("user.account.privilege.grant", "Grant user privilege", userTarget(u),
			eventTarget{ID: g.ID, Type: "RoleAssignment", DisplayName: role})
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id, Outputs: map[string]string{"role": role}}, nil
}

func (roleAssign) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	var res provider.Result
	found := false
	err = t.call(ctx, "GET", "/api/v1/users/"+c.Params["user"]+"/roles", func(s *State, _ *emitter) error {
		for _, g := range s.Grants {
			if g.Name == c.Name && g.UserID == c.Params["user"] {
				res, found = provider.Result{ID: g.ID, Outputs: map[string]string{"role": g.Role}}, true
			}
		}
		return nil
	})
	return res, found, err
}

func (roleAssign) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	return t.call(ctx, "DELETE", "/api/v1/users/"+c.Params["user"]+"/roles/"+r.ID, func(s *State, e *emitter) error {
		g, ok := s.Grants[r.ID]
		if !ok {
			return notFound("role assignment " + r.ID)
		}
		delete(s.Grants, g.ID)
		targets := []eventTarget{{ID: g.ID, Type: "RoleAssignment", DisplayName: g.Role}}
		if u, ok := s.Users[g.UserID]; ok {
			targets = append([]eventTarget{userTarget(u)}, targets...)
		}
		e.emit("user.account.privilege.revoke", "Revoke user privilege", targets...)
		return nil
	})
}

func (roleAssign) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	gone := false
	err = t.call(ctx, "GET", "/api/v1/users/"+c.Params["user"]+"/roles/"+r.ID, func(s *State, _ *emitter) error {
		_, exists := s.Grants[r.ID]
		gone = !exists
		return nil
	})
	return gone, err
}

// --- fake.zone.create ---------------------------------------------------

type zoneCreate struct{}

func (zoneCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opZoneCreate,
		Summary:  "Create an active IP network zone",
		Kind:     provider.KindCreate,
		Resource: resZone,
		Params: []provider.Param{
			{Name: "gateway", Type: provider.ParamString, Example: "203.0.113.0/24", Doc: "Gateway CIDR; defaults to a documentation range."},
		},
		Scopes:      []string{"fake.zones.manage"},
		Events:      []string{"zone.create"},
		UndoEvents:  []string{"zone.delete"},
		Request:     "POST /api/v1/zones",
		UndoSummary: "delete zone",
		GoneCheck:   "GET /api/v1/zones/{id} -> 404",
	}
}

func (zoneCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	gw := c.Params["gateway"]
	if gw == "" {
		gw = "203.0.113.0/24"
	}
	if _, err := netip.ParsePrefix(gw); err != nil {
		return provider.Result{}, fmt.Errorf("gateway %q is not a CIDR: %w", gw, err)
	}
	var id string
	err = t.call(ctx, "POST", "/api/v1/zones", func(s *State, e *emitter) error {
		for _, z := range s.Zones {
			if z.Name == c.Name {
				return badRequest("zone %s already exists", c.Name)
			}
		}
		z := &Zone{ID: s.newID("nzo"), Name: c.Name, Gateway: gw, Status: statusActive}
		s.Zones[z.ID] = z
		id = z.ID
		e.emit("zone.create", "Create network zone", eventTarget{ID: z.ID, Type: "Zone", DisplayName: z.Name})
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id}, nil
}

func (zoneCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	var res provider.Result
	found := false
	err = t.call(ctx, "GET", "/api/v1/zones?filter=name+eq+"+c.Name, func(s *State, _ *emitter) error {
		for _, z := range s.Zones {
			if z.Name == c.Name {
				res, found = provider.Result{ID: z.ID}, true
			}
		}
		return nil
	})
	return res, found, err
}

func (zoneCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	return t.call(ctx, "DELETE", "/api/v1/zones/"+r.ID, func(s *State, e *emitter) error {
		z, ok := s.Zones[r.ID]
		if !ok {
			return notFound("zone " + r.ID)
		}
		delete(s.Zones, z.ID)
		e.emit("zone.delete", "Delete network zone", eventTarget{ID: z.ID, Type: "Zone", DisplayName: z.Name})
		return nil
	})
}

func (zoneCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	gone := false
	err = t.call(ctx, "GET", "/api/v1/zones/"+r.ID, func(s *State, _ *emitter) error {
		_, exists := s.Zones[r.ID]
		gone = !exists
		return nil
	})
	return gone, err
}

// --- fake.zone.deactivate (modify) --------------------------------------

type zoneDeactivate struct{}

type zonePrior struct {
	Status string `json:"status"`
}

func (zoneDeactivate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opZoneDeactivate,
		Summary:  "Deactivate a network zone",
		Kind:     provider.KindModify,
		Resource: resZone,
		Params: []provider.Param{
			{Name: "zone", Type: provider.ParamRef, Ref: resZone, Required: true, Doc: "The zone to deactivate."},
		},
		Scopes:      []string{"fake.zones.manage"},
		Events:      []string{"zone.deactivate"},
		UndoEvents:  []string{"zone.activate"},
		Request:     "POST /api/v1/zones/{zone}/lifecycle/deactivate",
		UndoSummary: "restore the recorded zone status",
		GoneCheck:   "GET /api/v1/zones/{zone} -> status equals the recorded prior",
	}
}

func (zoneDeactivate) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	t, err := tenantOf(c)
	if err != nil {
		return nil, err
	}
	var prior zonePrior
	err = t.call(ctx, "GET", "/api/v1/zones/"+c.Params["zone"], func(s *State, _ *emitter) error {
		z, ok := s.Zones[c.Params["zone"]]
		if !ok {
			return notFound("zone " + c.Params["zone"])
		}
		prior.Status = z.Status
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(prior)
}

func (zoneDeactivate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	id := c.Params["zone"]
	err = t.call(ctx, "POST", "/api/v1/zones/"+id+"/lifecycle/deactivate", func(s *State, e *emitter) error {
		z, ok := s.Zones[id]
		if !ok {
			return notFound("zone " + id)
		}
		z.Status = statusInactive
		e.emit("zone.deactivate", "Deactivate network zone", eventTarget{ID: z.ID, Type: "Zone", DisplayName: z.Name})
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id}, nil
}

func (zoneDeactivate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	var prior zonePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Status == "" {
		return fmt.Errorf("zone deactivate: journal holds no prior status")
	}
	id := c.Params["zone"]
	return t.call(ctx, "POST", "/api/v1/zones/"+id+"/lifecycle/restore", func(s *State, e *emitter) error {
		z, ok := s.Zones[id]
		if !ok {
			return notFound("zone " + id)
		}
		if z.Status == prior.Status {
			return nil // already restored
		}
		z.Status = prior.Status
		if z.Status == statusActive {
			e.emit("zone.activate", "Activate network zone", eventTarget{ID: z.ID, Type: "Zone", DisplayName: z.Name})
		}
		return nil
	})
}

func (zoneDeactivate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	var prior zonePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("zone deactivate: journal holds no prior status")
	}
	restored := false
	err = t.call(ctx, "GET", "/api/v1/zones/"+c.Params["zone"], func(s *State, _ *emitter) error {
		z, ok := s.Zones[c.Params["zone"]]
		restored = !ok || z.Status == prior.Status
		return nil
	})
	return restored, err
}

// --- fake.org_setting.set (modify an existing, org-wide object) ---------

type orgSettingSet struct{}

type settingPrior struct {
	Value string `json:"value"`
}

func (orgSettingSet) Spec() provider.Spec {
	return provider.Spec{
		Name:     opOrgSettingSet,
		Summary:  "Change an org-wide security setting",
		Kind:     provider.KindModify,
		Resource: resOrgSetting,
		Params: []provider.Param{
			{Name: "setting", Type: provider.ParamEnum, Enum: orgSettings, Example: "session.mfa_required", Required: true},
			{Name: "value", Type: provider.ParamEnum, Enum: []string{"on", "off"}, Example: "off", Required: true},
		},
		Scopes:      []string{"fake.org.manage"},
		Events:      []string{"org.setting.update"},
		UndoEvents:  []string{"org.setting.update"},
		Request:     "PUT /api/v1/org/settings/{setting}",
		UndoSummary: "restore the recorded setting value",
		GoneCheck:   "GET /api/v1/org/settings/{setting} -> value equals the recorded prior",
	}
}

func (orgSettingSet) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	t, err := tenantOf(c)
	if err != nil {
		return nil, err
	}
	var prior settingPrior
	name := c.Params["setting"]
	err = t.call(ctx, "GET", "/api/v1/org/settings/"+name, func(s *State, _ *emitter) error {
		v, ok := s.Settings[name]
		if !ok {
			return notFound("setting " + name)
		}
		prior.Value = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(prior)
}

func (orgSettingSet) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	t, err := tenantOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	name, value := c.Params["setting"], c.Params["value"]
	err = t.call(ctx, "PUT", "/api/v1/org/settings/"+name, func(s *State, e *emitter) error {
		if _, ok := s.Settings[name]; !ok {
			return notFound("setting " + name)
		}
		s.Settings[name] = value
		e.emit("org.setting.update", "Update org setting", eventTarget{ID: name, Type: "OrgSetting", DisplayName: value})
		return nil
	})
	if err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: name}, nil
}

func (orgSettingSet) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	t, err := tenantOf(c)
	if err != nil {
		return err
	}
	var prior settingPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Value == "" {
		return fmt.Errorf("org setting: journal holds no prior value")
	}
	name := c.Params["setting"]
	return t.call(ctx, "PUT", "/api/v1/org/settings/"+name, func(s *State, e *emitter) error {
		if _, ok := s.Settings[name]; !ok {
			return notFound("setting " + name)
		}
		if s.Settings[name] == prior.Value {
			return nil
		}
		s.Settings[name] = prior.Value
		e.emit("org.setting.update", "Update org setting", eventTarget{ID: name, Type: "OrgSetting", DisplayName: prior.Value})
		return nil
	})
}

func (orgSettingSet) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	t, err := tenantOf(c)
	if err != nil {
		return false, err
	}
	var prior settingPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("org setting: journal holds no prior value")
	}
	restored := false
	name := c.Params["setting"]
	err = t.call(ctx, "GET", "/api/v1/org/settings/"+name, func(s *State, _ *emitter) error {
		restored = s.Settings[name] == prior.Value
		return nil
	})
	return restored, err
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
