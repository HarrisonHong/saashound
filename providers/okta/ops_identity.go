package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- okta.user.create --------------------------------------------------

type userCreate struct{}

func (userCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opUserCreate,
		Summary:  "Create an active synthetic user",
		Kind:     provider.KindCreate,
		Resource: resUser,
		Params: []provider.Param{
			{Name: "display_name", Type: provider.ParamString, Example: "Synthetic victim", Doc: "Surname of the synthetic user; defaults to the object name."},
		},
		Outputs:     []string{"login"},
		Scopes:      []string{scopeUsersMgmt},
		Events:      []string{"user.lifecycle.create"},
		UndoEvents:  []string{"user.lifecycle.deactivate", "user.lifecycle.delete"},
		Request:     "POST /api/v1/users?activate=true",
		UndoSummary: "deactivate + delete user",
		GoneCheck:   "GET /api/v1/users/{id} -> 404",
		Note:        "no password is ever set; the account is inert",
	}
}

func (userCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	login := loginFor(c.Name, c.Target.TestDomain)
	last := c.Params["display_name"]
	if last == "" {
		last = c.Name
	}
	// No credentials are sent: the synthetic account has no password, so an
	// account a failed cleanup leaves behind cannot be signed in to.
	body := map[string]any{"profile": map[string]any{
		"login": login, "email": login, "firstName": "SaaSHound", "lastName": last}}
	var u apiUser
	if err := cl.post(ctx, "/api/v1/users?activate=true", body, &u); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: u.ID, Outputs: map[string]string{"login": login}}, nil
}

func (userCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	login := loginFor(c.Name, c.Target.TestDomain)
	var u apiUser
	// Okta addresses a user by id or login; the login encodes the exact object
	// name, so this matches the exact name and nothing near it.
	err = cl.get(ctx, "/api/v1/users/"+escape(login), &u)
	if isNotFound(err) {
		return provider.Result{}, false, nil
	}
	if err != nil {
		return provider.Result{}, false, err
	}
	if u.Profile.Login != login {
		return provider.Result{}, false, nil
	}
	return provider.Result{ID: u.ID, Outputs: map[string]string{"login": login}}, true, nil
}

func (userCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	// Okta refuses to delete an active user, so deactivate first; a user
	// already gone makes both calls 404, which counts as success.
	if err := cl.post(ctx, "/api/v1/users/"+escape(r.ID)+"/lifecycle/deactivate", nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return cl.del(ctx, "/api/v1/users/"+escape(r.ID))
}

func (userCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/users/"+escape(r.ID))
	return !ok, err
}

// ---- okta.factor.enroll_totp -------------------------------------------

type factorEnroll struct{}

func (factorEnroll) Spec() provider.Spec {
	return provider.Spec{
		Name:     opFactorEnroll,
		Summary:  "Enroll and activate a software TOTP factor on a user",
		Kind:     provider.KindCreate,
		Resource: resFactor,
		Params: []provider.Param{
			{Name: "user", Type: provider.ParamRef, Ref: resUser, Required: true, Doc: "The user to enroll the factor on."},
		},
		Scopes:      []string{scopeUsersMgmt},
		Events:      []string{"user.mfa.factor.activate"},
		UndoEvents:  []string{"user.mfa.factor.deactivate"},
		Request:     "POST /api/v1/users/{user}/factors?activate=true",
		UndoSummary: "delete factor",
		GoneCheck:   "GET /api/v1/users/{user}/factors/{id} -> 404",
		Note:        "the shared secret stays server-side and is never retrieved",
	}
}

func (factorEnroll) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	// The object name travels in the factor's credentialId, a real settable
	// Okta field, so the factor can be found again by its exact name.
	body := map[string]any{"factorType": "token:software:totp", "provider": "FIDO",
		"profile": map[string]any{"credentialId": c.Name}}
	var f apiFactor
	if err := cl.post(ctx, "/api/v1/users/"+escape(c.Params["user"])+"/factors?activate=true", body, &f); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: f.ID}, nil
}

func (factorEnroll) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	fs, err := listFactors(ctx, cl, c.Params["user"])
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, f := range fs {
		if f.Profile.CredentialID == c.Name { // exact name only
			return provider.Result{ID: f.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (factorEnroll) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	return cl.del(ctx, "/api/v1/users/"+escape(c.Params["user"])+"/factors/"+escape(r.ID))
}

func (factorEnroll) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/users/"+escape(c.Params["user"])+"/factors/"+escape(r.ID))
	return !ok, err
}

// listFactors returns a user's enrolled factors.
func listFactors(ctx context.Context, cl *client, userID string) ([]apiFactor, error) {
	var fs []apiFactor
	if err := cl.get(ctx, "/api/v1/users/"+escape(userID)+"/factors", &fs); err != nil {
		return nil, err
	}
	return fs, nil
}

// ---- okta.factor.reset (help-desk MFA reset) ---------------------------
//
// reset_factors unenrolls every factor on a user and is logged as
// user.mfa.factor.reset_all, the event the help-desk-reset detections key on.
// It is modelled as a modify of the run's own factor (its ref is okta.factor),
// so the conformance suite always resets a user that actually has a factor.
// Its restorable value is "the user still has a factor with this credentialId":
// Do removes it, Undo re-enrolls an inert replacement with the same
// credentialId (a new, discarded seed), and the whole synthetic user is
// removed at cleanup regardless. It only ever runs on a run-created user.

type factorReset struct{}

type resetPrior struct {
	UserID       string `json:"user_id"`
	CredentialID string `json:"credential_id"`
}

func (factorReset) Spec() provider.Spec {
	return provider.Spec{
		Name:     opFactorReset,
		Summary:  "Reset (unenroll) a user's MFA factors",
		Kind:     provider.KindModify,
		Resource: resFactor,
		Params: []provider.Param{
			{Name: "factor", Type: provider.ParamRef, Ref: resFactor, Required: true, Doc: "A factor on the user whose factors are reset."},
		},
		Scopes:      []string{scopeUsersMgmt},
		Events:      []string{"user.mfa.factor.reset_all"},
		UndoEvents:  []string{"user.mfa.factor.activate"},
		Request:     "POST /api/v1/users/{user}/lifecycle/reset_factors",
		UndoSummary: "re-enroll an inert replacement factor with the recorded credentialId",
		GoneCheck:   "GET /api/v1/users/{user}/factors -> a factor with the recorded credentialId",
	}
}

// Prior finds, before the reset, which user the ref'd factor belongs to and
// its credentialId, searching only the run's own synthetic users.
func (factorReset) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	uid, cred, found, err := findFactorUser(ctx, cl, c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("okta: factor %s not found on any run-created user", c.Params["factor"])
	}
	return json.Marshal(resetPrior{UserID: uid, CredentialID: cred})
}

func (factorReset) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	uid, _, found, err := findFactorUser(ctx, cl, c)
	if err != nil {
		return provider.Result{}, err
	}
	if !found {
		return provider.Result{}, fmt.Errorf("okta: factor %s not found", c.Params["factor"])
	}
	if err := cl.post(ctx, "/api/v1/users/"+escape(uid)+"/lifecycle/reset_factors", nil, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: c.Params["factor"]}, nil
}

func (factorReset) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior resetPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.UserID == "" {
		return fmt.Errorf("okta: reset journal holds no prior user")
	}
	// Idempotent: if a factor with the recorded credentialId is already back,
	// there is nothing to restore.
	has, err := hasCredential(ctx, cl, prior.UserID, prior.CredentialID)
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	body := map[string]any{"factorType": "token:software:totp", "provider": "FIDO",
		"profile": map[string]any{"credentialId": prior.CredentialID}}
	err = cl.post(ctx, "/api/v1/users/"+escape(prior.UserID)+"/factors?activate=true", body, nil)
	if isNotFound(err) {
		return nil // the user is already gone; nothing to restore
	}
	return err
}

func (factorReset) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior resetPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: reset journal holds no prior")
	}
	// Restored means the user has a factor with the recorded credentialId
	// again (or the user is gone, which a later cleanup step proves).
	has, err := hasCredential(ctx, cl, prior.UserID, prior.CredentialID)
	if err != nil {
		return false, err
	}
	return has, nil
}

// findFactorUser locates which of the run's own synthetic users holds the
// ref'd factor, returning that user's id and the factor's credentialId. It
// lists only users whose login carries this run's prefix, so it is bounded by
// the run's own objects, never the whole org.
func findFactorUser(ctx context.Context, cl *client, c *provider.Call) (userID, cred string, found bool, err error) {
	factorID := c.Params["factor"]
	prefix := marker.RunPrefix(c.Run) + "-"
	raws, err := cl.list(ctx, "/api/v1/users?search="+escape(`profile.login sw "`+prefix+`"`)+"&limit=200")
	if err != nil {
		return "", "", false, err
	}
	for _, raw := range raws {
		var u apiUser
		if json.Unmarshal(raw, &u) != nil {
			continue
		}
		fs, err := listFactors(ctx, cl, u.ID)
		if err != nil {
			return "", "", false, err
		}
		for _, f := range fs {
			if f.ID == factorID {
				return u.ID, f.Profile.CredentialID, true, nil
			}
		}
	}
	return "", "", false, nil
}

func hasCredential(ctx context.Context, cl *client, userID, cred string) (bool, error) {
	fs, err := listFactors(ctx, cl, userID)
	if isNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, f := range fs {
		if f.Profile.CredentialID == cred {
			return true, nil
		}
	}
	return false, nil
}

// ---- okta.role.assign --------------------------------------------------

type roleAssign struct{}

type rolePrior struct {
	Assigned bool `json:"assigned"`
}

func (roleAssign) Spec() provider.Spec {
	return provider.Spec{
		Name:     opRoleAssign,
		Summary:  "Assign an admin role to a user",
		Kind:     provider.KindModify,
		Resource: resUser,
		Params: []provider.Param{
			{Name: "user", Type: provider.ParamRef, Ref: resUser, Required: true, Doc: "The user to grant the role to."},
			{Name: "role", Type: provider.ParamEnum, Enum: adminRoles, Example: "READ_ONLY_ADMIN", Required: true, Doc: "The admin role type."},
		},
		Outputs:     []string{"role"},
		Scopes:      []string{scopeRolesMgmt},
		Events:      []string{"user.account.privilege.grant"},
		UndoEvents:  []string{"user.account.privilege.revoke"},
		Request:     "POST /api/v1/users/{user}/roles",
		UndoSummary: "revoke the role assignment",
		GoneCheck:   "GET /api/v1/users/{user}/roles -> the role is not assigned",
		Note:        "SUPER_ADMIN needs the service app to hold Super Admin",
	}
}

func (roleAssign) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	assigned, _, err := findRole(ctx, cl, c.Params["user"], c.Params["role"])
	if err != nil {
		return nil, err
	}
	return json.Marshal(rolePrior{Assigned: assigned})
}

func (roleAssign) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	role := c.Params["role"]
	if !containsStr(adminRoles, role) {
		return provider.Result{}, fmt.Errorf("okta: unknown admin role %q", role)
	}
	if err := cl.post(ctx, "/api/v1/users/"+escape(c.Params["user"])+"/roles", map[string]any{"type": role}, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: c.Params["user"], Outputs: map[string]string{"role": role}}, nil
}

func (roleAssign) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior rolePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("okta: role journal holds no prior")
	}
	if prior.Assigned {
		return nil // the role pre-existed the run; leave it exactly as found
	}
	assigned, id, err := findRole(ctx, cl, c.Params["user"], c.Params["role"])
	if err != nil {
		if isNotFound(err) {
			return nil // the user is gone
		}
		return err
	}
	if !assigned {
		return nil
	}
	err = cl.del(ctx, "/api/v1/users/"+escape(c.Params["user"])+"/roles/"+escape(id))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (roleAssign) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior rolePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: role journal holds no prior")
	}
	assigned, _, err := findRole(ctx, cl, c.Params["user"], c.Params["role"])
	if isNotFound(err) {
		return true, nil // the user is gone, so the grant is gone
	}
	if err != nil {
		return false, err
	}
	return assigned == prior.Assigned, nil
}

// findRole reports whether a user holds a role of the given type, and that
// assignment's id.
func findRole(ctx context.Context, cl *client, userID, roleType string) (bool, string, error) {
	var roles []apiRole
	if err := cl.get(ctx, "/api/v1/users/"+escape(userID)+"/roles", &roles); err != nil {
		return false, "", err
	}
	for _, r := range roles {
		if strings.EqualFold(r.Type, roleType) {
			return true, r.ID, nil
		}
	}
	return false, "", nil
}
