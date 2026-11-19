package github

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- github.org.promote_owner ------------------------------------------
//
// Promotes an existing organization member to owner. Unlike the other
// techniques this one changes a real, operator-owned account's role rather
// than a run-created object, so it is never production-safe: the technique
// that uses it must declare safety.modifies_existing. Cleanup restores the
// exact role the account held before the run.

type orgPromoteOwner struct{}

type membershipPrior struct {
	Role    string `json:"role"`
	Account string `json:"account"`
}

func (orgPromoteOwner) Spec() provider.Spec {
	return provider.Spec{
		Name:     opOrgPromoteOwner,
		Summary:  "Promote an organization member to owner",
		Kind:     provider.KindModify,
		Resource: resMembership,
		Params: []provider.Param{
			{Name: "member", Type: provider.ParamString, Example: "octo-second", Doc: "Login of the operator-owned member to promote; defaults to the target's second_account option."},
		},
		Scopes:      []string{scopeAdminOrg},
		Events:      []string{"org.update_member"},
		UndoEvents:  []string{"org.update_member"},
		Request:     "PUT /orgs/{org}/memberships/{member}",
		UndoSummary: "restore the recorded org role",
		GoneCheck:   "GET /orgs/{org}/memberships/{member} -> role equals the recorded prior",
	}
}

func (orgPromoteOwner) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return nil, err
	}
	account, err := secondAccount(c, "member")
	if err != nil {
		return nil, err
	}
	var mem apiMembership
	if err := cl.get(ctx, "/orgs/"+escape(org)+"/memberships/"+escape(account), &mem); err != nil {
		return nil, err
	}
	if mem.Role == "" {
		return nil, fmt.Errorf("github: %q is not a member of the organization", account)
	}
	return json.Marshal(membershipPrior{Role: mem.Role, Account: account})
}

func (orgPromoteOwner) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	account, err := secondAccount(c, "member")
	if err != nil {
		return provider.Result{}, err
	}
	if err := cl.put(ctx, "/orgs/"+escape(org)+"/memberships/"+escape(account), map[string]any{"role": "admin"}, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: account}, nil
}

func (orgPromoteOwner) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	var prior membershipPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Account == "" || prior.Role == "" {
		return fmt.Errorf("github: membership journal holds no prior role")
	}
	err = cl.put(ctx, "/orgs/"+escape(org)+"/memberships/"+escape(prior.Account), map[string]any{"role": prior.Role}, nil)
	if isNotFound(err) {
		return nil // the member is gone; nothing to restore
	}
	return err
}

func (orgPromoteOwner) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	var prior membershipPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Account == "" {
		return false, fmt.Errorf("github: membership journal holds no prior role")
	}
	var mem apiMembership
	err = cl.get(ctx, "/orgs/"+escape(org)+"/memberships/"+escape(prior.Account), &mem)
	if isNotFound(err) {
		return true, nil // the member is gone, so the promotion is gone
	}
	if err != nil {
		return false, err
	}
	return mem.Role == prior.Role, nil
}
