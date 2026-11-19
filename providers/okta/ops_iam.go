package okta

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- okta.iam.create_role (custom admin role) --------------------------

type iamRoleCreate struct{}

func (iamRoleCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:        opIamCreateRole,
		Summary:     "Create a custom admin role",
		Kind:        provider.KindCreate,
		Resource:    resCustomRole,
		Scopes:      []string{scopeRolesMgmt},
		Events:      []string{"iam.role.create"},
		UndoEvents:  []string{"iam.role.delete"},
		Request:     "POST /api/v1/iam/roles",
		UndoSummary: "delete custom role",
		GoneCheck:   "GET /api/v1/iam/roles/{id} -> 404",
	}
}

func (iamRoleCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{"label": c.Name, "description": "SaaSHound custom role",
		"permissions": []string{"okta.users.read", "okta.users.userprofile.manage"}}
	var cr apiCustomRole
	if err := cl.post(ctx, "/api/v1/iam/roles", body, &cr); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: cr.ID}, nil
}

func (iamRoleCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	rs, err := cl.list(ctx, "/api/v1/iam/roles")
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range rs {
		var cr apiCustomRole
		if json.Unmarshal(raw, &cr) == nil && cr.Label == c.Name {
			return provider.Result{ID: cr.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (iamRoleCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	return cl.del(ctx, "/api/v1/iam/roles/"+escape(r.ID))
}

func (iamRoleCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/iam/roles/"+escape(r.ID))
	return !ok, err
}

// ---- okta.iam.create_resource_set --------------------------------------

type iamResourceSetCreate struct{}

func (iamResourceSetCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:        opIamCreateResourceSet,
		Summary:     "Create a resource set",
		Kind:        provider.KindCreate,
		Resource:    resResourceSet,
		Scopes:      []string{scopeRolesMgmt},
		Events:      []string{"iam.resourceset.create"},
		UndoEvents:  []string{"iam.resourceset.delete"},
		Request:     "POST /api/v1/iam/resource-sets",
		UndoSummary: "delete resource set",
		GoneCheck:   "GET /api/v1/iam/resource-sets/{id} -> 404",
	}
}

func (iamResourceSetCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{"label": c.Name, "description": "SaaSHound resource set",
		"resources": []string{clientBase(c) + "/api/v1/users"}}
	var rs apiResourceSet
	if err := cl.post(ctx, "/api/v1/iam/resource-sets", body, &rs); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: rs.ID}, nil
}

func (iamResourceSetCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	rs, err := cl.list(ctx, "/api/v1/iam/resource-sets")
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range rs {
		var set apiResourceSet
		if json.Unmarshal(raw, &set) == nil && set.Label == c.Name {
			return provider.Result{ID: set.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (iamResourceSetCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	return cl.del(ctx, "/api/v1/iam/resource-sets/"+escape(r.ID))
}

func (iamResourceSetCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/iam/resource-sets/"+escape(r.ID))
	return !ok, err
}

// ---- okta.iam.bind_role ------------------------------------------------

type iamBindRole struct{}

type bindingPrior struct {
	Bound bool `json:"bound"`
}

func (iamBindRole) Spec() provider.Spec {
	return provider.Spec{
		Name:     opIamBindRole,
		Summary:  "Bind a custom role over a resource set to a member",
		Kind:     provider.KindModify,
		Resource: resResourceSet,
		Params: []provider.Param{
			{Name: "resource_set", Type: provider.ParamRef, Ref: resResourceSet, Required: true, Doc: "The resource set to bind over."},
			{Name: "role", Type: provider.ParamRef, Ref: resCustomRole, Required: true, Doc: "The custom role to bind."},
			{Name: "member", Type: provider.ParamRef, Ref: resUser, Required: true, Doc: "The user to grant the bound role."},
		},
		Scopes:      []string{scopeRolesMgmt},
		Events:      []string{"iam.resourceset.bindings.add"},
		UndoEvents:  []string{"iam.resourceset.bindings.delete"},
		Request:     "POST /api/v1/iam/resource-sets/{resource_set}/bindings",
		UndoSummary: "delete the role binding",
		GoneCheck:   "GET /api/v1/iam/resource-sets/{resource_set}/bindings -> the role is not bound",
	}
}

func (iamBindRole) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	bound, err := hasBinding(ctx, cl, c.Params["resource_set"], c.Params["role"])
	if err != nil {
		return nil, err
	}
	return json.Marshal(bindingPrior{Bound: bound})
}

func (iamBindRole) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{"role": c.Params["role"], "members": []string{c.Params["member"]}}
	if err := cl.post(ctx, "/api/v1/iam/resource-sets/"+escape(c.Params["resource_set"])+"/bindings", body, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: c.Params["resource_set"]}, nil
}

func (iamBindRole) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior bindingPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("okta: binding journal holds no prior")
	}
	if prior.Bound {
		return nil // the binding pre-existed the run
	}
	err = cl.del(ctx, "/api/v1/iam/resource-sets/"+escape(c.Params["resource_set"])+"/bindings/"+escape(c.Params["role"]))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (iamBindRole) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior bindingPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: binding journal holds no prior")
	}
	bound, err := hasBinding(ctx, cl, c.Params["resource_set"], c.Params["role"])
	if isNotFound(err) {
		return true, nil // the resource set is gone, so the binding is gone
	}
	if err != nil {
		return false, err
	}
	return bound == prior.Bound, nil
}

// hasBinding reports whether a resource set holds a binding for the role.
func hasBinding(ctx context.Context, cl *client, rsID, role string) (bool, error) {
	var bs []apiBinding
	if err := cl.get(ctx, "/api/v1/iam/resource-sets/"+escape(rsID)+"/bindings", &bs); err != nil {
		return false, err
	}
	for _, b := range bs {
		if b.Role == role {
			return true, nil
		}
	}
	return false, nil
}
