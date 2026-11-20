package okta

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- okta.app.create_oauth ---------------------------------------------

type appCreate struct{}

func (appCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opAppCreate,
		Summary:  "Create an OAuth 2.0 service application",
		Kind:     provider.KindCreate,
		Resource: resApp,
		Scopes:   []string{scopeAppsMgmt},
		// Okta emits both the application and the OAuth-client creation events.
		Events:      []string{"application.lifecycle.create", "app.oauth2.client.lifecycle.create"},
		UndoEvents:  []string{"application.lifecycle.delete"},
		Request:     "POST /api/v1/apps",
		UndoSummary: "deactivate + delete application",
		GoneCheck:   "GET /api/v1/apps/{id} -> 404",
		Note:        "the generated client secret is used once and never journalled",
	}
}

func (appCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{
		"name": "oidc_client", "label": c.Name, "signOnMode": "OPENID_CONNECT",
		"settings": map[string]any{"oauthClient": map[string]any{
			"application_type": "service",
			"grant_types":      []string{"client_credentials"},
			"response_types":   []string{"token"}}},
	}
	// apiApp names no secret field, so the client secret in the response is
	// decoded away and never reaches a result or the journal.
	var a apiApp
	if err := cl.post(ctx, "/api/v1/apps", body, &a); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: a.ID}, nil
}

func (appCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	as, err := cl.list(ctx, "/api/v1/apps")
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range as {
		var a apiApp
		if json.Unmarshal(raw, &a) == nil && a.Label == c.Name {
			return provider.Result{ID: a.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (appCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	if err := cl.post(ctx, "/api/v1/apps/"+escape(r.ID)+"/lifecycle/deactivate", nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return cl.del(ctx, "/api/v1/apps/"+escape(r.ID))
}

func (appCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/apps/"+escape(r.ID))
	return !ok, err
}

// ---- okta.app.grant_scope (the Salesloft/Drift analogue) ---------------

type appGrantScope struct{}

type grantPrior struct {
	Granted bool `json:"granted"`
}

func (appGrantScope) Spec() provider.Spec {
	return provider.Spec{
		Name:     opAppGrantScope,
		Summary:  "Grant an Okta API scope to a service app",
		Kind:     provider.KindModify,
		Resource: resApp,
		Params: []provider.Param{
			{Name: "app", Type: provider.ParamRef, Ref: resApp, Required: true, Doc: "The service app to grant the scope to."},
			{Name: "scope", Type: provider.ParamEnum, Enum: appScopes, Example: "okta.users.read", Required: true, Doc: "The Okta API scope."},
		},
		Scopes:      []string{scopeAppGrantsMgmt},
		Events:      []string{"app.oauth2.client.privilege.grant"},
		UndoEvents:  []string{"app.oauth2.client.privilege.revoke"},
		Request:     "POST /api/v1/apps/{app}/grants",
		UndoSummary: "revoke the scope grant",
		GoneCheck:   "GET /api/v1/apps/{app}/grants -> the scope is not granted",
		Note:        "granting Okta API scopes needs the service app to hold Super Admin",
	}
}

func (appGrantScope) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	granted, _, err := findGrant(ctx, cl, c.Params["app"], c.Params["scope"])
	if err != nil {
		return nil, err
	}
	return json.Marshal(grantPrior{Granted: granted})
}

func (appGrantScope) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	scope := c.Params["scope"]
	if !containsStr(appScopes, scope) {
		return provider.Result{}, fmt.Errorf("okta: scope %q is not in the allowed set", scope)
	}
	body := map[string]any{"scopeId": scope, "issuer": clientBase(c)}
	if err := cl.post(ctx, "/api/v1/apps/"+escape(c.Params["app"])+"/grants", body, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: c.Params["app"]}, nil
}

func (appGrantScope) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior grantPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("okta: grant journal holds no prior")
	}
	if prior.Granted {
		return nil // the scope pre-existed the run
	}
	granted, id, err := findGrant(ctx, cl, c.Params["app"], c.Params["scope"])
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !granted {
		return nil
	}
	err = cl.del(ctx, "/api/v1/apps/"+escape(c.Params["app"])+"/grants/"+escape(id))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (appGrantScope) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior grantPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: grant journal holds no prior")
	}
	granted, _, err := findGrant(ctx, cl, c.Params["app"], c.Params["scope"])
	if isNotFound(err) {
		return true, nil // the app is gone, so the grant is gone
	}
	if err != nil {
		return false, err
	}
	return granted == prior.Granted, nil
}

// findGrant reports whether an app holds a grant for the scope, and its id.
func findGrant(ctx context.Context, cl *client, appID, scope string) (bool, string, error) {
	var grants []apiGrant
	if err := cl.get(ctx, "/api/v1/apps/"+escape(appID)+"/grants", &grants); err != nil {
		return false, "", err
	}
	for _, g := range grants {
		if g.ScopeID == scope {
			return true, g.ID, nil
		}
	}
	return false, "", nil
}

// clientBase returns the tenant's org URL, used as the grant issuer.
func clientBase(c *provider.Call) string {
	if t, err := tenantOf(c); err == nil {
		return t.base.String()
	}
	return ""
}
