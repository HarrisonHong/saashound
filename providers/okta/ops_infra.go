package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- okta.zone.create --------------------------------------------------

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
		Scopes:      []string{scopeZonesMgmt},
		Events:      []string{"zone.create"},
		UndoEvents:  []string{"zone.delete"},
		Request:     "POST /api/v1/zones",
		UndoSummary: "deactivate + delete zone",
		GoneCheck:   "GET /api/v1/zones/{id} -> 404",
	}
}

func (zoneCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	gw := c.Params["gateway"]
	if gw == "" {
		gw = "203.0.113.0/24"
	}
	if _, err := netip.ParsePrefix(gw); err != nil {
		return provider.Result{}, fmt.Errorf("okta: gateway %q is not a CIDR: %w", gw, err)
	}
	body := map[string]any{"name": c.Name, "type": "IP",
		"gateways": []map[string]string{{"type": "CIDR", "value": gw}}}
	var z apiZone
	if err := cl.post(ctx, "/api/v1/zones", body, &z); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: z.ID}, nil
}

func (zoneCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	zs, err := cl.list(ctx, "/api/v1/zones")
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range zs {
		var z apiZone
		if json.Unmarshal(raw, &z) == nil && z.Name == c.Name {
			return provider.Result{ID: z.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (zoneCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	if err := cl.post(ctx, "/api/v1/zones/"+escape(r.ID)+"/lifecycle/deactivate", nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return cl.del(ctx, "/api/v1/zones/"+escape(r.ID))
}

func (zoneCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/zones/"+escape(r.ID))
	return !ok, err
}

// ---- okta.zone.deactivate ----------------------------------------------

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
		Scopes:      []string{scopeZonesMgmt},
		Events:      []string{"zone.deactivate"},
		UndoEvents:  []string{"zone.activate"},
		Request:     "POST /api/v1/zones/{zone}/lifecycle/deactivate",
		UndoSummary: "restore the recorded zone status",
		GoneCheck:   "GET /api/v1/zones/{zone} -> status equals the recorded prior",
	}
}

func (zoneDeactivate) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	var z apiZone
	if err := cl.get(ctx, "/api/v1/zones/"+escape(c.Params["zone"]), &z); err != nil {
		return nil, err
	}
	return json.Marshal(zonePrior{Status: z.Status})
}

func (zoneDeactivate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	id := c.Params["zone"]
	if err := cl.post(ctx, "/api/v1/zones/"+escape(id)+"/lifecycle/deactivate", nil, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: id}, nil
}

func (zoneDeactivate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior zonePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Status == "" {
		return fmt.Errorf("okta: zone journal holds no prior status")
	}
	if prior.Status != "ACTIVE" {
		return nil // it was already inactive before the run; leave it
	}
	err = cl.post(ctx, "/api/v1/zones/"+escape(c.Params["zone"])+"/lifecycle/activate", nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func (zoneDeactivate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior zonePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: zone journal holds no prior status")
	}
	var z apiZone
	err = cl.get(ctx, "/api/v1/zones/"+escape(c.Params["zone"]), &z)
	if isNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return z.Status == prior.Status, nil
}

// ---- okta.idp.create ---------------------------------------------------

type idpCreate struct{}

func (idpCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opIdpCreate,
		Summary:  "Create an inbound SAML identity provider",
		Kind:     provider.KindCreate,
		Resource: resIdp,
		Scopes:   []string{scopeIdpsMgmt},
		Events:   []string{"system.idp.lifecycle.create"},
		// Okta requires an IdP to be inactive before it can be deleted.
		UndoEvents:  []string{"system.idp.lifecycle.delete"},
		Request:     "POST /api/v1/idps",
		UndoSummary: "deactivate + delete identity provider",
		GoneCheck:   "GET /api/v1/idps/{id} -> 404",
		Note:        "SSO endpoint is on the reserved .invalid TLD; the signing key is discarded",
	}
}

func (idpCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	// The SSO endpoint can never resolve (RFC 6761 .invalid), so no real
	// authentication can be routed through this IdP.
	body := map[string]any{"name": c.Name, "type": "SAML2", "protocol": map[string]any{
		"type":      "SAML2",
		"endpoints": map[string]any{"sso": map[string]any{"url": "https://" + c.Name + ".invalid/sso"}}}}
	var idp apiIdp
	if err := cl.post(ctx, "/api/v1/idps", body, &idp); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: idp.ID}, nil
}

func (idpCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	is, err := cl.list(ctx, "/api/v1/idps")
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range is {
		var idp apiIdp
		if json.Unmarshal(raw, &idp) == nil && idp.Name == c.Name {
			return provider.Result{ID: idp.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (idpCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	if err := cl.post(ctx, "/api/v1/idps/"+escape(r.ID)+"/lifecycle/deactivate", nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return cl.del(ctx, "/api/v1/idps/"+escape(r.ID))
}

func (idpCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/idps/"+escape(r.ID))
	return !ok, err
}
