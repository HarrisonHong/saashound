package github

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- github.deploy_key.add ---------------------------------------------
//
// Adds a repository deploy key, the persistence step CISA's Shai-Hulud
// guidance tells defenders to audit (keys, apps, webhooks). The tool generates
// a throwaway ed25519 key pair and sends only the public half, so the key it
// leaves behind can authenticate nobody: nobody holds the private half.

type deployKeyAdd struct{}

func (deployKeyAdd) Spec() provider.Spec {
	return provider.Spec{
		Name:     opDeployKeyAdd,
		Summary:  "Add a read-only deploy key to a repository",
		Kind:     provider.KindCreate,
		Resource: resDeployKey,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository to add the deploy key to."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"public_key.create"},
		UndoEvents:  []string{"public_key.delete"},
		Request:     "POST /repos/{org}/{repo}/keys",
		UndoSummary: "delete deploy key",
		GoneCheck:   "GET /repos/{org}/{repo}/keys/{id} -> 404",
		Note:        "the private half is generated and discarded; the key authenticates nobody",
	}
}

func (deployKeyAdd) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	pub, err := sshPublicKey(c.Name)
	if err != nil {
		return provider.Result{}, err
	}
	// The object name travels in the key title, so the key can be found again
	// by its exact name after a crash.
	body := map[string]any{"title": c.Name, "key": pub, "read_only": true}
	var k apiDeployKey
	if err := cl.post(ctx, repoPath(org, c.Params["repo"], "/keys"), body, &k); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: strconv.FormatInt(k.ID, 10)}, nil
}

func (deployKeyAdd) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	keys, err := cl.list(ctx, repoPath(org, c.Params["repo"], "/keys"))
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, raw := range keys {
		var k apiDeployKey
		if json.Unmarshal(raw, &k) == nil && k.Title == c.Name { // exact name only
			return provider.Result{ID: strconv.FormatInt(k.ID, 10)}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (deployKeyAdd) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	err = cl.del(ctx, repoPath(org, c.Params["repo"], "/keys/"+escape(r.ID)))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (deployKeyAdd) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, repoPath(org, c.Params["repo"], "/keys/"+escape(r.ID)))
	return !ok, err
}

// ---- github.webhook.create ---------------------------------------------
//
// Creates a repository webhook whose payload URL is on the reserved .invalid
// TLD (RFC 6761), so the creation ping, and any later delivery, resolves
// nowhere. GhostAction exfiltrated over an HTTP POST webhook; this emits the
// same hook.create event with no possible delivery.

type webhookCreate struct{}

func (webhookCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opWebhookCreate,
		Summary:  "Create a repository webhook pointing at a .invalid URL",
		Kind:     provider.KindCreate,
		Resource: resWebhook,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository to add the webhook to."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"hook.create"},
		UndoEvents:  []string{"hook.destroy"},
		Request:     "POST /repos/{org}/{repo}/hooks",
		UndoSummary: "delete webhook",
		GoneCheck:   "GET /repos/{org}/{repo}/hooks/{id} -> 404",
		Note:        "payload URL is on the reserved .invalid TLD; the ping goes nowhere",
	}
}

func (webhookCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{
		"name":   "web",
		"active": true,
		"events": []string{"push"},
		"config": map[string]any{"url": webhookURL(c.Name), "content_type": "json"},
	}
	var h apiHook
	if err := cl.post(ctx, repoPath(org, c.Params["repo"], "/hooks"), body, &h); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: strconv.FormatInt(h.ID, 10)}, nil
}

func (webhookCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	hooks, err := cl.list(ctx, repoPath(org, c.Params["repo"], "/hooks"))
	if err != nil {
		return provider.Result{}, false, err
	}
	want := webhookURL(c.Name)
	for _, raw := range hooks {
		var h apiHook
		if json.Unmarshal(raw, &h) == nil && h.Config.URL == want { // exact name only
			return provider.Result{ID: strconv.FormatInt(h.ID, 10)}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (webhookCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	err = cl.del(ctx, repoPath(org, c.Params["repo"], "/hooks/"+escape(r.ID)))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (webhookCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, repoPath(org, c.Params["repo"], "/hooks/"+escape(r.ID)))
	return !ok, err
}

// webhookURL is the deterministic .invalid payload URL for a webhook object,
// encoding the object name in the host so Sweep and Locate can recover it.
func webhookURL(name string) string { return "https://" + name + ".invalid/hook" }
