package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- github.repo.create ------------------------------------------------
//
// The foundational object every other repo-scoped technique composes on: a
// private, auto-initialised repository named for the run. It is created with
// secret scanning and its push protection enabled, so the defence-impairment
// technique has something real to switch off, and deleted whole on cleanup.

type repoCreate struct{}

func (repoCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:        opRepoCreate,
		Summary:     "Create a private repository in the organization",
		Kind:        provider.KindCreate,
		Resource:    resRepo,
		Outputs:     []string{"repo_id"},
		Scopes:      []string{scopeRepo, scopeDeleteRepo},
		Events:      []string{"repo.create"},
		UndoEvents:  []string{"repo.destroy"},
		Request:     "POST /orgs/{org}/repos",
		UndoSummary: "delete repository",
		GoneCheck:   "GET /repos/{org}/{name} -> 404",
		Note:        "private, auto-initialised; no real content; deleted whole on cleanup",
	}
}

func (repoCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{
		"name":        c.Name,
		"description": "SaaSHound range repository (" + c.Run + ")",
		"private":     true,
		"auto_init":   true,
	}
	var r apiRepo
	if err := cl.post(ctx, "/orgs/"+escape(org)+"/repos", body, &r); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: r.Name, Outputs: map[string]string{"repo_id": strconv.FormatInt(r.ID, 10)}}, nil
}

func (repoCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	var r apiRepo
	err = cl.get(ctx, repoPath(org, c.Name, ""), &r)
	if isNotFound(err) {
		return provider.Result{}, false, nil
	}
	if err != nil {
		return provider.Result{}, false, err
	}
	if r.Name != c.Name { // exact name only
		return provider.Result{}, false, nil
	}
	return provider.Result{ID: r.Name, Outputs: map[string]string{"repo_id": strconv.FormatInt(r.ID, 10)}}, true, nil
}

func (repoCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	if err := cl.del(ctx, repoPath(org, r.ID, "")); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (repoCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, repoPath(org, r.ID, ""))
	return !ok, err
}

// ---- github.repo.make_public -------------------------------------------

type repoMakePublic struct{}

type visibilityPrior struct {
	Private bool `json:"private"`
}

func (repoMakePublic) Spec() provider.Spec {
	return provider.Spec{
		Name:     opRepoMakePublic,
		Summary:  "Turn a private repository public",
		Kind:     provider.KindModify,
		Resource: resRepo,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository to make public."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"repo.access"},
		UndoEvents:  []string{"repo.access"},
		Request:     "PATCH /repos/{org}/{repo}",
		UndoSummary: "restore the recorded visibility",
		GoneCheck:   "GET /repos/{org}/{repo} -> private equals the recorded prior",
	}
}

func (repoMakePublic) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return nil, err
	}
	var r apiRepo
	if err := cl.get(ctx, repoPath(org, c.Params["repo"], ""), &r); err != nil {
		return nil, err
	}
	return json.Marshal(visibilityPrior{Private: r.Private})
}

func (repoMakePublic) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	repo := c.Params["repo"]
	if err := cl.patch(ctx, repoPath(org, repo, ""), map[string]any{"private": false, "visibility": "public"}, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: repo}, nil
}

func (repoMakePublic) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	var prior visibilityPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("github: visibility journal holds no prior")
	}
	vis := "public"
	if prior.Private {
		vis = "private"
	}
	err = cl.patch(ctx, repoPath(org, c.Params["repo"], ""), map[string]any{"private": prior.Private, "visibility": vis}, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func (repoMakePublic) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	var prior visibilityPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("github: visibility journal holds no prior")
	}
	var repo apiRepo
	err = cl.get(ctx, repoPath(org, c.Params["repo"], ""), &repo)
	if isNotFound(err) {
		return true, nil // the repo is gone, so its visibility is restored by removal
	}
	if err != nil {
		return false, err
	}
	return repo.Private == prior.Private, nil
}

// ---- github.repo.add_collaborator (outside collaborator) ---------------

type repoAddCollaborator struct{}

type collaboratorPrior struct {
	Member  bool   `json:"member"`
	Account string `json:"account"`
}

func (repoAddCollaborator) Spec() provider.Spec {
	return provider.Spec{
		Name:     opRepoAddCollaborator,
		Summary:  "Add an outside collaborator to a repository",
		Kind:     provider.KindModify,
		Resource: resRepo,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository to add the collaborator to."},
			{Name: "collaborator", Type: provider.ParamString, Example: "octo-second", Doc: "Login of the operator-owned second account; defaults to the target's second_account option."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"repo.add_member"},
		UndoEvents:  []string{"repo.remove_member"},
		Request:     "PUT /repos/{org}/{repo}/collaborators/{account}",
		UndoSummary: "remove the collaborator",
		GoneCheck:   "GET /repos/{org}/{repo}/collaborators/{account} -> membership equals the recorded prior",
	}
}

func (repoAddCollaborator) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return nil, err
	}
	account, err := secondAccount(c, "collaborator")
	if err != nil {
		return nil, err
	}
	present, err := collaboratorPresent(ctx, cl, org, c.Params["repo"], account)
	if err != nil {
		return nil, err
	}
	return json.Marshal(collaboratorPrior{Member: present, Account: account})
}

func (repoAddCollaborator) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	account, err := secondAccount(c, "collaborator")
	if err != nil {
		return provider.Result{}, err
	}
	if err := cl.put(ctx, repoPath(org, c.Params["repo"], "/collaborators/"+escape(account)), map[string]any{"permission": "push"}, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: account}, nil
}

func (repoAddCollaborator) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	var prior collaboratorPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Account == "" {
		return fmt.Errorf("github: collaborator journal holds no prior")
	}
	if prior.Member {
		return nil // the account was already a collaborator before the run
	}
	// Remove an accepted collaborator, if any, and cancel a still-pending
	// invitation, so cleanup is complete whether or not the invite was accepted.
	if err := cl.del(ctx, repoPath(org, c.Params["repo"], "/collaborators/"+escape(prior.Account))); err != nil && !isNotFound(err) {
		return err
	}
	id, found, err := pendingInvitation(ctx, cl, org, c.Params["repo"], prior.Account)
	if err != nil {
		return err
	}
	if found {
		if err := cl.del(ctx, repoPath(org, c.Params["repo"], "/invitations/"+escape(id))); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}

func (repoAddCollaborator) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	var prior collaboratorPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.Account == "" {
		return false, fmt.Errorf("github: collaborator journal holds no prior")
	}
	present, err := collaboratorPresent(ctx, cl, org, c.Params["repo"], prior.Account)
	if err != nil {
		return false, err
	}
	// A gone repo reports the account as neither a collaborator nor invited:
	// the access is gone, matching a prior of not-present.
	return present == prior.Member, nil
}

// collaboratorPresent reports whether an account has access to a repo, as an
// accepted collaborator or a still-pending invitation. A gone repo (404)
// counts as not present.
func collaboratorPresent(ctx context.Context, cl *client, org, repo, user string) (bool, error) {
	member, err := isCollaborator(ctx, cl, org, repo, user)
	if err != nil {
		return false, err
	}
	if member {
		return true, nil
	}
	_, found, err := pendingInvitation(ctx, cl, org, repo, user)
	return found, err
}

// isCollaborator reports whether a user is an accepted collaborator on a repo:
// GET .../collaborators/{user} answers 204 (yes) or 404 (no, or the repo is
// gone, which for this purpose is the same: the user is not a collaborator).
func isCollaborator(ctx context.Context, cl *client, org, repo, user string) (bool, error) {
	err := cl.get(ctx, repoPath(org, repo, "/collaborators/"+escape(user)), nil)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, err
}

// pendingInvitation returns the id of a pending repository invitation for user,
// if one exists. A gone repo (404) reports no invitation.
func pendingInvitation(ctx context.Context, cl *client, org, repo, user string) (id string, found bool, err error) {
	raws, err := cl.list(ctx, repoPath(org, repo, "/invitations"))
	if isNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	for _, raw := range raws {
		var inv apiInvitation
		if json.Unmarshal(raw, &inv) == nil && inv.Invitee.Login == user {
			return strconv.FormatInt(inv.ID, 10), true, nil
		}
	}
	return "", false, nil
}

// ---- github.repo.disable_secret_scanning -------------------------------

type repoDisableScanning struct{}

type scanningPrior struct {
	Scanning string `json:"scanning"`
	Push     string `json:"push"`
}

func (repoDisableScanning) Spec() provider.Spec {
	return provider.Spec{
		Name:     opRepoDisableScanning,
		Summary:  "Disable secret scanning and its push protection on a repository",
		Kind:     provider.KindModify,
		Resource: resRepo,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository to disable scanning on."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"repository_secret_scanning.disable", "repository_secret_scanning_push_protection.disable"},
		UndoEvents:  []string{"repository_secret_scanning.enable", "repository_secret_scanning_push_protection.enable"},
		Request:     "PATCH /repos/{org}/{repo} (security_and_analysis)",
		UndoSummary: "restore the recorded scanning and push-protection status",
		GoneCheck:   "GET /repos/{org}/{repo} -> scanning status equals the recorded prior",
	}
}

func (repoDisableScanning) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return nil, err
	}
	var r apiRepo
	if err := cl.get(ctx, repoPath(org, c.Params["repo"], ""), &r); err != nil {
		return nil, err
	}
	return json.Marshal(scanningPrior{
		Scanning: r.SecurityAndAnalysis.SecretScanning.Status,
		Push:     r.SecurityAndAnalysis.SecretScanningPushProtection.Status,
	})
}

func (repoDisableScanning) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	repo := c.Params["repo"]
	if err := cl.patch(ctx, repoPath(org, repo, ""), securityPatch("disabled", "disabled"), nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: repo}, nil
}

func (repoDisableScanning) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	var prior scanningPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("github: scanning journal holds no prior")
	}
	err = cl.patch(ctx, repoPath(org, c.Params["repo"], ""), securityPatch(prior.Scanning, prior.Push), nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func (repoDisableScanning) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	var prior scanningPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("github: scanning journal holds no prior")
	}
	var repo apiRepo
	err = cl.get(ctx, repoPath(org, c.Params["repo"], ""), &repo)
	if isNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return repo.SecurityAndAnalysis.SecretScanning.Status == prior.Scanning &&
		repo.SecurityAndAnalysis.SecretScanningPushProtection.Status == prior.Push, nil
}

// securityPatch builds the security_and_analysis body for a PATCH. An empty
// status leaves that feature untouched.
func securityPatch(scanning, push string) map[string]any {
	sa := map[string]any{}
	if scanning != "" {
		sa["secret_scanning"] = map[string]any{"status": scanning}
	}
	if push != "" {
		sa["secret_scanning_push_protection"] = map[string]any{"status": push}
	}
	return map[string]any{"security_and_analysis": sa}
}
