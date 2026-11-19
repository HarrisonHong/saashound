package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// protectionID is the deterministic identifier of a branch protection,
// "<repo>:<branch>". The repo and branch travel in it so the removal op can
// recover both from the ref alone.
func protectionID(repo string) string { return repo + ":" + defaultBranch }

// parseProtectionID splits a protection ID back into its repo and branch.
func parseProtectionID(id string) (repo, branch string) {
	if i := strings.LastIndexByte(id, ':'); i >= 0 {
		return id[:i], id[i+1:]
	}
	return id, defaultBranch
}

// ---- github.branch_protection.create -----------------------------------
//
// Protects the default branch, so the branch-protection-removal technique has
// a run-owned protection to remove and restore rather than touching any branch
// the org relies on. The object name travels in a required status-check
// context, a real settable field, so the protection can be found by its exact
// name after a crash.

type branchProtectionCreate struct{}

func (branchProtectionCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:     opBranchProtectionCreate,
		Summary:  "Protect the default branch of a repository",
		Kind:     provider.KindCreate,
		Resource: resBranchProtection,
		Params: []provider.Param{
			{Name: "repo", Type: provider.ParamRef, Ref: resRepo, Required: true, Doc: "The repository whose default branch to protect."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"protected_branch.create"},
		UndoEvents:  []string{"protected_branch.destroy"},
		Request:     "PUT /repos/{org}/{repo}/branches/{branch}/protection",
		UndoSummary: "remove branch protection",
		GoneCheck:   "GET /repos/{org}/{repo}/branches/{branch}/protection -> 404",
		Note:        "run-owned setup for the removal technique; tagged with the run's name",
	}
}

// protectionBody builds the PUT body with the given status-check contexts.
func protectionBody(contexts []string) map[string]any {
	if contexts == nil {
		contexts = []string{}
	}
	return map[string]any{
		"required_status_checks":        map[string]any{"strict": false, "contexts": contexts},
		"enforce_admins":                true,
		"required_pull_request_reviews": nil,
		"restrictions":                  nil,
	}
}

func (branchProtectionCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	repo := c.Params["repo"]
	if err := cl.put(ctx, repoPath(org, repo, "/branches/"+escape(defaultBranch)+"/protection"), protectionBody([]string{c.Name}), nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: protectionID(repo)}, nil
}

func (branchProtectionCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	repo := c.Params["repo"]
	var bp apiBranchProtection
	err = cl.get(ctx, repoPath(org, repo, "/branches/"+escape(defaultBranch)+"/protection"), &bp)
	if isNotFound(err) {
		return provider.Result{}, false, nil
	}
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, name := range bp.RequiredStatusChecks.Contexts {
		if name == c.Name { // exact name only
			return provider.Result{ID: protectionID(repo)}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (branchProtectionCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	repo, branch := parseProtectionID(r.ID)
	err = cl.del(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection"))
	if isNotFound(err) {
		return nil
	}
	return err
}

func (branchProtectionCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	repo, branch := parseProtectionID(r.ID)
	ok, err := cl.exists(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection"))
	return !ok, err
}

// ---- github.branch.unprotect -------------------------------------------

type branchUnprotect struct{}

type protectionPrior struct {
	Protected bool     `json:"protected"`
	Contexts  []string `json:"contexts"`
}

func (branchUnprotect) Spec() provider.Spec {
	return provider.Spec{
		Name:     opBranchUnprotect,
		Summary:  "Remove protection from a protected branch",
		Kind:     provider.KindModify,
		Resource: resBranchProtection,
		Params: []provider.Param{
			{Name: "protection", Type: provider.ParamRef, Ref: resBranchProtection, Required: true, Doc: "The branch protection to remove."},
		},
		Scopes:      []string{scopeRepo},
		Events:      []string{"protected_branch.destroy"},
		UndoEvents:  []string{"protected_branch.create"},
		Request:     "DELETE /repos/{org}/{repo}/branches/{branch}/protection",
		UndoSummary: "restore the recorded branch protection",
		GoneCheck:   "GET /repos/{org}/{repo}/branches/{branch}/protection -> presence equals the recorded prior",
	}
}

func (branchUnprotect) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return nil, err
	}
	repo, branch := parseProtectionID(c.Params["protection"])
	var bp apiBranchProtection
	err = cl.get(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection"), &bp)
	if isNotFound(err) {
		return json.Marshal(protectionPrior{Protected: false})
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(protectionPrior{Protected: true, Contexts: bp.RequiredStatusChecks.Contexts})
}

func (branchUnprotect) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	repo, branch := parseProtectionID(c.Params["protection"])
	if err := cl.del(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection")); err != nil && !isNotFound(err) {
		return provider.Result{}, err
	}
	return provider.Result{ID: c.Params["protection"]}, nil
}

func (branchUnprotect) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, org, err := orgOf(c)
	if err != nil {
		return err
	}
	var prior protectionPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return fmt.Errorf("github: protection journal holds no prior")
	}
	if !prior.Protected {
		return nil // the branch was not protected before the run
	}
	repo, branch := parseProtectionID(c.Params["protection"])
	err = cl.put(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection"), protectionBody(prior.Contexts), nil)
	if isNotFound(err) {
		return nil // the repo is gone; a later step proves that
	}
	return err
}

func (branchUnprotect) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, org, err := orgOf(c)
	if err != nil {
		return false, err
	}
	var prior protectionPrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("github: protection journal holds no prior")
	}
	repo, branch := parseProtectionID(c.Params["protection"])
	// exists reports a gone repo as "no protection", which equals a prior of
	// unprotected; cleanup restores protection before the repo is deleted, so
	// the restore is proven while the repo still exists.
	ok, err := cl.exists(ctx, repoPath(org, repo, "/branches/"+escape(branch)+"/protection"))
	if err != nil {
		return false, err
	}
	return ok == prior.Protected, nil
}
