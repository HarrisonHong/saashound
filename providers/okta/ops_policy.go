package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// ---- okta.policy.create ------------------------------------------------

type policyCreate struct{}

func (policyCreate) Spec() provider.Spec {
	return provider.Spec{
		Name:        opPolicyCreate,
		Summary:     "Create an access policy",
		Kind:        provider.KindCreate,
		Resource:    resPolicy,
		Scopes:      []string{scopePolicyMgmt},
		Events:      []string{"policy.lifecycle.create"},
		UndoEvents:  []string{"policy.lifecycle.delete"},
		Request:     "POST /api/v1/policies",
		UndoSummary: "delete policy",
		GoneCheck:   "GET /api/v1/policies/{id} -> 404",
	}
}

func (policyCreate) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	var p apiPolicy
	if err := cl.post(ctx, "/api/v1/policies", map[string]any{"name": c.Name, "type": "ACCESS_POLICY"}, &p); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: p.ID}, nil
}

func (policyCreate) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	ps, err := listPolicies(ctx, cl)
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, p := range ps {
		if p.Name == c.Name {
			return provider.Result{ID: p.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (policyCreate) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	return cl.del(ctx, "/api/v1/policies/"+escape(r.ID))
}

func (policyCreate) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/policies/"+escape(r.ID))
	return !ok, err
}

// ---- okta.policy.add_rule ----------------------------------------------

type policyAddRule struct{}

func (policyAddRule) Spec() provider.Spec {
	return provider.Spec{
		Name:     opPolicyAddRule,
		Summary:  "Add an MFA-requiring rule to a policy",
		Kind:     provider.KindCreate,
		Resource: resPolicyRule,
		Params: []provider.Param{
			{Name: "policy", Type: provider.ParamRef, Ref: resPolicy, Required: true, Doc: "The policy to add the rule to."},
		},
		Scopes:      []string{scopePolicyMgmt},
		Events:      []string{"policy.rule.add"},
		UndoEvents:  []string{"policy.rule.delete"},
		Request:     "POST /api/v1/policies/{policy}/rules",
		UndoSummary: "delete policy rule",
		GoneCheck:   "GET /api/v1/policies/{policy}/rules/{id} -> 404",
	}
}

func (policyAddRule) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	body := map[string]any{"name": c.Name, "actions": mfaAction("2FA")}
	var rule apiRule
	if err := cl.post(ctx, "/api/v1/policies/"+escape(c.Params["policy"])+"/rules", body, &rule); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: rule.ID}, nil
}

func (policyAddRule) Locate(ctx context.Context, c *provider.Call) (provider.Result, bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, false, err
	}
	rules, err := listRules(ctx, cl, c.Params["policy"])
	if err != nil {
		return provider.Result{}, false, err
	}
	for _, rule := range rules {
		if rule.Name == c.Name {
			return provider.Result{ID: rule.ID}, true, nil
		}
	}
	return provider.Result{}, false, nil
}

func (policyAddRule) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	return cl.del(ctx, "/api/v1/policies/"+escape(c.Params["policy"])+"/rules/"+escape(r.ID))
}

func (policyAddRule) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	ok, err := cl.exists(ctx, "/api/v1/policies/"+escape(c.Params["policy"])+"/rules/"+escape(r.ID))
	return !ok, err
}

// ---- okta.policy.weaken_rule -------------------------------------------

type policyWeaken struct{}

type rulePrior struct {
	PolicyID      string `json:"policy_id"`
	RequireFactor bool   `json:"require_factor"`
}

func (policyWeaken) Spec() provider.Spec {
	return provider.Spec{
		Name:     opPolicyWeaken,
		Summary:  "Weaken a policy rule to no longer require MFA",
		Kind:     provider.KindModify,
		Resource: resPolicyRule,
		Params: []provider.Param{
			{Name: "rule", Type: provider.ParamRef, Ref: resPolicyRule, Required: true, Doc: "The rule to weaken."},
		},
		Scopes:      []string{scopePolicyMgmt},
		Events:      []string{"policy.rule.update"},
		UndoEvents:  []string{"policy.rule.update"},
		Request:     "PUT /api/v1/policies/{policy}/rules/{rule}",
		UndoSummary: "restore the recorded MFA requirement",
		GoneCheck:   "GET /api/v1/policies/{policy}/rules/{rule} -> the recorded MFA requirement",
	}
}

func (policyWeaken) Prior(ctx context.Context, c *provider.Call) (json.RawMessage, error) {
	cl, err := clientOf(c)
	if err != nil {
		return nil, err
	}
	pid, rule, found, err := findRule(ctx, cl, c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("okta: rule %s not found on any run-created policy", c.Params["rule"])
	}
	return json.Marshal(rulePrior{PolicyID: pid, RequireFactor: rule.requiresFactor()})
}

func (policyWeaken) Do(ctx context.Context, c *provider.Call) (provider.Result, error) {
	cl, err := clientOf(c)
	if err != nil {
		return provider.Result{}, err
	}
	pid, rule, found, err := findRule(ctx, cl, c)
	if err != nil {
		return provider.Result{}, err
	}
	if !found {
		return provider.Result{}, fmt.Errorf("okta: rule %s not found", c.Params["rule"])
	}
	if err := cl.put(ctx, "/api/v1/policies/"+escape(pid)+"/rules/"+escape(rule.ID), map[string]any{"actions": mfaAction("1FA")}, nil); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{ID: rule.ID}, nil
}

func (policyWeaken) Undo(ctx context.Context, c *provider.Call, r provider.Record) error {
	cl, err := clientOf(c)
	if err != nil {
		return err
	}
	var prior rulePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil || prior.PolicyID == "" {
		return fmt.Errorf("okta: rule journal holds no prior")
	}
	mode := "1FA"
	if prior.RequireFactor {
		mode = "2FA"
	}
	err = cl.put(ctx, "/api/v1/policies/"+escape(prior.PolicyID)+"/rules/"+escape(c.Params["rule"]), map[string]any{"actions": mfaAction(mode)}, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func (policyWeaken) Gone(ctx context.Context, c *provider.Call, r provider.Record) (bool, error) {
	cl, err := clientOf(c)
	if err != nil {
		return false, err
	}
	var prior rulePrior
	if err := json.Unmarshal(r.Prior, &prior); err != nil {
		return false, fmt.Errorf("okta: rule journal holds no prior")
	}
	var rule apiRule
	err = cl.get(ctx, "/api/v1/policies/"+escape(prior.PolicyID)+"/rules/"+escape(c.Params["rule"]), &rule)
	if isNotFound(err) {
		return true, nil // the rule (or its policy) is gone
	}
	if err != nil {
		return false, err
	}
	return rule.requiresFactor() == prior.RequireFactor, nil
}

// findRule locates the ref'd rule among the run's own policies, returning the
// policy id and the rule. It lists only this run's policies, so it is bounded
// by the run's own objects.
func findRule(ctx context.Context, cl *client, c *provider.Call) (policyID string, rule apiRule, found bool, err error) {
	ruleID := c.Params["rule"]
	prefix := marker.RunPrefix(c.Run) + "-"
	ps, err := listPolicies(ctx, cl)
	if err != nil {
		return "", apiRule{}, false, err
	}
	for _, p := range ps {
		if !strings.HasPrefix(p.Name, prefix) {
			continue
		}
		rules, err := listRules(ctx, cl, p.ID)
		if err != nil {
			return "", apiRule{}, false, err
		}
		for _, r := range rules {
			if r.ID == ruleID {
				return p.ID, r, true, nil
			}
		}
	}
	return "", apiRule{}, false, nil
}

func listPolicies(ctx context.Context, cl *client) ([]apiPolicy, error) {
	raws, err := cl.list(ctx, "/api/v1/policies?type=ACCESS_POLICY")
	if err != nil {
		return nil, err
	}
	out := make([]apiPolicy, 0, len(raws))
	for _, raw := range raws {
		var p apiPolicy
		if json.Unmarshal(raw, &p) == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func listRules(ctx context.Context, cl *client, policyID string) ([]apiRule, error) {
	var rules []apiRule
	if err := cl.get(ctx, "/api/v1/policies/"+escape(policyID)+"/rules", &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// mfaAction builds the rule actions body for a given factor mode.
func mfaAction(mode string) map[string]any {
	return map[string]any{"appSignOn": map[string]any{
		"verificationMethod": map[string]any{"factorMode": mode}}}
}
