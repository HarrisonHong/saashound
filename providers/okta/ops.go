package okta

import (
	"fmt"
	"net/url"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// Op names. The namespace is the platform; the tactic lives in the technique
// ID and the ATT&CK metadata, never in an op name.
const (
	opUserCreate     = "okta.user.create"
	opFactorEnroll   = "okta.factor.enroll_totp"
	opFactorReset    = "okta.factor.reset"
	opRoleAssign     = "okta.role.assign"
	opZoneCreate     = "okta.zone.create"
	opZoneDeactivate = "okta.zone.deactivate"
	opIdpCreate      = "okta.idp.create"
	opAppCreate      = "okta.app.create_oauth"
	opAppGrantScope  = "okta.app.grant_scope"
	opPolicyCreate   = "okta.policy.create"
	opPolicyAddRule  = "okta.policy.add_rule"
	opPolicyWeaken   = "okta.policy.weaken_rule"

	opIamCreateRole        = "okta.iam.create_role"
	opIamCreateResourceSet = "okta.iam.create_resource_set"
	opIamBindRole          = "okta.iam.bind_role"
)

// Resource types ops create or modify.
const (
	resUser        = "okta.user"
	resFactor      = "okta.factor"
	resZone        = "okta.zone"
	resIdp         = "okta.idp"
	resApp         = "okta.app"
	resPolicy      = "okta.policy"
	resPolicyRule  = "okta.policy_rule"
	resCustomRole  = "okta.custom_role"
	resResourceSet = "okta.resource_set"
)

// Okta OAuth scopes / admin permissions, declared per op for the plan and the
// `auth` scope check. They document least privilege; techniques that assign
// Super Admin or grant app scopes need a Super Admin profile (see the README).
const (
	scopeLogsRead   = "okta.logs.read"
	scopeUsersMgmt  = "okta.users.manage"
	scopeRolesMgmt  = "okta.roles.manage"
	scopeZonesMgmt  = "okta.networkZones.manage"
	scopeIdpsMgmt   = "okta.idps.manage"
	scopeAppsMgmt   = "okta.apps.manage"
	scopePolicyMgmt = "okta.policies.manage"
)

// adminRoles is the closed set of Okta admin role types the role op may grant.
var adminRoles = []string{"SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "HELP_DESK_ADMIN", "READ_ONLY_ADMIN", "GROUP_MEMBERSHIP_ADMIN"}

// appScopes is the closed set of API scopes the service-app op may grant: the
// ones a Salesloft/Drift-style persistent integration would want.
var appScopes = []string{"okta.users.read", "okta.users.manage", "okta.logs.read", "okta.groups.manage", "okta.apps.manage"}

// tenantOf recovers the okta tenant an op was called with.
func tenantOf(c *provider.Call) (*Tenant, error) {
	t, ok := c.Tenant.(*Tenant)
	if !ok {
		return nil, fmt.Errorf("okta op %s called with a %T tenant", c.Step, c.Tenant)
	}
	return t, nil
}

// clientOf recovers the client an op calls through.
func clientOf(c *provider.Call) (*client, error) {
	t, err := tenantOf(c)
	if err != nil {
		return nil, err
	}
	return t.client, nil
}

// loginFor is the deterministic login of a synthetic user, built from the
// object name so it can be found again by exact name after a crash. Any
// invitation goes nowhere: the domain is the operator's declared test domain.
func loginFor(name, testDomain string) string {
	if testDomain == "" {
		testDomain = "example.com"
	}
	return name + "@" + testDomain
}

// containsStr reports membership.
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// escape path-escapes an Okta id so it can never alter the request path.
func escape(s string) string { return url.PathEscape(s) }
