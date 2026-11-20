package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// maxActiveUserScan bounds how many active users Whoami counts, so the count
// (used only by the lab-size guardrail) cannot page without bound.
const maxActiveUserScan = 500

// Tenant is an authenticated connection to one Okta org.
type Tenant struct {
	cfg       provider.Config
	base      *url.URL
	client    *client
	principal string
}

var _ provider.Tenant = (*Tenant)(nil)

// Whoami asks the org, live, who this session's token belongs to. The org's
// introspection endpoint (RFC 7662) names the client the token was issued to,
// which the guardrail matches against the target's principal, and the scopes
// it carries; /org gives the org's identity. The org URL is the tenant
// identifier the guardrail matches: a key registered in a different org
// cannot obtain a token from this one at all, so the match is live by
// construction.
func (t *Tenant) Whoami(ctx context.Context) (provider.Identity, error) {
	src := t.client.auth.src
	in, err := src.introspect(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	if !in.Active {
		return provider.Identity{}, errors.New("okta: the org reports this session's access token as inactive")
	}
	if in.ClientID == "" {
		return provider.Identity{}, errors.New("okta: the org's token introspection did not name the token's client")
	}
	scopes := scopeSet(strings.Fields(in.Scope)...)
	if len(scopes) == 0 {
		if scopes, err = src.scopes(ctx); err != nil {
			return provider.Identity{}, err
		}
	}
	var org apiOrg
	if err := t.client.get(ctx, "/api/v1/org", &org); err != nil {
		return provider.Identity{}, err
	}
	// The app's admin roles bound what its scopes allow. They are shown when
	// this session may read them; no session asks for a scope just for this.
	roles := []string{}
	if hasScope(scopes, familyRoles, false) {
		var rr []apiRole
		if err := t.client.get(ctx, "/oauth2/v1/clients/"+escape(in.ClientID)+"/roles", &rr); err == nil {
			for _, r := range rr {
				roles = append(roles, r.Type)
			}
		}
	}
	active, err := t.countActiveUsers(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	short := org.Subdomain
	if short == "" {
		short = t.base.Hostname()
	}
	return provider.Identity{
		Tenant:      t.base.String(),
		Principal:   in.ClientID,
		DisplayName: org.CompanyName,
		Domain:      t.base.Host,
		ShortName:   short,
		Roles:       roles,
		Scopes:      scopes,
		Credential:  fmt.Sprintf("%s; a per-session access token valid %s", src.describe(), fmtLifetime(src.tokenLifetime())),
		ActiveUsers: active,
	}, nil
}

func (t *Tenant) countActiveUsers(ctx context.Context) (int, error) {
	raws, err := t.client.listUpTo(ctx, "/api/v1/users?filter="+escape(`status eq "ACTIVE"`)+"&limit=200", maxActiveUserScan)
	if err != nil {
		return -1, err
	}
	return len(raws), nil
}

// ReadMarker reads the ownership group's description. It only ever reads, with
// okta.groups.read: no session asks for okta.groups.manage, so a token alone
// cannot self-authorise.
func (t *Tenant) ReadMarker(ctx context.Context) (string, bool, error) {
	var groups []apiGroup
	if err := t.client.get(ctx, "/api/v1/groups?q="+escape(marker.AuthorizationName), &groups); err != nil {
		return "", false, err
	}
	for _, g := range groups {
		if g.Profile.Name == marker.AuthorizationName {
			return g.Profile.Description, true, nil
		}
	}
	return "", false, nil
}

// Capabilities probes the System Log: a reachable /logs means telemetry can be
// verified. The session's token carries okta.logs.read whenever the caller
// asked for the audit scopes, so a 403 means the app's admin role cannot read
// the System Log.
func (t *Tenant) Capabilities(ctx context.Context) (provider.Caps, error) {
	err := t.client.get(ctx, "/api/v1/logs?limit=1", nil)
	if err == nil {
		return provider.Caps{Audit: true, Tier: "okta"}, nil
	}
	var ae *apiError
	if errors.As(err, &ae) && (ae.Status == 403 || ae.Status == 401) {
		return provider.Caps{Audit: false, Tier: "okta", Note: "the service app cannot read the System Log (it needs okta.logs.read and an admin role that may read it)"}, nil
	}
	return provider.Caps{}, err
}

// AuditSource returns the System Log reader.
func (t *Tenant) AuditSource() provider.AuditSource { return auditSource{t} }

// Close scrubs the key and the token and releases the client.
func (t *Tenant) Close() error {
	t.client.close()
	return nil
}

type auditSource struct{ t *Tenant }

// wireEvent is the subset of a System Log event the collector needs. Decoding
// is defensive (see provider.DecodeEvent): a missing or oddly typed field
// yields a zero value.
type wireEvent struct {
	UUID      string             `json:"uuid"`
	Published provider.EventTime `json:"published"`
	EventType string             `json:"eventType"`
	Client    struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
	} `json:"client"`
	Target []wireTarget `json:"target"`
}

// wireTarget is one System Log target. Okta names the object in displayName
// (a zone, policy, rule, app label, IdP, role or resource set) and, for a
// user, puts the login in alternateId.
type wireTarget struct {
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

// objects returns every target name the event records, for the collector's
// name-prefix correlation.
func (w wireEvent) objects() []string {
	var out []string
	for _, t := range w.Target {
		for _, v := range []string{t.DisplayName, t.AlternateID} {
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// Poll reads the System Log for the query window. It returns every event in
// the window verbatim, with its recorded User-Agent and target names; the
// collector keeps the ones that are this run's.
func (a auditSource) Poll(ctx context.Context, q provider.AuditQuery) ([]provider.Event, error) {
	path := "/api/v1/logs?limit=100"
	if !q.Since.IsZero() {
		path += "&since=" + escape(q.Since.UTC().Format(time.RFC3339Nano))
	}
	if !q.Until.IsZero() {
		path += "&until=" + escape(q.Until.UTC().Format(time.RFC3339Nano))
	}
	raws, err := a.t.client.list(ctx, path)
	if err != nil {
		return nil, err
	}
	out := make([]provider.Event, 0, len(raws))
	for _, raw := range raws {
		var w wireEvent
		if !provider.DecodeEvent(raw, &w) {
			continue
		}
		out = append(out, provider.Event{
			ID:        w.UUID,
			Time:      w.Published.Time,
			Type:      w.EventType,
			UserAgent: w.Client.UserAgent.RawUserAgent,
			Objects:   w.objects(),
			Raw:       append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

// Sweep lists every run-created object whose name matches the reserved grammar
// and the given prefix, as orphans the cleaner can remove with the op that
// created them. Children (factors, rules) come before their parents (users,
// policies). It never returns an object whose name is not a strict
// saashound-<run>-<step> name, so the service app itself, the org's admins and
// the ownership group can never be swept.
//
// Every family it lists must be readable with this session's token: a family
// the token cannot see is an error naming the scope to grant, never a silent
// gap that would report the tenant clean. A session that may write (sweep
// --delete) must also hold the manage scope of every kind of object found, so
// a deletion the org would refuse is refused here, before anyone confirms it.
func (t *Tenant) Sweep(ctx context.Context, prefix string) ([]provider.Orphan, error) {
	scopes, err := t.requireSweepScopes(ctx)
	if err != nil {
		return nil, err
	}
	cl := t.client
	var out []provider.Orphan

	// The run's own synthetic users, by login prefix.
	users, err := runUsers(ctx, cl, prefix)
	if err != nil {
		return nil, err
	}
	// Factors first (children of users).
	for _, u := range users {
		factors, err := listFactors(ctx, cl, u.ID)
		if err != nil {
			return nil, err
		}
		for _, f := range factors {
			if isRunObject(f.Profile.CredentialID, prefix) {
				out = append(out, provider.Orphan{Op: opFactorEnroll, Name: f.Profile.CredentialID, Resource: resFactor,
					Params: map[string]string{"user": u.ID}, Record: provider.Record{ID: f.ID}})
			}
		}
	}

	// Policy rules first (children of policies), then the policies.
	policies, err := listPolicies(ctx, cl)
	if err != nil {
		return nil, err
	}
	var runPolicies []apiPolicy
	for _, p := range policies {
		if isRunObject(p.Name, prefix) {
			runPolicies = append(runPolicies, p)
		}
	}
	for _, p := range runPolicies {
		rules, err := listRules(ctx, cl, p.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if isRunObject(r.Name, prefix) {
				out = append(out, provider.Orphan{Op: opPolicyAddRule, Name: r.Name, Resource: resPolicyRule,
					Params: map[string]string{"policy": p.ID}, Record: provider.Record{ID: r.ID}})
			}
		}
	}

	// Parents and standalone objects.
	for _, u := range users {
		name := objectNameFromLogin(u.Profile.Login)
		if isRunObject(name, prefix) {
			out = append(out, provider.Orphan{Op: opUserCreate, Name: name, Resource: resUser,
				Record: provider.Record{ID: u.ID, Outputs: map[string]string{"login": u.Profile.Login}}})
		}
	}
	apps, err := cl.list(ctx, "/api/v1/apps")
	if err != nil {
		return nil, err
	}
	for _, raw := range apps {
		var a apiApp
		if json.Unmarshal(raw, &a) == nil && isRunObject(a.Label, prefix) {
			out = append(out, provider.Orphan{Op: opAppCreate, Name: a.Label, Resource: resApp, Record: provider.Record{ID: a.ID}})
		}
	}
	idps, err := cl.list(ctx, "/api/v1/idps")
	if err != nil {
		return nil, err
	}
	for _, raw := range idps {
		var idp apiIdp
		if json.Unmarshal(raw, &idp) == nil && isRunObject(idp.Name, prefix) {
			out = append(out, provider.Orphan{Op: opIdpCreate, Name: idp.Name, Resource: resIdp, Record: provider.Record{ID: idp.ID}})
		}
	}
	zones, err := cl.list(ctx, "/api/v1/zones")
	if err != nil {
		return nil, err
	}
	for _, raw := range zones {
		var z apiZone
		if json.Unmarshal(raw, &z) == nil && isRunObject(z.Name, prefix) {
			out = append(out, provider.Orphan{Op: opZoneCreate, Name: z.Name, Resource: resZone, Record: provider.Record{ID: z.ID}})
		}
	}
	for _, p := range runPolicies {
		out = append(out, provider.Orphan{Op: opPolicyCreate, Name: p.Name, Resource: resPolicy, Record: provider.Record{ID: p.ID}})
	}
	croles, err := cl.list(ctx, "/api/v1/iam/roles")
	if err != nil {
		return nil, err
	}
	for _, raw := range croles {
		var cr apiCustomRole
		if json.Unmarshal(raw, &cr) == nil && isRunObject(cr.Label, prefix) {
			out = append(out, provider.Orphan{Op: opIamCreateRole, Name: cr.Label, Resource: resCustomRole, Record: provider.Record{ID: cr.ID}})
		}
	}
	rsets, err := cl.list(ctx, "/api/v1/iam/resource-sets")
	if err != nil {
		return nil, err
	}
	for _, raw := range rsets {
		var rs apiResourceSet
		if json.Unmarshal(raw, &rs) == nil && isRunObject(rs.Label, prefix) {
			out = append(out, provider.Orphan{Op: opIamCreateResourceSet, Name: rs.Label, Resource: resResourceSet, Record: provider.Record{ID: rs.ID}})
		}
	}
	if !t.cfg.ReadOnly {
		if err := requireDeleteScopes(scopes, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// sweepFamilies are the scope families Sweep lists, with what it calls them
// and the resources each one's manage scope is needed to delete.
var sweepFamilies = []struct {
	family, what string
	resources    []string
}{
	{familyUsers, "users and their factors", []string{resUser, resFactor}},
	{familyPolicies, "policies and their rules", []string{resPolicy, resPolicyRule}},
	{familyApps, "apps", []string{resApp}},
	{familyIdps, "identity providers", []string{resIdp}},
	{familyNetworkZones, "network zones", []string{resZone}},
	{familyRoles, "custom admin roles and resource sets", []string{resCustomRole, resResourceSet}},
}

// requireDeleteScopes fails, naming every gap, unless scopes hold the manage
// scope of each family that has an orphan. A family with nothing to delete
// never blocks the sweep.
func requireDeleteScopes(scopes []string, orphans []provider.Orphan) error {
	found := map[string]bool{}
	for _, o := range orphans {
		found[o.Resource] = true
	}
	var whats, grants []string
	for _, f := range sweepFamilies {
		if hasScope(scopes, f.family, true) {
			continue
		}
		for _, r := range f.resources {
			if found[r] {
				whats = append(whats, f.what)
				grants = append(grants, f.family+".manage")
				break
			}
		}
	}
	if len(whats) == 0 {
		return nil
	}
	return fmt.Errorf("okta: sweep --delete found %s this token may list but not delete; "+
		"grant %s (or run sweep without --delete to list only)", strings.Join(whats, ", "), strings.Join(grants, ", "))
}

// requireSweepScopes returns the session token's scopes, or fails, naming
// every gap, unless that token may read every family Sweep lists. A read-only
// session asks only for read scopes, so there a granted manage scope does not
// help and the advice names the read scope alone.
func (t *Tenant) requireSweepScopes(ctx context.Context) ([]string, error) {
	scopes, err := t.client.auth.src.scopes(ctx)
	if err != nil {
		return nil, err
	}
	var gaps []string
	for _, f := range sweepFamilies {
		if hasScope(scopes, f.family, false) {
			continue
		}
		if t.cfg.ReadOnly {
			gaps = append(gaps, fmt.Sprintf("%s (grant %s.read)", f.what, f.family))
		} else {
			gaps = append(gaps, fmt.Sprintf("%s (grant %s.manage, or %s.read to list only)", f.what, f.family, f.family))
		}
	}
	if len(gaps) == 0 {
		return scopes, nil
	}
	need := ""
	if t.cfg.ReadOnly {
		need = "a listing sweep needs the .read scope of each kind, and "
	}
	return nil, fmt.Errorf("okta: sweep cannot see every kind of object a run creates, so it cannot prove the org clean; "+
		"%sthis session's token may not list %s", need, strings.Join(gaps, "; "))
}

// runUsers lists users whose login carries the run prefix.
func runUsers(ctx context.Context, cl *client, prefix string) ([]apiUser, error) {
	raws, err := cl.list(ctx, "/api/v1/users?search="+escape(`profile.login sw "`+prefix+`"`)+"&limit=200")
	if err != nil {
		return nil, err
	}
	var out []apiUser
	for _, raw := range raws {
		var u apiUser
		if json.Unmarshal(raw, &u) == nil {
			out = append(out, u)
		}
	}
	return out, nil
}

// objectNameFromLogin recovers the object name from a synthetic user's login
// ("saashound-<run>-<step>@domain" -> "saashound-<run>-<step>").
func objectNameFromLogin(login string) string {
	if i := strings.IndexByte(login, '@'); i >= 0 {
		return login[:i]
	}
	return login
}

// isRunObject reports whether name is a strict run-object name under prefix.
func isRunObject(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	_, _, ok := marker.ParseObjectName(name)
	return ok
}
