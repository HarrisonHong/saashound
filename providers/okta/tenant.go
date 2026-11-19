package okta

import (
	"context"
	"encoding/json"
	"errors"
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

// Whoami asks the org, live, who the SSWS token belongs to: /users/me gives the
// principal, /org the org identity. The org URL is the tenant identifier the
// guardrail matches; a token for a different org cannot authenticate against
// this URL at all, so the match is live by construction.
func (t *Tenant) Whoami(ctx context.Context) (provider.Identity, error) {
	var me apiUser
	if err := t.client.get(ctx, "/api/v1/users/me", &me); err != nil {
		return provider.Identity{}, err
	}
	var org apiOrg
	if err := t.client.get(ctx, "/api/v1/org", &org); err != nil {
		return provider.Identity{}, err
	}
	roles := []string{}
	var rr []apiRole
	if err := t.client.get(ctx, "/api/v1/users/"+escape(me.ID)+"/roles", &rr); err == nil {
		for _, r := range rr {
			roles = append(roles, r.Type)
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
		Principal:   me.Profile.Login,
		DisplayName: org.CompanyName,
		Domain:      t.base.Host,
		ShortName:   short,
		Roles:       roles,
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

// ReadMarker reads the ownership group's description. It only ever reads: a
// token alone must not be able to self-authorise.
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
// verified; a 403 means the token lacks okta.logs.read.
func (t *Tenant) Capabilities(ctx context.Context) (provider.Caps, error) {
	err := t.client.get(ctx, "/api/v1/logs?limit=1", nil)
	if err == nil {
		return provider.Caps{Audit: true, Tier: "okta"}, nil
	}
	var ae *apiError
	if errors.As(err, &ae) && (ae.Status == 403 || ae.Status == 401) {
		return provider.Caps{Audit: false, Tier: "okta", Note: "the token lacks okta.logs.read"}, nil
	}
	return provider.Caps{}, err
}

// AuditSource returns the System Log reader.
func (t *Tenant) AuditSource() provider.AuditSource { return auditSource{t} }

// Close scrubs the token and releases the client.
func (t *Tenant) Close() error {
	t.client.close()
	return nil
}

type auditSource struct{ t *Tenant }

// wireEvent is the subset of a System Log event the collector needs. Decoding
// is defensive: a missing or oddly typed field yields a zero value.
type wireEvent struct {
	UUID      string    `json:"uuid"`
	Published time.Time `json:"published"`
	EventType string    `json:"eventType"`
	Client    struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
		} `json:"userAgent"`
	} `json:"client"`
}

// Poll reads the System Log for the query window. It returns every event in
// the window verbatim; the collector keeps the ones whose recorded User-Agent
// carries this run's marker.
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
		if json.Unmarshal(raw, &w) != nil {
			continue
		}
		out = append(out, provider.Event{
			ID:        w.UUID,
			Time:      w.Published,
			Type:      w.EventType,
			UserAgent: w.Client.UserAgent.RawUserAgent,
			Raw:       append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

// Sweep lists every run-created object whose name matches the reserved grammar
// and the given prefix, as orphans the cleaner can remove with the op that
// created them. Children (factors, rules) come before their parents (users,
// policies). It never returns an object whose name is not a strict
// saashound-<run>-<step> name, so the token's own user and the ownership group
// can never be swept.
func (t *Tenant) Sweep(ctx context.Context, prefix string) ([]provider.Orphan, error) {
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
	return out, nil
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
