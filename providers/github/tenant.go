package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// maxActiveUserScan bounds how many org members Whoami counts, so the count
// (used only by the lab-size guardrail) cannot page without bound.
const maxActiveUserScan = 500

// Tenant is an authenticated connection to one GitHub organization.
type Tenant struct {
	cfg       provider.Config
	org       string
	base      string
	client    *client
	principal string
}

var _ provider.Tenant = (*Tenant)(nil)

// Whoami asks GitHub, live, who the token belongs to: /user gives the
// principal, /orgs/{org} the organization identity, and the membership
// endpoint the principal's org role. The org login is the tenant identifier
// the guardrail matches; a token for a different org cannot read this org at
// all, so the match is live by construction.
func (t *Tenant) Whoami(ctx context.Context) (provider.Identity, error) {
	var me apiUser
	if err := t.client.get(ctx, "/user", &me); err != nil {
		return provider.Identity{}, err
	}
	var org apiOrg
	if err := t.client.get(ctx, "/orgs/"+escape(t.org), &org); err != nil {
		return provider.Identity{}, err
	}
	roles := []string{}
	var mem apiMembership
	if err := t.client.get(ctx, "/user/memberships/orgs/"+escape(t.org), &mem); err == nil && mem.Role != "" {
		roles = append(roles, mem.Role)
	}
	active, err := t.countMembers(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	display := org.Name
	if display == "" {
		display = org.Login
	}
	return provider.Identity{
		Tenant:      org.Login,
		Principal:   me.Login,
		DisplayName: display,
		Domain:      org.Login,
		ShortName:   org.Login,
		Roles:       roles,
		ActiveUsers: active,
	}, nil
}

func (t *Tenant) countMembers(ctx context.Context) (int, error) {
	raws, err := t.client.listUpTo(ctx, "/orgs/"+escape(t.org)+"/members?per_page=100", maxActiveUserScan)
	if err != nil {
		return -1, err
	}
	return len(raws), nil
}

// contentsResponse is the subset of the contents API the marker reader needs.
type contentsResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// ReadMarker reads the ownership marker: a file named MarkerFile at the root of
// the MarkerRepo repository. It only ever reads: a token alone must not be able
// to self-authorise.
func (t *Tenant) ReadMarker(ctx context.Context) (string, bool, error) {
	var resp contentsResponse
	err := t.client.get(ctx, repoPath(t.org, MarkerRepo, "/contents/"+escape(MarkerFile)), &resp)
	if isNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if resp.Encoding != "base64" {
		return "", false, errors.New("github: ownership marker file is not base64-encoded content")
	}
	// GitHub wraps the base64 content with newlines; strip all whitespace.
	raw := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(resp.Content)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", false, errors.New("github: ownership marker file content is not valid base64")
	}
	return strings.TrimSpace(string(decoded)), true, nil
}

// Capabilities probes the org audit-log API: a reachable endpoint means
// telemetry can be verified; the endpoint is GHEC-only, so a Free org answers
// 404 and a token without read:audit_log answers 403.
func (t *Tenant) Capabilities(ctx context.Context) (provider.Caps, error) {
	err := t.client.get(ctx, "/orgs/"+escape(t.org)+"/audit-log?per_page=1", nil)
	if err == nil {
		return provider.Caps{Audit: true, Tier: "ghec"}, nil
	}
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusNotFound:
			return provider.Caps{Audit: false, Tier: "github", Note: "the org audit-log API needs GitHub Enterprise Cloud (GHEC)"}, nil
		case http.StatusForbidden, http.StatusUnauthorized:
			return provider.Caps{Audit: false, Tier: "github", Note: "the token lacks read:audit_log"}, nil
		}
	}
	return provider.Caps{}, err
}

// AuditSource returns the org audit-log reader.
func (t *Tenant) AuditSource() provider.AuditSource { return auditSource{t} }

// Close scrubs the token and releases the client.
func (t *Tenant) Close() error {
	t.client.close()
	return nil
}

type auditSource struct{ t *Tenant }

// wireEvent is the subset of an org audit-log event the collector needs.
// Decoding is defensive: a missing or oddly typed field yields a zero value.
type wireEvent struct {
	DocumentID string `json:"_document_id"`
	Timestamp  int64  `json:"@timestamp"` // milliseconds since the epoch
	Action     string `json:"action"`
	UserAgent  string `json:"user_agent"`
}

// Poll reads the org audit log for the query window. It returns every event in
// the window verbatim; the collector keeps the ones whose recorded User-Agent
// carries this run's marker. GitHub's audit-log phrase filter is date-grained,
// so the window is widened to whole days and the collector refines it.
func (a auditSource) Poll(ctx context.Context, q provider.AuditQuery) ([]provider.Event, error) {
	path := "/orgs/" + escape(a.t.org) + "/audit-log?per_page=100&order=asc"
	if !q.Since.IsZero() {
		path += "&phrase=" + escape("created:>="+q.Since.UTC().Format("2006-01-02"))
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
			ID:        w.DocumentID,
			Time:      time.UnixMilli(w.Timestamp).UTC(),
			Type:      w.Action,
			UserAgent: w.UserAgent,
			Raw:       append(json.RawMessage(nil), raw...),
		})
	}
	return out, nil
}

// Sweep lists every run-created object whose name matches the reserved grammar
// and the given prefix, as orphans the cleaner can remove with the op that
// created them. Children (deploy keys, webhooks, branch protection) come
// before their parents (repos). It never returns an object whose name is not a
// strict saashound-<run>-<step> name, so the ownership-marker repo and the
// org's own repositories can never be swept.
func (t *Tenant) Sweep(ctx context.Context, prefix string) ([]provider.Orphan, error) {
	cl := t.client
	repos, err := t.runRepos(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []provider.Orphan

	// Children first: deploy keys, webhooks and branch protection.
	for _, repo := range repos {
		keys, err := cl.list(ctx, repoPath(t.org, repo.Name, "/keys"))
		if err != nil {
			return nil, err
		}
		for _, raw := range keys {
			var k apiDeployKey
			if json.Unmarshal(raw, &k) == nil && isRunObject(k.Title, prefix) {
				out = append(out, provider.Orphan{Op: opDeployKeyAdd, Name: k.Title, Resource: resDeployKey,
					Params: map[string]string{"repo": repo.Name}, Record: provider.Record{ID: strconv.FormatInt(k.ID, 10)}})
			}
		}
		hooks, err := cl.list(ctx, repoPath(t.org, repo.Name, "/hooks"))
		if err != nil {
			return nil, err
		}
		for _, raw := range hooks {
			var h apiHook
			if json.Unmarshal(raw, &h) != nil {
				continue
			}
			if name, ok := hookObjectName(h.Config.URL); ok && isRunObject(name, prefix) {
				out = append(out, provider.Orphan{Op: opWebhookCreate, Name: name, Resource: resWebhook,
					Params: map[string]string{"repo": repo.Name}, Record: provider.Record{ID: strconv.FormatInt(h.ID, 10)}})
			}
		}
		var bp apiBranchProtection
		err = cl.get(ctx, repoPath(t.org, repo.Name, "/branches/"+escape(defaultBranch)+"/protection"), &bp)
		if err != nil && !isNotFound(err) {
			return nil, err
		}
		if err == nil {
			for _, ctxName := range bp.RequiredStatusChecks.Contexts {
				if isRunObject(ctxName, prefix) {
					out = append(out, provider.Orphan{Op: opBranchProtectionCreate, Name: ctxName, Resource: resBranchProtection,
						Params: map[string]string{"repo": repo.Name}, Record: provider.Record{ID: protectionID(repo.Name)}})
					break
				}
			}
		}
	}

	// Parents: the repositories themselves.
	for _, repo := range repos {
		out = append(out, provider.Orphan{Op: opRepoCreate, Name: repo.Name, Resource: resRepo,
			Record: provider.Record{ID: repo.Name, Outputs: map[string]string{"repo_id": strconv.FormatInt(repo.ID, 10)}}})
	}
	return out, nil
}

// runRepos lists the org's repositories whose name is a strict run-object name
// under prefix.
func (t *Tenant) runRepos(ctx context.Context, prefix string) ([]apiRepo, error) {
	raws, err := t.client.list(ctx, "/orgs/"+escape(t.org)+"/repos?per_page=100")
	if err != nil {
		return nil, err
	}
	var out []apiRepo
	for _, raw := range raws {
		var r apiRepo
		if json.Unmarshal(raw, &r) == nil && isRunObject(r.Name, prefix) {
			out = append(out, r)
		}
	}
	return out, nil
}

// hookObjectName recovers the object name a webhook's config URL encodes
// ("https://saashound-<run>-<step>.invalid/..." -> "saashound-<run>-<step>").
func hookObjectName(configURL string) (string, bool) {
	const scheme = "https://"
	s := strings.TrimPrefix(configURL, scheme)
	if s == configURL {
		return "", false
	}
	host := s
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	name := strings.TrimSuffix(host, ".invalid")
	if name == host {
		return "", false
	}
	return name, true
}

// isRunObject reports whether name is a strict run-object name under prefix.
func isRunObject(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	_, _, ok := marker.ParseObjectName(name)
	return ok
}
