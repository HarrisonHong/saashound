package github

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Name is the platform name and the namespace of its ops and technique IDs.
const Name = "github"

// AuditSourceName is the org audit-log source techniques reference in
// expect[].source.
const AuditSourceName = "github.audit_log"

// optionAPIURL is the targets.yaml option that overrides the REST API base
// URL (for GitHub Enterprise Server, or a mock in tests). The default is
// https://api.github.com.
const optionAPIURL = "api_url"

// MarkerRepo is the repository a tenant admin creates to opt the org in, and
// MarkerFile is the file inside it whose contents are the ownership marker.
// The tool only ever reads them; it never creates either, so a token alone
// cannot self-authorise.
const (
	MarkerRepo = marker.Prefix + "-range"
	MarkerFile = marker.AuthorizationName
)

// orgSlugRe is GitHub's organization-login grammar: alphanumerics and hyphens,
// no leading or trailing hyphen, up to 39 characters.
var orgSlugRe = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$`)

func init() { provider.Register(New()) }

// Provider is the GitHub platform. It is stateless: each Open builds its own
// authenticated client for one organization.
type Provider struct{}

// New returns the GitHub provider.
func New() *Provider { return &Provider{} }

// Name implements provider.Provider.
func (*Provider) Name() string { return Name }

// Audit implements provider.Provider. The org audit-log REST API is GHEC-only
// and ingests within minutes; the deadline is generous to tolerate that lag.
func (*Provider) Audit() provider.AuditInfo {
	return provider.AuditInfo{
		Name:         AuditSourceName,
		TypeField:    "action",
		Deadline:     5 * time.Minute,
		PollInterval: 2 * time.Second,
		Scopes:       []string{scopeReadAuditLog},
	}
}

// Ops implements provider.Provider: the closed vocabulary techniques compose.
func (*Provider) Ops() []provider.Op {
	return []provider.Op{
		repoCreate{},
		deployKeyAdd{},
		webhookCreate{},
		repoAddCollaborator{},
		orgPromoteOwner{},
		repoDisableScanning{},
		branchProtectionCreate{},
		branchUnprotect{},
		repoMakePublic{},
	}
}

// Open builds an authenticated client for one GitHub org. It makes no network
// call, but it does fail fast on a missing credential or a malformed org slug.
func (*Provider) Open(ctx context.Context, cfg provider.Config) (provider.Tenant, error) {
	org := cfg.Target.Tenant
	if !orgSlugRe.MatchString(org) {
		return nil, fmt.Errorf("github: tenant must be the organization login (slug), e.g. acme-labs, got %q", org)
	}
	base, err := parseBase(cfg.Target.Options[optionAPIURL])
	if err != nil {
		return nil, err
	}
	if cfg.Credential.IsZero() {
		return nil, errors.New("github: this target declares no API token; set credential.env or credential.file (use a fine-grained PAT, a GHEC token or a GitHub App installation token; the tool never mints one)")
	}
	tok, err := cfg.Secrets.Resolve(ctx, cfg.Credential)
	if err != nil {
		return nil, err
	}
	if tok.Empty() {
		tok.Wipe()
		return nil, errors.New("github: the API token is empty")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	cl := newClient(base, newAuthTransport(nil, tok), clk, cfg.Trace)
	return &Tenant{cfg: cfg, org: org, base: base.String(), client: cl, principal: cfg.Target.Principal}, nil
}

// MarkerInstructions implements provider.Onboarder: how a tenant admin opts the
// org in. The tool only ever reads this file; it never creates it, so a token
// alone cannot self-authorise.
func (*Provider) MarkerInstructions(t provider.TargetInfo, value string) []string {
	return []string{
		fmt.Sprintf("Create a repository named exactly  %s  in the organization (it can be private).", MarkerRepo),
		fmt.Sprintf("Add a file named  %s  at its root whose only contents are:", MarkerFile),
		fmt.Sprintf("    %s", value),
		"A tenant admin (an org owner) must do this once; SaaSHound only reads it and refuses to run until it is present.",
	}
}

var (
	_ provider.Provider  = (*Provider)(nil)
	_ provider.Onboarder = (*Provider)(nil)
)
