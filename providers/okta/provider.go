package okta

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
)

// Name is the platform name and the namespace of its ops and technique IDs.
const Name = "okta"

// AuditSourceName is the System Log source techniques reference in expect[].source.
const AuditSourceName = "okta.system_log"

func init() { provider.Register(New()) }

// Provider is the Okta platform. It is stateless: each Open builds its own
// authenticated client.
type Provider struct{}

// New returns the Okta provider.
func New() *Provider { return &Provider{} }

// Name implements provider.Provider.
func (*Provider) Name() string { return Name }

// Audit implements provider.Provider. The System Log is near-real-time with a
// 90-day window; the deadline is generous to tolerate ingestion lag.
func (*Provider) Audit() provider.AuditInfo {
	return provider.AuditInfo{
		Name:         AuditSourceName,
		TypeField:    "eventType",
		Deadline:     5 * time.Minute,
		PollInterval: 2 * time.Second,
		Scopes:       []string{scopeLogsRead},
	}
}

// Ops implements provider.Provider: the closed vocabulary techniques compose.
func (*Provider) Ops() []provider.Op {
	return []provider.Op{
		userCreate{},
		factorEnroll{},
		factorReset{},
		roleAssign{},
		zoneCreate{},
		zoneDeactivate{},
		idpCreate{},
		appCreate{},
		appGrantScope{},
		policyCreate{},
		policyAddRule{},
		policyWeaken{},
		iamRoleCreate{},
		iamResourceSetCreate{},
		iamBindRole{},
	}
}

// optKeyID is the target option naming the key ID (kid) to sign with, for a
// PEM key; a JWK carries its own.
const optKeyID = "key_id"

// clientIDRe is the shape of an Okta OAuth client ID.
var clientIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

// Open builds an authenticated client for one Okta org. The target's
// principal is the OAuth 2.0 API Services app's client ID and its credential
// the app's private key. Open makes no network call, but it does fail fast on
// a missing or malformed key, client ID or org URL; the first call mints the
// session's access token, carrying exactly the scopes cfg asks for plus the
// read-only scopes Whoami and the marker read need.
func (*Provider) Open(ctx context.Context, cfg provider.Config) (provider.Tenant, error) {
	base, err := parseBase(cfg.Target.Tenant)
	if err != nil {
		return nil, err
	}
	for k := range cfg.Target.Options {
		if k != optKeyID {
			return nil, fmt.Errorf("okta: unknown target option %q (the okta provider knows only %s)", k, optKeyID)
		}
	}
	clientID := strings.TrimSpace(cfg.Target.Principal)
	switch {
	case strings.Contains(clientID, "@"):
		return nil, fmt.Errorf("okta: principal %q looks like a user login; the okta provider authenticates as an OAuth 2.0 API Services app, so principal must be that app's client ID (see the README's Okta quick-start)", clientID)
	case !clientIDRe.MatchString(clientID):
		return nil, fmt.Errorf("okta: principal %q is not an OAuth client ID; set it to the API Services app's client ID", clientID)
	}
	if cfg.Credential.IsZero() {
		return nil, errors.New("okta: this target declares no credential; set credential.env or credential.file to the service app's private key (PEM or JWK)")
	}
	key, err := cfg.Secrets.Resolve(ctx, cfg.Credential)
	if err != nil {
		return nil, err
	}
	if key.Empty() {
		key.Wipe()
		return nil, errors.New("okta: the service app's private key is empty")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	src, err := newTokenSource(tokenConfig{
		base:     base,
		clientID: clientID,
		key:      key,
		keyID:    strings.TrimSpace(cfg.Target.Options[optKeyID]),
		scopes:   planSessionScopes(cfg.Scopes, cfg.OptionalScopes, cfg.ReadOnly),
		clk:      clk,
		trace:    cfg.Trace,
	})
	if err != nil {
		key.Wipe()
		return nil, err
	}
	cl := newClient(base, newAuthTransport(nil, src), clk, cfg.Trace)
	return &Tenant{cfg: cfg, base: base, client: cl, principal: clientID}, nil
}

// MarkerInstructions implements provider.Onboarder: how a tenant admin opts the
// org in. The tool only ever reads this group and never asks for
// okta.groups.manage, so a token it holds cannot create the group: a token
// alone cannot self-authorise.
func (*Provider) MarkerInstructions(t provider.TargetInfo, value string) []string {
	return []string{
		"In the Okta Admin Console, go to Directory > Groups > Add group.",
		fmt.Sprintf("Name the group exactly  %s", marker.AuthorizationName),
		fmt.Sprintf("and set its Description to  %s", value),
		"A tenant admin must do this once; SaaSHound only reads it and refuses to run until it is present.",
	}
}

var (
	_ provider.Provider  = (*Provider)(nil)
	_ provider.Onboarder = (*Provider)(nil)
)
