package okta

import (
	"context"
	"errors"
	"fmt"
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

// Open builds an authenticated client for one Okta org. It makes no network
// call, but it does fail fast on a missing credential or a malformed org URL.
func (*Provider) Open(ctx context.Context, cfg provider.Config) (provider.Tenant, error) {
	base, err := parseBase(cfg.Target.Tenant)
	if err != nil {
		return nil, err
	}
	if cfg.Credential.IsZero() {
		return nil, errors.New("okta: this target declares no SSWS API token; set credential.env or credential.file (Okta cannot mint tokens over the API)")
	}
	tok, err := cfg.Secrets.Resolve(ctx, cfg.Credential)
	if err != nil {
		return nil, err
	}
	if tok.Empty() {
		tok.Wipe()
		return nil, errors.New("okta: the SSWS token is empty")
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	cl := newClient(base, newAuthTransport(nil, tok), clk, cfg.Trace)
	return &Tenant{cfg: cfg, base: base, client: cl, principal: cfg.Target.Principal}, nil
}

// MarkerInstructions implements provider.Onboarder: how a tenant admin opts the
// org in. The tool only ever reads this group; it never creates it, so a token
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
