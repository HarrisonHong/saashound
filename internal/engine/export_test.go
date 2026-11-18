package engine

import (
	"context"
	"time"

	"github.com/HarrisonHong/saashound/internal/plan"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/internal/report"
	"github.com/HarrisonHong/saashound/internal/state"
)

// Observe runs telemetry collection alone for a run whose journal is on
// disk, so a test can hand it a tenant that records what collection sends.
func (e *Engine) Observe(ctx context.Context, tenant provider.Tenant, p *plan.Run, since time.Time) (report.Telemetry, error) {
	jpath, err := e.State.File(p.Run, state.JournalFile)
	if err != nil {
		return report.Telemetry{}, err
	}
	exps, err := e.expectations(jpath, p)
	if err != nil {
		return report.Telemetry{}, err
	}
	tel, _ := e.observe(ctx, tenant, p, since, exps)
	return tel, nil
}
