package provider

import (
	"context"

	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/version"
)

type uaKey struct{}

// WithUserAgent returns a context whose requests carry ua. The engine sets it
// for every phase of a run; providers read it with UserAgent.
func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, uaKey{}, ua)
}

// UserAgent returns the User-Agent a provider must send with every request
// made under ctx. Without a run marker it identifies the tool alone, so even
// stray calls are attributable.
func UserAgent(ctx context.Context) string {
	if ua, ok := ctx.Value(uaKey{}).(string); ok && ua != "" {
		return ua
	}
	return marker.UserAgent(version.String(), "", marker.PhasePreflight)
}
