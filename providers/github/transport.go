package github

import (
	"net/http"

	"github.com/HarrisonHong/saashound/internal/secret"
)

// authTransport is the one place in the github provider that reads the raw
// token: it sets the Authorization header and nothing else. Every other file
// sees only the redacting secret.Value, which the policy test enforces by
// allowing Reveal() solely in a provider's transport.go.
//
// GitHub accepts a bearer token for a fine-grained personal access token, a
// GHEC token or a GitHub App installation token: `Authorization: Bearer
// <token>`. The tool never mints one over the API; the operator supplies it
// from an environment variable or a 0600 key file, and it is never written to
// disk, a log or the journal.
type authTransport struct {
	base  http.RoundTripper
	token secret.Value
}

func newAuthTransport(base http.RoundTripper, token secret.Value) *authTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &authTransport{base: base, token: token}
}

// RoundTrip adds the Authorization header to a clone of the request, so the
// caller's request is never mutated and the header is set exactly once per
// hop. The revealed token lives only for the duration of the call.
func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+t.token.Reveal())
	return t.base.RoundTrip(r2)
}

// wipe scrubs the token from memory.
func (t *authTransport) wipe() { t.token.Wipe() }
