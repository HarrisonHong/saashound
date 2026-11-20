package okta

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/secret"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// TestCredentialNeverLeavesTheOrg proves the access token goes to the org's own
// host and nowhere else: a request built for another host is refused before it
// is sent, and a redirect from the org is not followed.
func TestCredentialNeverLeavesTheOrg(t *testing.T) {
	srv := mockokta.New()
	defer srv.Close()
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer elsewhere.Close()

	// The "org" is a front that passes OAuth through to the mock but answers
	// one API call with a redirect off the org.
	mockURL, _ := url.Parse(srv.URL())
	proxy := httputil.NewSingleHostReverseProxy(mockURL)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/org" {
			http.Redirect(w, r, elsewhere.URL+"/api/v1/org", http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()

	base, err := parseBase(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	src, err := newTokenSource(tokenConfig{
		base: base, clientID: srv.ClientID(), key: secret.New(mockokta.DefaultKey().JWK()),
		scopes: planSessionScopes(nil, nil, false), clk: clock.Real{},
	})
	if err != nil {
		t.Fatal(err)
	}
	cl := newClient(base, newAuthTransport(nil, src), clock.Real{}, nil)
	defer cl.close()
	ctx := context.Background()

	if err := cl.get(ctx, "/api/v1/groups", nil); err != nil {
		t.Fatalf("a call to the org failed: %v", err)
	}
	err = cl.doURL(ctx, http.MethodGet, elsewhere.URL+"/api/v1/users", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to send the org's credential") {
		t.Fatalf("off-org request = %v; want it refused", err)
	}
	err = cl.get(ctx, "/api/v1/org", nil)
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != http.StatusTemporaryRedirect {
		t.Fatalf("redirected call = %v; want the 307 returned, not followed", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the other host received %d requests", n)
	}
}
