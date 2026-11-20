package okta_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HarrisonHong/saashound/internal/clock"
	"github.com/HarrisonHong/saashound/internal/marker"
	"github.com/HarrisonHong/saashound/internal/provider"
	"github.com/HarrisonHong/saashound/providers/okta"
	"github.com/HarrisonHong/saashound/providers/okta/mockokta"
)

// baseScopes are the read-only scopes every session adds to what it is asked
// for: the org, the lab-size count and the marker group.
var baseScopes = []string{"okta.groups.read", "okta.orgs.read", "okta.users.read"}

func sorted(s ...string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// assertNoCredential fails if s contains any access token or client assertion
// the org saw, or any line of a private key.
func assertNoCredential(t *testing.T, s string, srv *mockokta.Server, keys ...string) {
	t.Helper()
	for _, c := range srv.Credentials() {
		if strings.Contains(s, c) {
			t.Fatalf("a token or client assertion leaked: %q", s)
		}
	}
	// Key material is long base64: PEM body lines, or JWK member values.
	for _, k := range keys {
		for _, f := range strings.FieldsFunc(k, func(r rune) bool { return r == '\n' || r == '"' }) {
			if len(f) >= 32 && !strings.HasPrefix(f, "-----") && strings.Contains(s, f) {
				t.Fatalf("private key material leaked: %q", s)
			}
		}
	}
}

func pkcs1PEM(t *testing.T, k *mockokta.Key) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(k.Private.(*rsa.PrivateKey))
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

// sec1PEM is what `openssl ecparam -genkey` writes: the curve parameters,
// then the SEC 1 key.
func sec1PEM(t *testing.T, k *mockokta.Key) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k.Private.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}})
	return string(params) + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func publicPEM(t *testing.T, k *mockokta.Key) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func ed25519PEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TestFullyGrantedAppNeedsOneRequest proves an app holding every scope a
// session asks for gets its token in one request, with no probing and no read
// scope its manage scope already covers.
func TestFullyGrantedAppNeedsOneRequest(t *testing.T) {
	srv, cfg := newMock(t)
	cfg.Scopes = []string{"okta.logs.read"}
	cfg.OptionalScopes = allOpScopes()
	if _, err := open(t, cfg).Whoami(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := srv.TokenScopes()
	if len(got) != 1 || slices.Contains(got[0], "okta.idps.read") || !slices.Contains(got[0], "okta.idps.manage") {
		t.Fatalf("tokens = %v; want one, with manage scopes and no redundant reads", got)
	}
}

// TestOneTokenPerSessionWithExactlyItsScopes proves a session mints one token,
// on its first call, carrying exactly the scopes it was asked for plus the
// read-only base, and reuses it for every later call.
func TestOneTokenPerSessionWithExactlyItsScopes(t *testing.T) {
	srv, cfg := newMock(t)
	cfg.Scopes = []string{"okta.users.manage", "okta.logs.read"}
	ten, err := okta.New().Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ten.Close()
	if srv.Mints() != 0 {
		t.Fatal("Open must not call the org")
	}
	ctx := context.Background()
	if _, err := ten.Whoami(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ten.ReadMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ten.Capabilities(ctx); err != nil {
		t.Fatal(err)
	}
	got := srv.TokenScopes()
	want := sorted(append(baseScopes, "okta.users.manage", "okta.logs.read")...)
	if len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("tokens minted = %v; want exactly one carrying %v", got, want)
	}
}

// TestNoTokenCanCreateTheMarker proves the ownership marker is unspoofable by
// the tool's own token: even with the app granted okta.groups.manage and a
// session asking for every scope any op or the corpus could need, the token
// does not carry it, and the org refuses it a group create.
func TestNoTokenCanCreateTheMarker(t *testing.T) {
	srv, cfg := newMock(t)
	cfg.OptionalScopes = allOpScopes()
	ten := open(t, cfg)
	if _, err := ten.Whoami(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, scopes := range srv.TokenScopes() {
		if slices.Contains(scopes, "okta.groups.manage") {
			t.Fatalf("a session asked for okta.groups.manage: %v", scopes)
		}
	}
	var tok string
	for _, c := range srv.Credentials() {
		if strings.HasPrefix(c, "mock-at-") {
			tok = c
		}
	}
	body := strings.NewReader(`{"profile":{"name":"saashound-authorized","description":"saashound-authorized:forged"}}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL()+"/api/v1/groups", body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("creating the marker group with the session's token answered %d; want 403", resp.StatusCode)
	}
	if _, found, _ := ten.ReadMarker(context.Background()); found {
		t.Fatal("the marker group exists")
	}
}

// TestMissingRequiredScopeIsNamed proves a session that needs a scope the app
// was not granted fails before any API call, naming exactly that scope. To
// name it, the session asks for each scope alone; those probe tokens carry a
// single scope each and are dropped unused.
func TestMissingRequiredScopeIsNamed(t *testing.T) {
	srv, cfg := newMock(t, mockokta.WithoutScopes("okta.idps.manage", "okta.appGrants.manage"))
	cfg.Scopes = []string{"okta.idps.manage", "okta.logs.read"}
	before := srv.Snapshot()
	ten := open(t, cfg)
	_, err := ten.Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not granted okta.idps.manage,") || strings.Contains(err.Error(), "appGrants") {
		t.Fatalf("missing scope = %v; want a refusal naming okta.idps.manage alone", err)
	}
	for _, scopes := range srv.TokenScopes() {
		if len(scopes) != 1 {
			t.Fatalf("a refused session obtained a token for %v", scopes)
		}
	}
	if after := srv.Snapshot(); string(after) != string(before) {
		t.Fatal("the org changed")
	}
}

// TestMissingBaseScopeFailsAuthToo proves a session that asks for optional
// scopes (as auth does) still fails, naming it, when a scope every session
// needs is missing.
func TestMissingBaseScopeFailsAuthToo(t *testing.T) {
	srv, cfg := newMock(t, mockokta.WithoutScopes("okta.groups.read", "okta.idps.manage"))
	cfg.Scopes = []string{"okta.logs.read"}
	cfg.OptionalScopes = allOpScopes()
	_, err := open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not granted okta.groups.read,") {
		t.Fatalf("missing base scope = %v; want a refusal naming okta.groups.read alone", err)
	}
	for _, scopes := range srv.TokenScopes() {
		if len(scopes) != 1 {
			t.Fatalf("a refused session obtained a token for %v", scopes)
		}
	}
}

// TestOptionalScopesAreBestEffort proves optional scopes the app lacks are
// left out, not fatal, that a manage scope the app lacks falls back to its
// read scope, and that Whoami reports what the session got.
func TestOptionalScopesAreBestEffort(t *testing.T) {
	srv, cfg := newMock(t, mockokta.WithoutScopes("okta.appGrants.manage", "okta.appGrants.read", "okta.idps.manage"))
	cfg.Scopes = []string{"okta.logs.read"}
	cfg.OptionalScopes = allOpScopes()
	ten := open(t, cfg)
	id, err := ten.Whoami(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := sorted(append(baseScopes, "okta.logs.read", "okta.apps.manage", "okta.idps.read", "okta.networkZones.manage",
		"okta.policies.manage", "okta.roles.manage", "okta.users.manage")...)
	if !slices.Equal(id.Scopes, want) {
		t.Fatalf("scopes = %v; want %v", id.Scopes, want)
	}
	// Later calls reuse the resolved set without probing again.
	n := srv.Mints()
	if _, _, err := ten.ReadMarker(context.Background()); err != nil || srv.Mints() != n {
		t.Fatalf("ReadMarker re-minted (%d -> %d): %v", n, srv.Mints(), err)
	}
}

// TestTokenRefreshedBeforeExpiry proves the session replaces its token shortly
// before it expires, and not before.
func TestTokenRefreshedBeforeExpiry(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	srv, cfg := newMock(t, mockokta.WithClock(clk.Now))
	cfg.Clock = clk
	ten := open(t, cfg)
	ctx := context.Background()
	marker := func() {
		t.Helper()
		if _, _, err := ten.ReadMarker(ctx); err != nil {
			t.Fatal(err)
		}
	}
	marker()
	clk.Advance(50 * time.Minute)
	marker()
	if srv.Mints() != 1 {
		t.Fatalf("token replaced after 50m of 1h: %d mints", srv.Mints())
	}
	clk.Advance(6 * time.Minute)
	marker()
	if srv.Mints() != 2 {
		t.Fatalf("token not replaced within 5m of expiry: %d mints", srv.Mints())
	}
}

// TestRevokedTokenIsReplacedOnce proves a token the org stops accepting
// mid-session is replaced, and the call retried once.
func TestRevokedTokenIsReplacedOnce(t *testing.T) {
	srv, cfg := newMock(t)
	ten := open(t, cfg)
	ctx := context.Background()
	if _, err := ten.Whoami(ctx); err != nil {
		t.Fatal(err)
	}
	srv.RevokeTokens()
	if _, _, err := ten.ReadMarker(ctx); err != nil {
		t.Fatalf("ReadMarker after revocation: %v", err)
	}
	if srv.Mints() != 2 {
		t.Fatalf("mints = %d, want 2", srv.Mints())
	}
}

// TestClientAssertionShape checks, from the tool's side, every assertion it
// sent: RS256 with the key's kid, iss = sub = the client ID, aud exactly the
// endpoint, valid for five minutes from now (iat backdated half a minute, for
// a local clock running fast) and a jti never reused.
func TestClientAssertionShape(t *testing.T) {
	srv, cfg := newMock(t)
	ten := open(t, cfg)
	ctx := context.Background()
	if _, err := ten.Whoami(ctx); err != nil { // a token and an introspection
		t.Fatal(err)
	}
	srv.RevokeTokens()
	if _, _, err := ten.ReadMarker(ctx); err != nil { // a second token
		t.Fatal(err)
	}
	jtis := map[string]bool{}
	auds := map[string]int{}
	n := 0
	for _, c := range srv.Credentials() {
		parts := strings.Split(c, ".")
		if len(parts) != 3 {
			continue // an access token
		}
		n++
		var hdr struct{ Alg, Kid, Typ string }
		var cl struct {
			Iss, Sub, Aud, Jti string
			Iat, Exp           int64
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &cl) != nil {
			t.Fatalf("assertion %d does not decode", n)
		}
		if hdr.Alg != "RS256" || hdr.Kid != mockokta.DefaultKeyID || hdr.Typ != "JWT" {
			t.Errorf("header %+v", hdr)
		}
		if cl.Iss != srv.ClientID() || cl.Sub != srv.ClientID() {
			t.Errorf("iss/sub %q/%q", cl.Iss, cl.Sub)
		}
		if now := time.Now().Unix(); cl.Iat > now-25 || cl.Exp > now+300 || cl.Exp-cl.Iat != 330 {
			t.Errorf("iat %d exp %d at %d; want iat 30s back, exp 5m ahead", cl.Iat, cl.Exp, now)
		}
		if jtis[cl.Jti] || len(cl.Jti) < 16 {
			t.Errorf("jti %q reused or short", cl.Jti)
		}
		jtis[cl.Jti] = true
		auds[cl.Aud]++
	}
	if auds[srv.URL()+"/oauth2/v1/token"] != 2 || auds[srv.URL()+"/oauth2/v1/introspect"] != 1 || n != 3 {
		t.Fatalf("assertions by audience = %v (%d total); want 2 token, 1 introspect", auds, n)
	}
}

// TestKeyFormats proves every key form an operator may hold authenticates:
// the console's JWK and PEM, PKCS#1 and SEC 1 PEM, EC curves, and a PEM key
// whose kid comes from options.key_id.
func TestKeyFormats(t *testing.T) {
	rsaKey := mockokta.DefaultKey()
	ec256, err := mockokta.NewECKey("ec-256", elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := mockokta.NewECKey("ec-384", elliptic.P384())
	if err != nil {
		t.Fatal(err)
	}
	ec521, err := mockokta.NewECKey("", elliptic.P521())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		key     *mockokta.Key
		stored  string
		options map[string]string
		alg     string
	}{
		{"rsa jwk", rsaKey, rsaKey.JWK(), nil, "RS256"},
		{"rsa pkcs8 pem with key_id", rsaKey, rsaKey.PEM(), map[string]string{"key_id": rsaKey.ID}, "RS256"},
		{"rsa pkcs1 pem", rsaKey, pkcs1PEM(t, rsaKey), map[string]string{"key_id": rsaKey.ID}, "RS256"},
		{"ec p-256 jwk", ec256, ec256.JWK(), nil, "ES256"},
		{"ec p-384 sec1 pem", ec384, sec1PEM(t, ec384), map[string]string{"key_id": ec384.ID}, "ES384"},
		{"ec p-521 pem without kid", ec521, ec521.PEM(), nil, "ES512"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, cfg := newMock(t, mockokta.WithClientKey(c.key))
			cfg.Secrets = keySource(c.stored)
			cfg.Target.Options = c.options
			id, err := open(t, cfg).Whoami(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if id.Principal != srv.ClientID() || !strings.Contains(id.Credential, c.alg) {
				t.Fatalf("identity %+v", id)
			}
		})
	}
}

// TestUnusableKeysAreRefusedAtOpen proves a key the tool cannot sign with
// fails Open, before any call, without quoting the key.
func TestUnusableKeysAreRefusedAtOpen(t *testing.T) {
	small, err := mockokta.NewRSAKey("small", 1024)
	if err != nil {
		t.Fatal(err)
	}
	k := mockokta.DefaultKey()
	var jwkNoD map[string]string
	_ = json.Unmarshal([]byte(k.JWK()), &jwkNoD)
	delete(jwkNoD, "d")
	pub, _ := json.Marshal(jwkNoD)
	cases := map[string]struct {
		stored string
		opts   map[string]string
		want   string
	}{
		"public key pem":     {publicPEM(t, k), nil, "needs the private key"},
		"encrypted pem":      {"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBvTBXBgkqhkiG9w0BBQ0w\n-----END ENCRYPTED PRIVATE KEY-----\n", nil, "encrypted"},
		"rsa 1024":           {small.PEM(), nil, "at least 2048"},
		"public jwk":         {string(pub), nil, "no private part"},
		"garbage":            {"not a key at all", nil, "no PEM private key"},
		"jwk kid mismatch":   {k.JWK(), map[string]string{"key_id": "other"}, "does not match the key's own kid"},
		"jwk set of two":     {`{"keys":[` + k.JWK() + `,` + k.JWK() + `]}`, nil, "holds 2 keys"},
		"rsa jwk wrong alg":  {strings.Replace(k.JWK(), `"alg":"RS256"`, `"alg":"ES256"`, 1), nil, "unsupported alg"},
		"rsa jwk wrong use":  {strings.Replace(k.JWK(), `"use":"sig"`, `"use":"enc"`, 1), nil, `not "sig"`},
		"ed25519 is refused": {ed25519PEM(t), nil, "ed25519 keys are not accepted"},
		"an old ssws token":  {"00Xq3vB7kLm9Rt2Yw5Zp8Nc4Hd6Fg1Js0Ae3Ui7Ob5", nil, "looks like an SSWS API token"},
		"ssws with scheme":   {"SSWS 00Xq3vB7kLm9Rt2Yw5Zp8Nc4Hd6Fg1Js0Ae3Ui7Ob5", nil, "looks like an SSWS API token"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			srv, cfg := newMock(t)
			cfg.Secrets = keySource(c.stored)
			cfg.Target.Options = c.opts
			_, err := okta.New().Open(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Open = %v; want an error mentioning %q", err, c.want)
			}
			assertNoCredential(t, err.Error(), srv, c.stored, k.PEM())
			if srv.Mints() != 0 {
				t.Fatal("a token was minted")
			}
		})
	}
}

// TestDPoPRequirementIsExplained proves an app set to require DPoP-bound tokens
// is reported with the setting to change.
func TestDPoPRequirementIsExplained(t *testing.T) {
	_, cfg := newMock(t, mockokta.WithDPoPRequired())
	_, err := open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Require Demonstrating Proof of Possession") {
		t.Fatalf("DPoP-required app = %v; want the setting to clear", err)
	}
}

// TestOnlyDPoPCodesAreBlamedOnDPoP proves a refusal is put down to DPoP by its
// error code alone: a rejected key whose description happens to mention DPoP
// is still explained as the key and client ID problem it is.
func TestOnlyDPoPCodesAreBlamedOnDPoP(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"The client_assertion is invalid; DPoP is not enabled for this client."}`))
	}))
	defer refusing.Close()
	_, cfg := newMock(t)
	cfg.Target.Tenant = refusing.URL
	_, err := open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not accept principal (client ID)") {
		t.Fatalf("invalid_client mentioning DPoP = %v; want the key and client ID explanation", err)
	}
	if strings.Contains(err.Error(), "requires DPoP-bound tokens") || strings.Contains(err.Error(), "Require Demonstrating Proof of Possession") {
		t.Fatalf("invalid_client mentioning DPoP was blamed on DPoP: %v", err)
	}
}

// TestTokenEndpointRateLimit proves the token request backs off on 429 like
// every other call.
func TestTokenEndpointRateLimit(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	srv, cfg := newMock(t, mockokta.WithClock(clk.Now))
	cfg.Clock = clk
	srv.InjectTokenRateLimit(2)
	if _, err := open(t, cfg).Whoami(context.Background()); err != nil {
		t.Fatalf("Whoami did not survive a rate-limited token endpoint: %v", err)
	}
}

// TestTokenEndpointRefusalsAreExplained proves a token endpoint answer that is
// not an OAuth error (a wrong org URL's 404, a rate limit that outlasts the
// back-off) still tells the operator what to do, never "(HTTP 404, )".
func TestTokenEndpointRefusalsAreExplained(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	srv, cfg := newMock(t, mockokta.WithClock(clk.Now))
	cfg.Clock = clk
	srv.InjectTokenRateLimit(1 << 20)
	_, err := open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "still rate limiting this client (HTTP 429)") {
		t.Fatalf("persistent token-endpoint 429 = %v", err)
	}

	// A 200 that is not a usable token response (a rewriting proxy, say) is
	// not blamed on DPoP.
	blank := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer blank.Close()
	_, cfg = newMock(t)
	cfg.Target.Tenant = blank.URL
	_, err = open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "carried no usable Bearer token") || strings.Contains(err.Error(), "DPoP") {
		t.Fatalf("empty 200 token response = %v", err)
	}

	notOkta := httptest.NewServer(http.NotFoundHandler())
	defer notOkta.Close()
	_, cfg = newMock(t)
	cfg.Target.Tenant = notOkta.URL
	_, err = open(t, cfg).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no OAuth endpoint here (HTTP 404)") || strings.Contains(err.Error(), ", )") {
		t.Fatalf("token endpoint 404 = %v", err)
	}
}

// TestAppWithoutAdminRole proves an app holding scopes but no admin role is
// refused by the org, and the guardrail reads fail rather than pass.
func TestAppWithoutAdminRole(t *testing.T) {
	_, cfg := newMock(t, mockokta.WithClientRoles())
	if _, err := open(t, cfg).Whoami(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("roleless app = %v; want 403", err)
	}
}

// TestSweepNeedsEveryFamily proves sweep refuses, naming the gap, rather than
// reporting the org clean while blind to a kind of object, and that the scope
// it advises is one the session would actually ask for: a listing session
// asks only for read scopes, so it is never told a manage scope would help.
func TestSweepNeedsEveryFamily(t *testing.T) {
	_, cfg := newMock(t, mockokta.WithoutScopes("okta.idps.manage", "okta.idps.read"))
	cfg.Scopes = nil
	cfg.OptionalScopes = allOpScopes()
	_, err := open(t, cfg).Sweep(context.Background(), "saashound-")
	if err == nil || !strings.Contains(err.Error(), "identity providers (grant okta.idps.manage, or okta.idps.read to list only)") {
		t.Fatalf("Sweep = %v; want a refusal naming identity providers", err)
	}
	if strings.Contains(err.Error(), "a listing sweep") {
		t.Fatalf("a session that may write was refused as a listing sweep: %v", err)
	}

	cfg.ReadOnly = true
	_, err = open(t, cfg).Sweep(context.Background(), "saashound-")
	if err == nil || !strings.Contains(err.Error(), "a listing sweep needs the .read scope of each kind") ||
		!strings.Contains(err.Error(), "identity providers (grant okta.idps.read)") {
		t.Fatalf("read-only Sweep = %v; want a refusal advising okta.idps.read", err)
	}
	if strings.Contains(err.Error(), ".manage") {
		t.Fatalf("a listing sweep was told a manage scope would help: %v", err)
	}

	var manageOnly []string
	for _, s := range allOpScopes() {
		if !strings.HasSuffix(s, ".read") {
			manageOnly = append(manageOnly, s)
		}
	}
	_, cfg = newMock(t, mockokta.WithGrantedScopes(append(manageOnly, "okta.orgs.read", "okta.users.read", "okta.groups.read", "okta.logs.read")...))
	cfg.Scopes = nil
	cfg.OptionalScopes = allOpScopes()
	cfg.ReadOnly = true
	_, err = open(t, cfg).Sweep(context.Background(), "saashound-")
	if err == nil {
		t.Fatal("a listing sweep by an app granted no read scope beyond the base ones was not refused")
	}
	for _, family := range []string{"okta.policies", "okta.apps", "okta.idps", "okta.networkZones", "okta.roles"} {
		if !strings.Contains(err.Error(), "(grant "+family+".read)") {
			t.Fatalf("read-only Sweep = %v; want it to advise %s.read", err, family)
		}
	}
	if strings.Contains(err.Error(), ".manage") || strings.Contains(err.Error(), "okta.users") {
		t.Fatalf("read-only Sweep = %v; want only the five missing read scopes", err)
	}
	cfg.ReadOnly = false
	if _, err := open(t, cfg).Sweep(context.Background(), "saashound-"); err != nil {
		t.Fatalf("the same app, in a session that may write: %v", err)
	}
}

// TestDeletingSweepNeedsManageScopeOfWhatItFinds proves a session that may
// write refuses, naming the manage scope, when it finds objects of a kind its
// token may list but not delete, and that a kind with nothing to delete never
// blocks it. A listing session is unaffected.
func TestDeletingSweepNeedsManageScopeOfWhatItFinds(t *testing.T) {
	srv, cfg := newMock(t, mockokta.WithoutScopes("okta.idps.manage"))
	cfg.Scopes = nil
	cfg.OptionalScopes = allOpScopes()
	if found, err := open(t, cfg).Sweep(context.Background(), "saashound-"); err != nil || len(found) != 0 {
		t.Fatalf("Sweep with no identity provider to delete = %v, %v; want a clean sweep", found, err)
	}

	name := marker.ObjectName("q8wd3f", "idp")
	srv.State(func(st *mockokta.State) {
		st.IdPs["0oaorphan1"] = &mockokta.IdP{ID: "0oaorphan1", Name: name, Type: "OIDC", Status: "ACTIVE"}
	})
	found, err := open(t, cfg).Sweep(context.Background(), "saashound-")
	want := "okta: sweep --delete found identity providers this token may list but not delete; " +
		"grant okta.idps.manage (or run sweep without --delete to list only)"
	if err == nil || err.Error() != want {
		t.Fatalf("Sweep = %v; want %q", err, want)
	}
	if len(found) != 0 {
		t.Fatalf("a refused sweep returned orphans: %v", found)
	}

	cfg.ReadOnly = true
	found, err = open(t, cfg).Sweep(context.Background(), "saashound-")
	if err != nil || len(found) != 1 || found[0].Name != name {
		t.Fatalf("listing Sweep = %v, %v; want the one identity provider", found, err)
	}
}

// TestTracesAndErrorsCarryNoCredential drives a session's every path with a
// trace attached and proves no trace record or error holds a credential.
func TestTracesAndErrorsCarryNoCredential(t *testing.T) {
	srv, cfg := newMock(t)
	var traces []provider.Request
	cfg.Trace = func(r provider.Request) { traces = append(traces, r) }
	ten := open(t, cfg)
	ctx := context.Background()
	if _, err := ten.Whoami(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ten.Sweep(ctx, "saashound-"); err != nil {
		t.Fatal(err)
	}
	srv.RevokeTokens()
	if _, err := ten.Capabilities(ctx); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	sawToken := false
	for _, r := range traces {
		all.WriteString(r.Method + " " + r.Path + "\n")
		sawToken = sawToken || r.Path == "/oauth2/v1/token"
	}
	if !sawToken {
		t.Fatal("token requests are not traced")
	}
	assertNoCredential(t, all.String(), srv, mockokta.DefaultKey().PEM())
}
