package okta

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// This file holds the JSON Web Signature primitives behind private_key_jwt
// client authentication: parsing the operator's private key and signing a
// client assertion with it. It never reads a secret.Value itself; transport.go
// hands it the key bytes for the length of one signature and drops the parsed
// key straight after, so no long-lived object holds key material.

// minRSABits is the smallest RSA key accepted. Okta requires 2048.
const minRSABits = 2048

// signingKey is a parsed client private key and the JWS algorithm it signs
// with. It lives only for one signature.
type signingKey struct {
	signer crypto.Signer
	alg    string
	hash   crypto.Hash
	// size is the byte length of one EC signature coordinate; 0 for RSA.
	size int
	// kid is the key ID sent in the assertion header, if known.
	kid string
}

// keyFormatHint is appended to every parse error so the operator knows what
// the tool accepts.
const keyFormatHint = "expected the service app's private key as PEM (PKCS#8, PKCS#1 or SEC 1) or as a JWK, RSA (2048 bits or more) or EC P-256/P-384/P-521"

// parseSigningKey parses a private key in PEM or JWK form. keyID, if set,
// overrides the JWK's own kid only when they agree, so a typo cannot silently
// send the wrong one. Errors describe the problem but never quote the key.
func parseSigningKey(raw []byte, keyID string) (*signingKey, error) {
	raw = bytes.TrimSpace(raw)
	var (
		k   *signingKey
		err error
	)
	switch {
	case looksLikeSSWS(raw):
		return nil, errors.New("okta: the credential looks like an SSWS API token, which the okta provider no longer accepts; " +
			"point credential at the OAuth 2.0 API Services app's private key instead (see the README's Okta quick-start)")
	case len(raw) > 0 && raw[0] == '{':
		k, err = parseJWK(raw)
	default:
		k, err = parsePEM(raw)
	}
	if err != nil {
		return nil, fmt.Errorf("okta: the private key is not usable: %w (%s)", err, keyFormatHint)
	}
	switch {
	case keyID == "":
	case k.kid == "":
		k.kid = keyID
	case k.kid != keyID:
		return nil, fmt.Errorf("okta: options.key_id %q does not match the key's own kid %q", keyID, k.kid)
	}
	return k, nil
}

// looksLikeSSWS reports whether raw has the shape of an Okta SSWS API token
// (42 URL-safe characters starting "00", with or without the "SSWS " scheme
// in front), the credential this provider took
// before it authenticated as an OAuth service app. It never echoes the value.
func looksLikeSSWS(raw []byte) bool {
	if rest, ok := bytes.CutPrefix(raw, []byte("SSWS ")); ok {
		raw = bytes.TrimSpace(rest) // pasted with its Authorization scheme
	}
	if len(raw) < 40 || len(raw) > 48 || !bytes.HasPrefix(raw, []byte("00")) {
		return false
	}
	for _, c := range raw {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parsePEM(raw []byte) (*signingKey, error) {
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no PEM private key block found")
		}
		if _, encrypted := block.Headers["Proc-Type"]; encrypted || block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, errors.New("the PEM key is encrypted; store it decrypted in a 0600 file, e.g. `openssl pkey -in key.pem -out plain.pem`")
		}
		switch block.Type {
		case "EC PARAMETERS":
			continue // `openssl ecparam -genkey` writes these before the key
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("malformed PKCS#8 private key")
			}
			return fromCryptoKey(key)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("malformed PKCS#1 RSA private key")
			}
			return fromCryptoKey(key)
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("malformed SEC 1 EC private key")
			}
			return fromCryptoKey(key)
		case "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE":
			return nil, fmt.Errorf("found a %s, but the tool needs the private key (Okta holds the public half)", strings.ToLower(block.Type))
		default:
			return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
		}
	}
}

// fromCryptoKey picks the JWS algorithm for a parsed key.
func fromCryptoKey(key any) (*signingKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < minRSABits {
			return nil, fmt.Errorf("the RSA key has %d bits; Okta needs at least %d", bits, minRSABits)
		}
		return &signingKey{signer: k, alg: "RS256", hash: crypto.SHA256}, nil
	case *ecdsa.PrivateKey:
		return ecSigningKey(k, "")
	case ed25519.PrivateKey:
		return nil, errors.New("ed25519 keys are not accepted by Okta for client authentication")
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// ecAlgs maps an EC curve to its JWS algorithm, hash and coordinate size.
var ecAlgs = map[string]struct {
	curve elliptic.Curve
	alg   string
	hash  crypto.Hash
	size  int
}{
	"P-256": {elliptic.P256(), "ES256", crypto.SHA256, 32},
	"P-384": {elliptic.P384(), "ES384", crypto.SHA384, 48},
	"P-521": {elliptic.P521(), "ES512", crypto.SHA512, 66},
}

func ecSigningKey(k *ecdsa.PrivateKey, wantAlg string) (*signingKey, error) {
	name := k.Curve.Params().Name
	a, ok := ecAlgs[name]
	if !ok {
		return nil, fmt.Errorf("unsupported EC curve %s", name)
	}
	if wantAlg != "" && wantAlg != a.alg {
		return nil, fmt.Errorf("the JWK says alg %s, but a %s key signs with %s", wantAlg, name, a.alg)
	}
	return &signingKey{signer: k, alg: a.alg, hash: a.hash, size: a.size}, nil
}

// jwk is the subset of RFC 7517/7518 a private signing key uses. A JWK Set
// holding exactly one key is accepted too, since that is what some consoles
// download.
type jwk struct {
	Kty  string            `json:"kty"`
	Kid  string            `json:"kid"`
	Alg  string            `json:"alg"`
	Use  string            `json:"use"`
	Crv  string            `json:"crv"`
	N    string            `json:"n"`
	E    string            `json:"e"`
	D    string            `json:"d"`
	P    string            `json:"p"`
	Q    string            `json:"q"`
	X    string            `json:"x"`
	Y    string            `json:"y"`
	Keys []json.RawMessage `json:"keys"`
}

func parseJWK(raw []byte) (*signingKey, error) {
	var j jwk
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, errors.New("malformed JWK JSON")
	}
	if j.Keys != nil {
		if len(j.Keys) != 1 {
			return nil, fmt.Errorf("the JWK Set holds %d keys; give the tool exactly one private key", len(j.Keys))
		}
		return parseJWK(j.Keys[0])
	}
	if j.D == "" {
		return nil, errors.New("the JWK has no private part (\"d\"); this looks like the public key")
	}
	if j.Use != "" && j.Use != "sig" {
		return nil, fmt.Errorf("the JWK's use is %q, not \"sig\"", j.Use)
	}
	var (
		k   *signingKey
		err error
	)
	switch j.Kty {
	case "RSA":
		k, err = rsaFromJWK(j)
	case "EC":
		k, err = ecFromJWK(j)
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", j.Kty)
	}
	if err != nil {
		return nil, err
	}
	k.kid = j.Kid
	return k, nil
}

func rsaFromJWK(j jwk) (*signingKey, error) {
	ints := map[string]*big.Int{}
	for name, v := range map[string]string{"n": j.N, "e": j.E, "d": j.D, "p": j.P, "q": j.Q} {
		if v == "" {
			return nil, fmt.Errorf("the RSA JWK lacks %q", name)
		}
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("the RSA JWK's %q is not base64url", name)
		}
		ints[name] = new(big.Int).SetBytes(b)
	}
	e := ints["e"]
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("the RSA JWK's exponent is out of range")
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: ints["n"], E: int(e.Int64())},
		D:         ints["d"],
		Primes:    []*big.Int{ints["p"], ints["q"]},
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("the RSA JWK is not a consistent key pair")
	}
	key.Precompute()
	k, err := fromCryptoKey(key)
	if err != nil {
		return nil, err
	}
	switch j.Alg {
	case "", "RS256":
	case "RS384":
		k.alg, k.hash = "RS384", crypto.SHA384
	case "RS512":
		k.alg, k.hash = "RS512", crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported alg %q for an RSA key (Okta accepts RS256, RS384, RS512)", j.Alg)
	}
	return k, nil
}

func ecFromJWK(j jwk) (*signingKey, error) {
	a, ok := ecAlgs[j.Crv]
	if !ok {
		return nil, fmt.Errorf("unsupported EC curve %q", j.Crv)
	}
	d, err := base64.RawURLEncoding.DecodeString(j.D)
	if err != nil {
		return nil, errors.New("the EC JWK's \"d\" is not base64url")
	}
	key, err := ecdsa.ParseRawPrivateKey(a.curve, d)
	if err != nil {
		return nil, errors.New("the EC JWK's \"d\" is not a valid private scalar for its curve")
	}
	if j.X != "" || j.Y != "" {
		x, errX := base64.RawURLEncoding.DecodeString(j.X)
		y, errY := base64.RawURLEncoding.DecodeString(j.Y)
		pub, errP := key.PublicKey.Bytes()
		if errX != nil || errY != nil || errP != nil || !bytes.Equal(pub, append(append([]byte{4}, x...), y...)) {
			return nil, errors.New("the EC JWK's public point does not match its private part")
		}
	}
	return ecSigningKey(key, j.Alg)
}

// jwsHeader is the protected header of a client assertion.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ"`
}

// sign returns the compact JWS of claims.
func (k *signingKey) sign(claims any) (string, error) {
	h, err := json.Marshal(jwsHeader{Alg: k.alg, Kid: k.kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(h) + "." + b64(p)
	hh := k.hash.New()
	hh.Write([]byte(input))
	digest := hh.Sum(nil)
	var sig []byte
	switch key := k.signer.(type) {
	case *rsa.PrivateKey:
		if sig, err = rsa.SignPKCS1v15(rand.Reader, key, k.hash, digest); err != nil {
			return "", fmt.Errorf("okta: sign client assertion: %w", err)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return "", fmt.Errorf("okta: sign client assertion: %w", err)
		}
		// JWS wants the fixed-width big-endian concatenation r || s.
		sig = make([]byte, 2*k.size)
		r.FillBytes(sig[:k.size])
		s.FillBytes(sig[k.size:])
	default:
		return "", fmt.Errorf("okta: unsupported signing key %T", k.signer)
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
