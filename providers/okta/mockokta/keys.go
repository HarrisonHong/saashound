package mockokta

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
)

// DefaultKeyID is the kid of DefaultKey.
const DefaultKeyID = "saashound-test-key"

// Key is a service app's client key pair, for tests: the private half in the
// forms an operator stores it (PEM or JWK), the public half as the org
// registers it on the app.
type Key struct {
	// ID is the key ID (kid) the org knows the public half by. It may be
	// empty, for a key registered without one.
	ID      string
	Private crypto.Signer
}

// Public is the half the org holds.
func (k *Key) Public() crypto.PublicKey { return k.Private.Public() }

// PEM is the private key as PKCS#8 PEM, the format the Okta Admin Console
// offers next to the JWK.
func (k *Key) PEM() string {
	der, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		panic(err) // only RSA and ECDSA keys are built here
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// JWK is the private key as a JSON Web Key carrying its kid, the format the
// Okta Admin Console shows when it generates a key.
func (k *Key) JWK() string {
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	m := map[string]string{"use": "sig"}
	if k.ID != "" {
		m["kid"] = k.ID
	}
	switch p := k.Private.(type) {
	case *rsa.PrivateKey:
		m["kty"], m["alg"] = "RSA", "RS256"
		m["n"], m["e"] = enc(p.N.Bytes()), enc(bigEndian(p.E))
		m["d"], m["p"], m["q"] = enc(p.D.Bytes()), enc(p.Primes[0].Bytes()), enc(p.Primes[1].Bytes())
		m["dp"], m["dq"], m["qi"] = enc(p.Precomputed.Dp.Bytes()), enc(p.Precomputed.Dq.Bytes()), enc(p.Precomputed.Qinv.Bytes())
	case *ecdsa.PrivateKey:
		d, err := p.Bytes()
		if err != nil {
			panic(err)
		}
		pub, err := p.PublicKey.Bytes()
		if err != nil {
			panic(err)
		}
		size := (len(pub) - 1) / 2
		m["kty"], m["crv"] = "EC", p.Curve.Params().Name
		m["x"], m["y"], m["d"] = enc(pub[1:1+size]), enc(pub[1+size:]), enc(d)
	default:
		panic(fmt.Sprintf("unsupported key %T", k.Private))
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func bigEndian(e int) []byte {
	var out []byte
	for ; e > 0; e >>= 8 {
		out = append([]byte{byte(e)}, out...)
	}
	return out
}

// NewRSAKey generates an RSA client key.
func NewRSAKey(kid string, bits int) (*Key, error) {
	p, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &Key{ID: kid, Private: p}, nil
}

// NewECKey generates an EC client key on curve.
func NewECKey(kid string, curve elliptic.Curve) (*Key, error) {
	p, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{ID: kid, Private: p}, nil
}

var (
	defaultKeyOnce sync.Once
	defaultKey     *Key
)

// DefaultKey is the RSA 2048 key a mock org registers on its service app
// unless WithClientKey says otherwise. It is generated once per process.
func DefaultKey() *Key {
	defaultKeyOnce.Do(func() {
		k, err := NewRSAKey(DefaultKeyID, 2048)
		if err != nil {
			panic(err)
		}
		defaultKey = k
	})
	return defaultKey
}
