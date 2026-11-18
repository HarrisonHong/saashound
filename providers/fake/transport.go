package fake

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// authenticate is the simulated provider's transport: the one place in the
// provider that reads a raw credential, the way a real provider's HTTP
// transport sets the Authorization header and nothing else does.
//
// A target without a credential reference connects anonymously, which is
// all the simulated tenant needs. When one is declared it must resolve, and
// if the tenant was provisioned with a credential, it must match.
func (t *Tenant) authenticate(ctx context.Context) error {
	var want string
	err := t.store.View(t.id, func(s *State) error {
		want = s.TokenSHA256
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNoTenant) {
			return fmt.Errorf("%w; run `saashound init %s --platform fake` first", err, t.cfg.Target.Name)
		}
		return err
	}
	if t.cfg.Credential.IsZero() {
		if want != "" {
			return errors.New("fake: this tenant requires a credential and the target declares none")
		}
		return nil
	}
	tok, err := t.cfg.Secrets.Resolve(ctx, t.cfg.Credential)
	if err != nil {
		return err
	}
	defer tok.Wipe()
	if tok.Empty() {
		return errors.New("fake: credential is empty")
	}
	if want != "" && subtle.ConstantTimeCompare([]byte(tokenDigest(tok.Reveal())), []byte(want)) != 1 {
		return errors.New("fake: 401 credential rejected by the tenant")
	}
	return nil
}

// credentialDigest returns the SHA-256 of the target's credential, or "" if
// it declares none. Provisioning stores the digest, never the credential.
func credentialDigest(ctx context.Context, cfg provider.Config) (string, error) {
	if cfg.Credential.IsZero() {
		return "", nil
	}
	tok, err := cfg.Secrets.Resolve(ctx, cfg.Credential)
	if err != nil {
		return "", err
	}
	defer tok.Wipe()
	return tokenDigest(tok.Reveal()), nil
}

func tokenDigest(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
