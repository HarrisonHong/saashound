package github

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"

	"github.com/HarrisonHong/saashound/internal/provider"
)

// Op names. The namespace is the platform; the tactic lives in the technique
// ID and the ATT&CK metadata, never in an op name.
const (
	opRepoCreate             = "github.repo.create"
	opDeployKeyAdd           = "github.deploy_key.add"
	opWebhookCreate          = "github.webhook.create"
	opRepoAddCollaborator    = "github.repo.add_collaborator"
	opOrgPromoteOwner        = "github.org.promote_owner"
	opRepoDisableScanning    = "github.repo.disable_secret_scanning"
	opBranchProtectionCreate = "github.branch_protection.create"
	opBranchUnprotect        = "github.branch.unprotect"
	opRepoMakePublic         = "github.repo.make_public"
)

// Resource types ops create or modify.
const (
	resRepo             = "github.repo"
	resDeployKey        = "github.deploy_key"
	resWebhook          = "github.webhook"
	resBranchProtection = "github.branch_protection"
	resMembership       = "github.membership"
)

// GitHub token scopes (classic-scope names, which is what the X-OAuth-Scopes
// header reports), declared per op for the plan and the `auth` scope check.
// They document least privilege.
const (
	scopeRepo         = "repo"
	scopeDeleteRepo   = "delete_repo"
	scopeAdminOrg     = "admin:org"
	scopeReadAuditLog = "read:audit_log"
)

// defaultBranch is the branch a repo is created with (auto_init) and the
// branch the branch-protection ops operate on.
const defaultBranch = "main"

// optionSecondAccount is the targets.yaml option naming the operator's own
// second GitHub account, used as the synthetic outside collaborator and the
// account promoted to owner. The tool never creates it; it is operator-owned.
const optionSecondAccount = "second_account"

// tenantOf recovers the github tenant an op was called with.
func tenantOf(c *provider.Call) (*Tenant, error) {
	t, ok := c.Tenant.(*Tenant)
	if !ok {
		return nil, fmt.Errorf("github op %s called with a %T tenant", c.Step, c.Tenant)
	}
	return t, nil
}

// orgOf recovers the client and the org slug an op operates against.
func orgOf(c *provider.Call) (*client, string, error) {
	t, err := tenantOf(c)
	if err != nil {
		return nil, "", err
	}
	return t.client, t.org, nil
}

// secondAccount resolves the operator's second-account login for an op from
// the step parameter, falling back to the target's second_account option.
func secondAccount(c *provider.Call, param string) (string, error) {
	if v := c.Params[param]; v != "" {
		return v, nil
	}
	if v := c.Target.Options[optionSecondAccount]; v != "" {
		return v, nil
	}
	return "", fmt.Errorf("github: no account given: set the step's %q parameter or the target's %q option to an operator-owned second GitHub account", param, optionSecondAccount)
}

// repoPath builds /repos/{org}/{repo}{suffix}, escaping the org and repo so a
// value can never alter the request path. suffix must already be escaped.
func repoPath(org, repo, suffix string) string {
	return "/repos/" + escape(org) + "/" + escape(repo) + suffix
}

// escape path-escapes a GitHub identifier so it can never alter the request path.
func escape(s string) string { return url.PathEscape(s) }

// sshPublicKey generates a throwaway ed25519 key pair and returns only the
// public half in authorized_keys format, with comment as the key comment. The
// private half is never returned, stored or logged: a deploy key the tool adds
// can authenticate nobody, because nobody holds its private half.
func sshPublicKey(comment string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("github: generate deploy key: %w", err)
	}
	// Discard the private half immediately; it never leaves this function.
	for i := range priv {
		priv[i] = 0
	}
	var buf bytes.Buffer
	writeSSHString(&buf, []byte("ssh-ed25519"))
	writeSSHString(&buf, pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(buf.Bytes()) + " " + comment, nil
}

func writeSSHString(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
