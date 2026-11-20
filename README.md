# SaaSHound

Adversary emulation with verified detection for SaaS and identity platforms. Run a documented intrusion technique against a tenant you own, prove the cleanup, then check whether the platform logged it and whether your detection fired.

Point it at your own org and, technique by technique, it gives a verdict from the platform's own audit log, with proof it left nothing behind: *verified detection, not just detonation*.

> **Status: Okta and GitHub providers, pre-release.** The platform-agnostic engine - technique corpus and validator, op registry, planner, guardrail gate, write-ahead journal, verified cleanup, telemetry collection and matching, versioned JSON-lines output - now drives two real platforms. The **Okta** provider runs documented Okta intrusion techniques against an org you own, cleans up provably, and reads the Okta **System Log** back to confirm the platform logged them. The **GitHub** provider does the same against a GitHub organization you own, reading the org **audit log** back (GHEC only; on a Free org techniques still detonate and clean up, with telemetry reported unsupported). The built-in **simulated platform** (`fake`) still exercises the whole loop with no network and no credentials. The **Sigma detection checker** now evaluates a technique's referenced Sigma rules locally, against the run's own events, and reports per rule whether the rule fired - *verified detection, not just detonation*. The `exec` (operator-SIEM) checker is the next increment.

## Authorized use

**SaaSHound is for testing tenants you own, or are explicitly authorized in writing to test. Nothing else.**

- **You are responsible for authorization.** The tool cannot verify legal ownership of a tenant, and nothing can. Its guardrails make accidents hard and misuse loud: a target must be allowlisted in `targets.yaml`; the platform must confirm, live, that the credential belongs to the declared tenant and principal; a tenant admin must have placed an ownership marker the tool only ever reads; production needs explicit flags and a change ticket; and an interactive run makes you type the tenant's name. Those checks prove that someone with admin rights in the tenant deliberately opted in. They do not replace your authorization.
- **Start with a lab tenant.** Targets default to `lab`. Run against `production` only after the technique has run cleanly in a lab, only with techniques marked `production_safe`, and only with `--production` and a `--ticket <change reference>` that is written into every record. A "lab" with more active users than expected is refused as probably mislabelled.
- **Follow the platform's terms.** Your agreement with the platform (for example a developer or trial plan's terms) governs what you may run against it.
- **Everything is attributable.** Every request carries a `saashound/<version> (run=<id>; phase=<phase>)` User-Agent (phases: `preflight`, `detonate`, `cleanup`, `collect`, `sweep`), every object the tool creates is named `saashound-<run>-<step>`, and both land in the tenant's own audit log for its defenders to see.

Excluded by design. These are not configuration options; the tool has no code for them:

- **No detection or EDR evasion.** It never spoofs or hides its User-Agent, never throttles itself to stay under a detection threshold, and never deletes or tampers with audit events. Techniques that impair a defence exist so you can test the detection for that behaviour, against objects the run creates; the tool hiding its own activity is out of scope.
- **No credential harvesting.** Every credential a technique creates (a password, a TOTP seed, a key) is generated in memory, used once and discarded. If a cleanup ever failed, the leftover object has no usable secret.
- **No phishing of real users.** Nothing is sent to anyone outside the tenant. Synthetic accounts use your declared test domain; consent-style techniques run against your own synthetic user.
- **No targeting of systems you don't own.** Requests go only to the declared tenant's API. A technique file cannot name a host, URL or command: it can only compose the tool's registered operations.
- **No attacks on shared platform infrastructure.** No password spraying, MFA push fatigue or credential stuffing: they hit infrastructure the platform shares with other customers.

Found a vulnerability in SaaSHound itself? See [SECURITY.md](SECURITY.md).

## Install

Every [release](https://github.com/HarrisonHong/saashound/releases) has a `saashound_<version>_<os>_<arch>.tar.gz` for `linux` and `darwin` on `amd64` and `arm64`, and a `saashound_<version>_windows_amd64.zip`, each holding a self-contained binary (no cgo), `LICENSE`, `README.md` and `THIRD_PARTY_LICENSES.txt`. Download, verify and unpack the latest in one line (Linux on x86-64 shown; needs the [GitHub CLI](https://cli.github.com/) 2.49 or later, signed in):

```sh
gh release download --repo HarrisonHong/saashound --pattern 'saashound_*_linux_amd64.tar.gz' && gh attestation verify saashound_*_linux_amd64.tar.gz --repo HarrisonHong/saashound --signer-workflow HarrisonHong/saashound/.github/workflows/release.yml && tar -xzf saashound_*_linux_amd64.tar.gz saashound
```

Or build from source with Go 1.26 or later (the Go checksum database authenticates the source):

```sh
go install github.com/HarrisonHong/saashound/cmd/saashound@latest
```

### Verify a download

SaaSHound holds a credential that can create a super admin, so check that the binary you run is the one this repository's release workflow built from the tagged source before you give it that credential. Releases are signed and attested keylessly with [Sigstore](https://www.sigstore.dev/), under the release workflow's own GitHub identity. There is no long-lived signing key to steal.

- **Build provenance** ([SLSA](https://slsa.dev/) v1 [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)) for every archive, SBOM and bare binary. This succeeds only for a file that this repository's `release.yml` built and attested:

  ```sh
  gh attestation verify saashound_0.1.0_linux_amd64.tar.gz --repo HarrisonHong/saashound --signer-workflow HarrisonHong/saashound/.github/workflows/release.yml
  ```

  It works on an unpacked or installed binary too: `gh attestation verify "$(command -v saashound)" --repo HarrisonHong/saashound --signer-workflow HarrisonHong/saashound/.github/workflows/release.yml`.

- **A signed `checksums.txt`**, to verify without a GitHub account. Put the release's `checksums.txt` and `checksums.txt.sigstore.json` beside the archive and the release's tag in the identity, then run [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

  ```sh
  cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity https://github.com/HarrisonHong/saashound/.github/workflows/release.yml@refs/tags/v0.1.0 && sha256sum --ignore-missing -c checksums.txt
  ```

  On macOS, use `shasum -a 256 --ignore-missing -c checksums.txt` for the last step.

- **An SPDX SBOM** per archive (`<archive>.sbom.json`) that lists every module compiled into its binary. Both checks above cover it.

There is deliberately no `saashound verify` command. A binary cannot vouch for itself, because a tampered one would carry a tampered check, so verification belongs to a tool you already trust.

**Reproducible builds.** A release binary depends only on the tagged source, the Go version and the build flags. Run this from a clean clone at the tag, with the Go version that `go version -m saashound` reports for the released binary (`GOTOOLCHAIN=go1.x.y` fetches it):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X github.com/HarrisonHong/saashound/internal/version.Version=v0.1.0" -o saashound ./cmd/saashound
```

It rebuilds the released binary byte for byte, so `gh attestation verify` accepts your own build too.

## Quick start

[Install](#install) a release, or build from a clone with Go 1.26 or later:

```sh
git clone https://github.com/HarrisonHong/saashound && cd saashound
go build -o saashound ./cmd/saashound      # or: go install ./cmd/saashound
```

Declare a target and authorize it. On a real platform `init` prints where a tenant admin places the marker; the simulated platform has no admin console, so `--place-marker` plays that admin:

```console
$ ./saashound init lab --platform fake --test-domain lab.example.com --place-marker
wrote ~/.config/saashound/targets.yaml  (target lab, platform fake, environment lab)
provisioned simulated tenant sim-lab

Authorize saashound for this tenant (a tenant admin must do this once):
  In the tenant's admin console, create a group named  saashound-authorized
  with description  saashound-authorized:cc8326f4920d
  ...
placed the ownership marker in the simulated tenant (as its admin)
Then: saashound auth lab

$ ./saashound auth lab          # read-only end-to-end check
```

See exactly what a run will do (read-only; `--offline` makes no calls at all):

```console
$ ./saashound plan fake.persistence.mfa-factor-register --target lab
fake.persistence.mfa-factor-register   Register an additional MFA factor on a user
  ATT&CK T1098.005, T1556.006 · tradecraft 2023-08-31 · production-safe
  run       pf2s75 against lab (tenant sim-lab, lab)
  1  fake.user.create    POST /api/v1/users?activate=true                 saashound-pf2s75-victim  ...  (password generated and discarded)
  2  fake.factor.enroll  POST /api/v1/users/{user}/factors?activate=true  saashound-pf2s75-factor  user={1}  (seed used once to activate, then discarded)
  cleanup   2: delete factor, then verify GET /api/v1/users/{user}/factors/{id} -> 404
            1: deactivate + delete user, then verify GET /api/v1/users/{id} -> 404
  expect    user.lifecycle.create (30s), user.mfa.factor.activate (20s)
  detect    sigma none: no public rule covers this
  scopes    fake.logs.read fake.users.manage
  guard     allowlisted · tenant matches · marker ok · lab
```

Run it. On a terminal you confirm by typing the tenant's short name and get a table; piped or in CI you pass `--yes` and get JSON lines:

```console
$ ./saashound apply fake.persistence.mfa-factor-register fake.defense-impairment.network-zone-deactivate --target lab
About to run 2 technique(s) against "Simulated tenant sim-lab" (sim-lab.fake.invalid), environment lab.
Type the tenant short name "sim-lab" to continue: sim-lab
[k6d364] run       fake.persistence.mfa-factor-register -> lab (lab)
[k6d364] detonate  2/2 steps ok                                0.0s
[k6d364] cleanup   2 objects undone, verified gone             0.0s
[k6d364] telemetry 2/2 expected events observed, max latency 0.0s
...
TECHNIQUE                                        VERDICT  TELEMETRY   DETECTIONS  CLEANUP
fake.persistence.mfa-factor-register             pass     2/2 (0.0s)  -           verified
fake.defense-impairment.network-zone-deactivate  pass     2/2 (0.0s)  -           verified

$ ./saashound apply fake.privilege-escalation.admin-role-assign --target lab --yes -q | jq -c '{t: .technique, v: .verdict, det: [.detections[] | {rule, status}]}'
{"t":"fake.privilege-escalation.admin-role-assign","v":"pass","det":[{"rule":"Admin role granted (example)","status":"fired"}]}
```

This technique references a bundled example Sigma rule, so the detection checker evaluates it end to end on the simulated platform. For a real platform, point `--sigma-rules` at your own Sigma checkout (or set `$SAASHOUND_SIGMA_RULES`); a technique references a rule by its Sigma UUID. A referenced rule that does not fire makes the verdict `detection-missing` (exit 1); one that is not found is reported as `unknown`, never a silent pass. Every event a referenced rule keys on must be one of the technique's expected events, or a slow one can make a working rule look like it did not fire; see [docs/technique-authoring.md](docs/technique-authoring.md#every-event-a-referenced-rule-keys-on-must-be-an-expectation).

If a run is interrupted, the first Ctrl-C stops detonating and cleans up; a second abandons cleanup and prints the command to resume it. A crashed or abandoned run is recovered from its journal:

```console
$ ./saashound status
RUN     TARGET  TECHNIQUE                             STATE            STARTED
5g8tad  lab     fake.persistence.mfa-factor-register  cleanup-pending  2026-11-14 22:23:26
$ ./saashound cleanup 5g8tad
[5g8tad] cleanup   step factor fake.factor.enroll: no recorded id; found exact name "saashound-5g8tad-factor" -> removed -> verified gone
[5g8tad] cleanup   step victim fake.user.create: removed -> verified gone
cleanup verified for run 5g8tad (2 objects)
$ ./saashound sweep --target lab
no saashound- objects found in tenant sim-lab
```

To try the slow paths, add options to the fake target in `targets.yaml`: `api_latency: 2s` (time to press Ctrl-C mid-call), `audit_lag: 5s`, `audit_lag/<eventType>: 40s` (a late event), `audit_drop: <eventType>` (a missing event), `audit_user_agent: dropped` or `truncated` (a log that does not keep the User-Agent whole, so events are matched by name), `audit: unsupported` (a tier without an audit API).

## Okta quick-start

The Okta provider runs the same loop against a real Okta org you own (a free [Integrator](https://developer.okta.com/) org works). It authenticates as an **OAuth 2.0 API Services app** using `private_key_jwt`, and holds no standing API token: each run signs a single-use assertion, valid for five minutes, with the app's private key and exchanges it at the org's token endpoint for an access token that carries **only the scopes that run's plan needs** and expires within the hour. The token lives in memory, goes to the org and nowhere else, and is never written down. (SSWS API tokens are not supported: they inherit every privilege of the admin who created them and cannot be narrowed per run.) Four one-time steps, then it is identical to the simulated flow above.

**1. Create the service app.** In the Okta Admin Console, go to **Applications → Applications → Create App Integration → API Services** and name it, for example `SaaSHound`. On its **General** tab:

- under **Client Credentials**, set **Client authentication** to **Public key / Private key**, then **Add key → Generate new key**. Okta shows the private key once: save the **JWK** form (it carries the key's ID) to a `0600` file outside any repository, or set it as an environment variable - never a flag. Okta keeps only the public half. You can instead paste the public half of a key pair you generated yourself (RSA 2048+ or EC P-256/P-384/P-521); a PEM private key works too, with its key ID given as `options: {key_id: <KID>}` on the target in `targets.yaml`;
- if **Require Demonstrating Proof of Possession (DPoP) header in token requests** is checked, clear it: SaaSHound does not send DPoP proofs;
- note the **Client ID**. It is the target's principal.

**2. Grant scopes and an admin role.** On the app's **Okta API Scopes** tab (a Super Admin must do this), grant what the techniques you run need:

| Scope | Needed for |
|---|---|
| `okta.orgs.read`, `okta.users.read`, `okta.groups.read`, `okta.logs.read` | every run: the org's identity, the lab-size check, the ownership marker, the System Log |
| `okta.users.manage` | synthetic users and their MFA factors |
| `okta.roles.manage` | the admin-role and custom-role techniques |
| `okta.apps.manage`, `okta.appGrants.manage` | the service-app technique |
| `okta.idps.manage` | the identity-provider technique |
| `okta.policies.manage` | the policy technique |
| `okta.networkZones.manage` | the network-zone technique |
| `okta.policies.read`, `okta.apps.read`, `okta.idps.read`, `okta.networkZones.read`, `okta.roles.read` | `sweep`: listing every kind of object a run can create (`sweep --delete` uses the `.manage` scopes instead) |

Each run's token asks for exactly its plan's scopes (`saashound plan` lists them) plus the org, users and groups read scopes in the first row (the System Log one is already among the plan's). So a technique whose scope you withhold is refused, naming the scope, before anything touches the org (an `apply` that names it alongside others is refused as a whole, like any guardrail refusal), and the techniques whose scopes you did grant run as usual. `sweep` needs to see every kind of object a run can create. A listing `sweep` asks only for the five `.read` scopes in the last row plus the org, users and groups ones in the first, so the `.manage` scopes alone do not cover it; `sweep --delete` asks for the `.manage` scopes of the ops that create those objects instead. Either way, a kind of object the token may not list is refused, naming the scope to grant, rather than reported clean. `sweep --delete` also refuses, before asking for confirmation, when it finds objects of a kind the token may list but not delete, naming the `.manage` scope to grant. **Do not grant `okta.groups.manage`**: the tool never asks for it, and without it no token the tool holds can create the ownership marker below.

Then, on the app's **Admin roles** tab, assign it an admin role: Okta lets a service app do only what both its scopes and its roles allow. A custom admin role covering the techniques you run is the least-privilege choice. Assigning Super Admin to a user, or granting API scopes to an app, needs the service app itself to hold **Super Admin**; `saashound plan` says so next to those steps.

**3. Place the ownership marker.** A tenant admin creates one Okta **group** named `saashound-authorized` whose **description** is the per-target marker value. `init` (next step) prints the exact value and where to put it; the tool only ever reads this group, with `okta.groups.read`, so a token alone can never authorise an org. In the Admin Console: **Directory → Groups → Add group**.

**4. Declare the target** (allowlist it in `targets.yaml`, which holds the org URL, the app's client ID and a *reference* to the key, never the key):

```console
$ ./saashound init okta --platform okta \
    --tenant https://your-org.okta.com \
    --principal 0oa1b2c3d4e5f6g7h8i9 \
    --test-domain your-test-domain.example \
    --credential-file ~/.config/saashound/okta-key.json      # or --credential-env OKTA_KEY
wrote ~/.config/saashound/targets.yaml  (target okta, platform okta, environment lab)

Authorize saashound for this tenant (a tenant admin must do this once):
  In the Okta Admin Console, go to Directory > Groups > Add group.
  Name the group exactly  saashound-authorized
  and set its Description to  saashound-authorized:3f1d9c0a7e52
  ...
Then: saashound auth okta
```

`--tenant` is the bare org URL (no trailing slash); `--principal` is the service app's client ID. Then check everything, read-only, before the first run:

```console
$ ./saashound auth okta
okta   okta   your-org.okta.com   "Your Org"
  principal   0oa1b2c3d4e5f6g7h8i9
  credential  OAuth 2.0 service app, private_key_jwt (RS256, key Bq3xN7v2kQ); a per-session access token valid 1h
  roles       SUPER_ADMIN
  scopes      11 granted, 8 needed by the okta corpus; MISSING okta.appGrants.manage okta.idps.manage
  allowlist   allowlisted
  identity    tenant matches
  marker      marker ok
  environment lab
  tier        okta: 3 of 25 active users allowed for a lab
  telemetry   audit API reachable
ready
$ ./saashound apply okta.persistence.mfa-factor-register --target okta
```

`auth` mints a token, asks the org who it was issued to (token introspection, so the principal is confirmed by the org itself, not taken from the config), reads the marker and the System Log, and lists any scope the corpus needs that the app was not granted. A missing scope only rules out the techniques that need it, so `auth` still says `ready`; a missing read scope from the first row of the table, a key the app does not hold, or a client ID that is not the app's is a refusal with what to fix.

Everything else - the plan, the guardrail, the verified cleanup, the System Log verdict, the JSON lines and exit codes - is the same as for the simulated platform. See the eight shipped techniques with `saashound list` and `saashound show <id>`.

> CI never touches a real org. The provider is proven against an in-process mock Okta ([providers/okta/mockokta](providers/okta/mockokta)) that speaks the same API, OAuth token and introspection endpoints, and System Log: it checks every client assertion's signature and claims, and refuses any call whose token lacks the scope Okta's API reference says the endpoint needs, so a technique that under-declares its scopes fails CI. The real-org path is exercised by the operator.

## GitHub quick-start

The GitHub provider runs the same loop against a GitHub **organization** you own. One honest tier line first: the org **audit-log REST API is GitHub Enterprise Cloud (GHEC) only**. On a GHEC org the whole loop works end to end, including the telemetry verdict; on a Free org techniques still **detonate and clean up**, but `saashound auth` reports telemetry `unsupported` and the verdict is `telemetry-unsupported` rather than `pass`. Three one-time steps.

**1. Create an API token.** The tool never mints one. Use a **fine-grained personal access token** (preferred), a GHEC token, or a GitHub App installation token, scoped to this one org and to only what the techniques you run need - equivalent to the classic scopes `repo`, `delete_repo` (so cleanup can delete the run's repositories), `admin:org` (owner promotion), and `read:audit_log` (the audit log on GHEC). Put it in an environment variable or a `0600` file - never a flag:

```sh
export GITHUB_TOKEN='github_pat_...'   # or a 0600 file referenced with --credential-file
```

**2. Place the ownership marker.** An org **owner** creates one repository named exactly `saashound-range` (it can be private) and adds a file named `saashound-authorized` at its root whose only contents are the per-target marker value. `init` (next step) prints the exact value; the tool only ever reads this file, so a token alone can never authorise an org.

**3. Declare the target** (allowlist it in `targets.yaml`, which holds the org login and a credential *reference*, never the token):

```console
$ ./saashound init github --platform github \
    --tenant your-org \
    --principal your-login \
    --credential-env GITHUB_TOKEN
wrote ~/.config/saashound/targets.yaml  (target github, platform github, environment lab)

Authorize saashound for this tenant (a tenant admin must do this once):
  Create a repository named exactly  saashound-range  in the organization (it can be private).
  Add a file named  saashound-authorized  at its root whose only contents are:
      saashound-authorized:3f1c9a0b7e42
  ...
Then: saashound auth github
```

`--tenant` is the organization **login** (slug), not a URL; `--principal` is the login of the account the token belongs to (what `GET /user` returns). Two techniques act on an operator-owned **second account** (outside-collaborator add and org-owner promotion); point them at it by adding `second_account` to the target's `options` in `targets.yaml`. For GitHub Enterprise **Server**, add the API base the same way:

```yaml
    options:
      second_account: your-second-login
      api_url: https://ghe.example.com/api/v3   # GHES only; github.com needs no api_url
```

Then verify and run:

```console
$ ./saashound auth github                # read-only: confirms the org, principal, marker and audit-log tier
$ ./saashound apply github.persistence.deploy-key-add --target github
```

Everything else - the plan, the guardrail, the verified cleanup, the audit-log verdict, the JSON lines and exit codes - is the same as for Okta. Webhook payload URLs are always on the reserved `.invalid` TLD, so a creation ping resolves nowhere; deploy keys are added with a freshly generated public key whose private half is discarded, so they authenticate nobody. See the seven shipped GitHub techniques with `saashound list` and `saashound show <id>`.

> CI never touches a real org. The provider is proven against an in-process mock GitHub ([providers/github/mockgithub](providers/github/mockgithub)) that speaks the same REST and audit-log API; the real GHEC path is exercised by the operator.

## Commands

| Command | What it does |
|---|---|
| `init <target> --platform P` | Declare a target in `targets.yaml` and print its ownership marker. Re-runnable. |
| `auth <target>` | Read-only check: identity, scopes, marker, environment, audit API. |
| `list`, `show <technique>` | The corpus; a technique's steps, inverses, expected events, detections, safety. |
| `validate [file.yaml\|dir ...]` | Validate technique files against the schema and the registered ops. |
| `plan <technique...> --target T [-o plan.json] [--offline]` | Read-only dry run, including the guardrail result. |
| `apply <technique...> --target T` / `apply --plan plan.json` | Detonate, clean up and prove it, collect telemetry, match expectations, check the referenced Sigma rules (`--sigma-rules <dir>`), report. A saved plan is re-derived from the corpus and refused if it differs. |
| `cleanup <run-id>... \| --all` | Replay journals; undo and prove gone. Idempotent. Every run is attempted; a refused one is reported and the rest still run. Abandoning a cleanup (second Ctrl-C) stops the command; the runs not attempted are listed with their retry command. |
| `status [--json]` | Runs and their states, derived from their journals. |
| `sweep --target T [--delete]` | Find `saashound-` objects; remove those no local journal accounts for, after confirmation. |
| `version` | Tool, corpus and schema versions. |

Global flags: `--targets <path>` (default `$SAASHOUND_TARGETS`, else `targets.yaml` in `$SAASHOUND_CONFIG_DIR`, else `saashound/targets.yaml` in `$XDG_CONFIG_HOME` or the user config directory), `--state-dir <path>` (default `$SAASHOUND_STATE_DIR`, else `$XDG_STATE_HOME/saashound`, else `~/.local/state/saashound`; on Windows `%LocalAppData%\saashound\state`), `--corpus-dir <dir>` (extra techniques, reported as `unverified`), `-q`, `-v`/`-vv`, `--no-color`.

**Output.** stdout carries results only: a table on a terminal, one JSON object per technique when piped or with `--jsonl`. stderr carries progress: `-q` silences it, `-v` adds one line per API call (method, path, status, latency; never headers or bodies) and a count of the events correlated by each signal, `-vv` adds per-event matching detail. The JSON record is versioned (`"schema": "saashound.result", "version": 2`) and documented in [docs/result-schema.md](docs/result-schema.md).

**Exit codes**, for CI:

| Code | Meaning |
|---|---|
| 0 | Every expectation met. |
| 1 | An expectation failed: telemetry missing, late or not collected, a detection did not fire, or detonation failed. |
| 2 | Usage, configuration or guardrail refusal. Nothing ran (or, when a later technique of an `apply` could not be started, nothing further ran; the earlier records are still printed). |
| 3 | Cleanup not verified. Overrides 1. The record lists the orphans and the exact retry command. `cleanup` and `sweep` also exit 3 while any object is left behind. |

## How it works

In short:

```
 corpus (YAML, embedded) ──> planner ──> guardrail gate ──> executor ───────> cleaner ──────────> collector ──> matcher ──> reporters
 composes registered ops     steps,      allowlist,         per step:         reverse order:      this run's     expected     JSON lines,
                             names,      live identity,     INTENT (fsync)    Undo (gone = ok),   audit events   vs observed  table,
                             cleanup     marker, env,       -> op.Do ->       then Gone must      (exact UA      per step,    exit codes
                             order       confirmation       RESULT (fsync)    hold -> verified    run marker)    latency
                                         refuse: exit 2           │                 ▲
                                                                  └── journal.jsonl ┘  (0600, write-ahead; cleanup reads only this)
```

- **Techniques are data.** A technique is a YAML file ([techniques/fake/](techniques/fake/)) that strings together registered operations with typed parameters and a strict `{{run.*}}` / `{{target.*}}` / `{{steps.<id>.<field>}}` substitution (no functions, conditionals or environment lookups). It has no host, URL or command field anywhere. It must declare the audit events it expects and its cleanup order. The validator ([internal/technique](internal/technique)) rejects unknown fields, unregistered ops, ops without an inverse, forward references, events the step's op does not produce, and much more. The verified corpus is embedded in the binary with `go:embed`.
- **Ops are Go, reversible by construction.** An op ([internal/provider/op.go](internal/provider/op.go)) implements `Do`, `Undo` (its inverse) and `Gone` (proof the inverse worked), plus `Locate` (find a created object by its exact deterministic name after a crash) or `Prior` (read the value a modifying op is about to change, so it is journalled before the change). Registration fails loudly if any of these is missing.
- **Write-ahead journal, verified cleanup.** The executor ([internal/engine](internal/engine)) writes and fsyncs an intent before every call and the result after it. Cleanup is a pure function of the journal: undo in reverse, treat "not found" as success, require `Gone`. An intent without a result (the process died mid-call) is resolved by exact-name lookup, never by substring search. Cleanup runs before telemetry collection, so nothing stays open during log latency.
- **Correlation does not rest on one field.** Every request carries the run's User-Agent with its phase, and the collector ([internal/telemetry](internal/telemetry)) attributes an event to the run first by that marker. A platform that does not record the User-Agent of API traffic, or truncates it, would otherwise make every expectation look missing, so an event without a usable User-Agent is also the run's when it names one of the run's `saashound-<run>-` objects or, on GitHub, carries the `hashed_token` of the run's token. Every match is bounded by the run's window from its journal (a match on `hashed_token` alone must also fall closer to this run than to the previous run on the same target), the window alone never correlates anything, and an event recorded with another client's User-Agent, or naming another run, never counts. Each expectation records which signal matched ([result schema](docs/result-schema.md#correlation)). Expectations match detonation-phase events only, and collection stops as soon as every expectation is met or its deadline passes. When every expectation is met but a referenced detection rule has not fired yet, it drains before stopping: up to 5 more polls, one poll interval apart, so a rule keyed on an event that lands a little after the expected ones is still judged on it. Its own audit-log reads carry the `collect` phase. A run whose telemetry was not collected to the end (an API failure, a Ctrl-C) is never a pass.
- **The provider boundary is open.** A platform is one package implementing `provider.Provider` ([internal/provider/provider.go](internal/provider/provider.go)): its op vocabulary, an `AuditSource`, and a `Tenant` with `Whoami`, `ReadMarker`, `Capabilities` and `Sweep`. It registers itself from `init()` and is linked by one import line in [providers/all.go](providers/all.go). Nothing in the core switches on platform names: Okta and GitHub were each added without one. The core tells a provider which scopes a session needs (`provider.Config.Scopes`: the plan's for `plan` and `apply`, the journalled ops' for `cleanup`, read-only ones for a listing `sweep`), so a provider whose credential can be narrowed per run never holds more. [providers/fake](providers/fake) is the reference implementation; [providers/okta](providers/okta) and [providers/github](providers/github) are the real ones (each a hand-written `net/http` client - no vendor SDK - GitHub with a bearer token, Okta with OAuth 2.0 `private_key_jwt` service-app auth minting a down-scoped token per run, both with rate-limit back-off, Link-header pagination and strict secret redaction). All three pass the same conformance suite in [internal/conformance](internal/conformance), which for Okta runs each op on a token carrying only the scopes it declares.
- **Detection checkers are a seam.** [internal/detect](internal/detect) defines a narrow checker interface; the engine folds each checker's results into the verdict. The **Sigma** checker ([internal/detect/sigma](internal/detect/sigma)) implements it with [`runreveal/sigmalite`](https://github.com/runreveal/sigmalite): it loads the operator's own Sigma rules from a local directory (`--sigma-rules`, never vendored), maps the platform's raw events to the fields the rules key on, and evaluates each referenced rule against the run's detonation-phase events. A rule that is not found is `unknown` and one it cannot evaluate (a Sigma v2 correlation rule, or a rule the evaluator cannot parse) is `unsupported`, never a wrong pass. The `exec` (operator-SIEM) checker is the next increment behind the same seam.

| Package | Role |
|---|---|
| `cmd/saashound` | The binary. |
| `internal/cli` | Commands, flags, output selection, interrupt handling. |
| `internal/marker` | The reserved prefix (one constant), run IDs, object names, User-Agent, ownership marker. |
| `internal/technique` | Technique schema, strict loader, substitution, validator, corpus. |
| `internal/provider` | The provider and op interfaces, and the registry that enforces inverses. |
| `internal/plan` | Technique to concrete plan. |
| `internal/guard` | The tenant-you-own guardrail. |
| `internal/journal` | The write-ahead journal. |
| `internal/engine` | Executor, cleaner, orchestration, orphan removal. |
| `internal/telemetry` | Collector and expectation matcher. |
| `internal/detect` | Detection-checker interface. |
| `internal/detect/sigma` | Sigma detection checker: loads the operator's rules, maps events, evaluates referenced rules with `sigmalite`. |
| `internal/report` | Result record, verdicts, exit codes, JSON lines and table. |
| `internal/secret` | The redacting secret type and credential references. |
| `internal/target`, `internal/state`, `internal/fsutil`, `internal/clock` | `targets.yaml`, run directories and locks, atomic private files, time. |
| `providers/fake` | The simulated platform. |
| `providers/okta` | The Okta provider: a hand-written `net/http` client, the System Log audit source, `Whoami`/marker/`Sweep`, and the op vocabulary. |
| `providers/okta/mockokta` | An in-process mock Okta org (test only; not in the binary) the suites run the real provider against. |
| `providers/github` | The GitHub provider: a hand-written `net/http` client, the org audit-log source (GHEC only), `Whoami`/marker/`Sweep`, and the op vocabulary. |
| `providers/github/mockgithub` | An in-process mock GitHub org (test only; not in the binary) the suites run the real provider against. |
| `techniques` | The embedded, verified corpus (`fake/`, `okta/` and `github/`). |

## Security of the tool itself

- **No telemetry, no phone-home, no listener.** The tool talks to nothing but the declared tenant's API and exits. The simulated platform makes no network calls at all.
- **Secrets.** Credentials come from an environment variable or a `0600` key file referenced in `targets.yaml`, never from a flag or the file itself. They are held in a type whose every formatting path prints `[redacted]`, and only a provider's transport may read the raw value. They never reach the journal, events, plan, result or logs; a canary test seeds a fake credential, drives every command at `-vv` and fails the build if it appears in any output or file (for Okta: any line of the private key, and every client assertion and access token the mock org saw).
- **No standing token.** The Okta provider holds the service app's private key, not an API token. Each run mints its own access token with only the scopes its plan needs, keeps it in memory, refreshes it shortly before its one-hour expiry, and sends it to the org's own host and nowhere else (a redirect is never followed). A leaked run token is inert within the hour and can do only what that run could.
- **Local state** lives under the state directory in per-run directories (mode `0700`, files `0600`): `plan.json`, `journal.jsonl`, `events.jsonl`, `result.json`. One run per target at a time, enforced with a lock the kernel releases if the process dies.
- **Architecture tests** ([internal/policy](internal/policy)) fail the build on `os/exec`, `text/template`, `plugin`, `reflect` or `unsafe` anywhere, on network imports outside real provider packages, on any listener, and on reading a raw secret outside a provider transport.
- **Minimal dependencies:** the standard library, `go.yaml.in/yaml/v3` (the YAML project's maintained successor to `gopkg.in/yaml.v3`), `github.com/spf13/cobra` and `github.com/runreveal/sigmalite` (the Sigma evaluator, which itself pulls in `gopkg.in/yaml.v3`).
- **Signed, attested, reproducible releases.** Release binaries are built by a workflow that runs only on a version tag and holds no signing key. Each release carries a Sigstore-signed `checksums.txt`, SLSA build provenance for every archive and binary, and an SBOM, and every binary rebuilds byte for byte from the tagged source. See [Verify a download](#verify-a-download).

## Development

```sh
go build ./...                 # compile everything
go test ./...                  # unit, conformance, crash-injection, golden and canary tests
go test -race ./...
go vet ./... && gofmt -l .
go test ./internal/cli -run Golden -update   # after an intended change to the result record
```

What the suites prove:

- **Op conformance** ([providers/fake/fake_test.go](providers/fake/fake_test.go), [providers/okta/okta_test.go](providers/okta/okta_test.go) and [providers/github/github_test.go](providers/github/github_test.go), all via [internal/conformance](internal/conformance)): every registered op goes Do, Gone false, Locate (exact name only), Sweep, declared events with the run's User-Agent (each also attributable without it, by a run object's name or the run's credential), Undo, Gone true, Undo again (idempotent), tenant unchanged. The okta ops run against the mock Okta org, each on an access token carrying only the scopes it declares, so a declared scope list that is not enough fails; the github ops run against the mock GitHub org. The suite itself is tested against deliberately broken providers.
- **Technique conformance** ([internal/engine/engine_test.go](internal/engine/engine_test.go) for fake; [internal/cli/okta_test.go](internal/cli/okta_test.go) for okta; [internal/cli/github_test.go](internal/cli/github_test.go) for github): every embedded technique validates, plans, applies, cleans up verified, observes its audit-log telemetry and leaves the tenant byte-identical.
- **Crash injection**: the run is killed at every point of every step of every technique (after the intent, after the call but before the result, after the result, after undo but before its record, between undo and gone, after gone), and a fresh cleaner, reading only the journal, must recover with nothing orphaned; a second cleanup must change nothing. [internal/cli/crash_unix_test.go](internal/cli/crash_unix_test.go), [internal/cli/okta_crash_unix_test.go](internal/cli/okta_crash_unix_test.go) and [internal/cli/github_crash_unix_test.go](internal/cli/github_crash_unix_test.go) do the same with real `SIGKILL`ed processes - the okta and github ones against a mock org in the parent process, which the killed child reaches over TCP.
- **Correlation without the User-Agent** ([internal/telemetry](internal/telemetry/telemetry_test.go), [internal/cli/correlation_test.go](internal/cli/correlation_test.go)): with the User-Agent dropped or truncated by the mock Okta and GitHub orgs, every technique still passes, matched by name or, for GitHub's org membership change, by `hashed_token`; decoys from another run, another client, another token or outside the run window never satisfy an expectation or enter the run's events, and neither do the `hashed_token`-only events of the run that went before on the same target, with the org's clock leading or lagging this machine's.
- **Golden output** ([internal/cli/testdata/golden](internal/cli/testdata/golden)): the exact JSON-lines records for passing, failing and degraded-correlation runs; every key must be documented in [docs/result-schema.md](docs/result-schema.md).

**Release dry run.** The release build runs in CI on every change, minus signing and publishing; to run it locally:

```sh
scripts/install-release-tools.sh                   # the pinned goreleaser, syft and cosign, built from source
goreleaser release --snapshot --clean --skip=sign  # archives, SBOMs and checksums.txt in dist/; nothing signed or published
```

**Cutting a release:** push a `v*` tag. [.github/workflows/release.yml](.github/workflows/release.yml) builds the release into a draft, signs `checksums.txt`, attests every archive and binary, runs the [verification](#verify-a-download) above against the draft, and publishes it only if that passes. It refuses to run in a private repository, because keyless signing writes the repository and tag to Sigstore's public transparency log.

**Adding a technique:** follow [docs/technique-authoring.md](docs/technique-authoring.md): write a YAML file under `techniques/<platform>/` (or test one with `--corpus-dir`), run `saashound validate <file>`, and run it against a lab tenant. **Adding a platform:** create `providers/<name>/` implementing `provider.Provider`, add one import to `providers/all.go`, put techniques in `techniques/<name>/`, and make the provider pass `conformance.Run`.

## License

Apache-2.0. See [LICENSE](LICENSE).
