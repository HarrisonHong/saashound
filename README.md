# SaaSHound

Adversary emulation with verified detection for SaaS and identity platforms. Run a documented intrusion technique against a tenant you own, prove the cleanup, then check whether the platform logged it and whether your detection fired.

Point it at your own org and, technique by technique, it gives a verdict from the platform's own audit log, with proof it left nothing behind: *verified detection, not just detonation*.

> **Status: Okta provider, pre-release.** The platform-agnostic engine - technique corpus and validator, op registry, planner, guardrail gate, write-ahead journal, verified cleanup, telemetry collection and matching, versioned JSON-lines output - now drives a real platform. The **Okta** provider runs documented Okta intrusion techniques against an org you own, cleans up provably, and reads the Okta **System Log** back to confirm the platform logged them. The built-in **simulated platform** (`fake`) still exercises the whole loop with no network and no credentials. The **Sigma detection checker** now evaluates a technique's referenced Sigma rules locally, against the run's own events, and reports per rule whether the rule fired - *verified detection, not just detonation*. The GitHub provider and the `exec` (operator-SIEM) checker are the next increments.

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

## Quick start

Requires Go 1.26 or later.

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

This technique references a bundled example Sigma rule, so the detection checker evaluates it end to end on the simulated platform. For a real platform, point `--sigma-rules` at your own Sigma checkout (or set `$SAASHOUND_SIGMA_RULES`); a technique references a rule by its Sigma UUID. A referenced rule that does not fire makes the verdict `detection-missing` (exit 1); one that is not found is reported as `unknown`, never a silent pass.

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

To try the slow paths, add options to the fake target in `targets.yaml`: `api_latency: 2s` (time to press Ctrl-C mid-call), `audit_lag: 5s`, `audit_lag/<eventType>: 40s` (a late event), `audit_drop: <eventType>` (a missing event), `audit: unsupported` (a tier without an audit API).

## Okta quick-start

The Okta provider runs the same loop against a real Okta org you own (a free [Integrator](https://developer.okta.com/) org works). Three one-time steps, then it is identical to the simulated flow above.

**1. Create an org-owned API token.** In the Okta Admin Console, go to **Security → API → Tokens → Create Token**. Okta cannot mint tokens over the API, so the operator supplies one; an SSWS token inherits the privileges of the admin who creates it, so sign in as a **dedicated service account** and give it a **custom admin role** scoped to only what the techniques you run need, rather than Super Admin. (Granting Super Admin to a user, or API scopes to a service app, does need the token's own account to hold Super Admin; those techniques are noted in `saashound show`.) Put the token in an environment variable or a `0600` file - never a flag:

```sh
export OKTA_TOKEN='00abc...'          # or a 0600 file referenced with --credential-file
```

**2. Place the ownership marker.** A tenant admin creates one Okta **group** named `saashound-authorized` whose **description** is the per-target marker value. `init` (next step) prints the exact value and where to put it; the tool only ever reads this group, so a token alone can never authorise an org. In the Admin Console: **Directory → Groups → Add group**.

**3. Declare the target** (allowlist it in `targets.yaml`, which holds the tenant URL and a credential *reference*, never the token):

```console
$ ./saashound init okta --platform okta \
    --tenant https://your-org.okta.com \
    --principal you@your-org.example \
    --test-domain your-test-domain.example \
    --credential-env OKTA_TOKEN
wrote ~/.config/saashound/targets.yaml  (target okta, platform okta, environment lab)

Authorize saashound for this tenant (a tenant admin must do this once):
  In the Okta Admin Console, go to Directory > Groups > Add group.
  Name the group exactly  saashound-authorized
  and set its Description to  saashound-authorized:cc8326f4920d
  ...
Then: saashound auth okta
```

`--tenant` is the bare org URL (no trailing slash); `--principal` is the login of the user the token belongs to (what `/api/v1/users/me` returns). Then verify and run:

```console
$ ./saashound auth okta                 # read-only: confirms the org, principal, marker and System Log
$ ./saashound apply okta.persistence.mfa-factor-register --target okta
```

Everything else - the plan, the guardrail, the verified cleanup, the System Log verdict, the JSON lines and exit codes - is the same as for the simulated platform. See the eight shipped techniques with `saashound list` and `saashound show <id>`.

> CI never touches a real org. The provider is proven against an in-process mock Okta ([providers/okta/mockokta](providers/okta/mockokta)) that speaks the same API and System Log; the real-org path is exercised by the operator.

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

**Output.** stdout carries results only: a table on a terminal, one JSON object per technique when piped or with `--jsonl`. stderr carries progress: `-q` silences it, `-v` adds one line per API call (method, path, status, latency; never headers or bodies), `-vv` adds per-event matching detail. The JSON record is versioned (`"schema": "saashound.result", "version": 1`) and documented in [docs/result-schema.md](docs/result-schema.md).

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
- **Correlation is exact.** Every request carries the run's User-Agent with its phase; the collector ([internal/telemetry](internal/telemetry)) keeps only events whose recorded User-Agent carries this run's ID, matches expectations against detonation-phase events only, and stops as soon as every expectation is met or its deadline passes. Its own audit-log reads carry the `collect` phase. A run whose telemetry was not collected to the end (an API failure, a Ctrl-C) is never a pass.
- **The provider boundary is open.** A platform is one package implementing `provider.Provider` ([internal/provider/provider.go](internal/provider/provider.go)): its op vocabulary, an `AuditSource`, and a `Tenant` with `Whoami`, `ReadMarker`, `Capabilities` and `Sweep`. It registers itself from `init()` and is linked by one import line in [providers/all.go](providers/all.go). Nothing in the core switches on platform names: adding Okta changed no core package. [providers/fake](providers/fake) is the reference implementation and [providers/okta](providers/okta) is the first real one (a hand-written `net/http` client - no vendor SDK - with SSWS token auth, 429 back-off, Link-header pagination and strict secret redaction); both pass the same conformance suite in [internal/conformance](internal/conformance).
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
| `techniques` | The embedded, verified corpus (`fake/` and `okta/`). |

## Security of the tool itself

- **No telemetry, no phone-home, no listener.** The tool talks to nothing but the declared tenant's API and exits. The simulated platform makes no network calls at all.
- **Secrets.** Credentials come from an environment variable or a `0600` key file referenced in `targets.yaml`, never from a flag or the file itself. They are held in a type whose every formatting path prints `[redacted]`, and only a provider's transport may read the raw value. They never reach the journal, events, plan, result or logs; a canary test seeds a fake credential, drives every command at `-vv` and fails the build if it appears in any output or file.
- **Local state** lives under the state directory in per-run directories (mode `0700`, files `0600`): `plan.json`, `journal.jsonl`, `events.jsonl`, `result.json`. One run per target at a time, enforced with a lock the kernel releases if the process dies.
- **Architecture tests** ([internal/policy](internal/policy)) fail the build on `os/exec`, `text/template`, `plugin`, `reflect` or `unsafe` anywhere, on network imports outside real provider packages, on any listener, and on reading a raw secret outside a provider transport.
- **Minimal dependencies:** the standard library, `go.yaml.in/yaml/v3` (the YAML project's maintained successor to `gopkg.in/yaml.v3`), `github.com/spf13/cobra` and `github.com/runreveal/sigmalite` (the Sigma evaluator, which itself pulls in `gopkg.in/yaml.v3`).

## Development

```sh
go build ./...                 # compile everything
go test ./...                  # unit, conformance, crash-injection, golden and canary tests
go test -race ./...
go vet ./... && gofmt -l .
go test ./internal/cli -run Golden -update   # after an intended change to the result record
```

What the suites prove:

- **Op conformance** ([providers/fake/fake_test.go](providers/fake/fake_test.go) and [providers/okta/okta_test.go](providers/okta/okta_test.go), both via [internal/conformance](internal/conformance)): every registered op goes Do, Gone false, Locate (exact name only), Sweep, declared events with the run's User-Agent, Undo, Gone true, Undo again (idempotent), tenant unchanged. The okta ops run against the mock Okta org. The suite itself is tested against deliberately broken providers.
- **Technique conformance** ([internal/engine/engine_test.go](internal/engine/engine_test.go) for fake; [internal/cli/okta_test.go](internal/cli/okta_test.go) for okta): every embedded technique validates, plans, applies, cleans up verified, observes its System Log telemetry and leaves the tenant byte-identical.
- **Crash injection**: the run is killed at every point of every step of every technique (after the intent, after the call but before the result, after the result, after undo but before its record, between undo and gone, after gone), and a fresh cleaner, reading only the journal, must recover with nothing orphaned; a second cleanup must change nothing. [internal/cli/crash_unix_test.go](internal/cli/crash_unix_test.go) and [internal/cli/okta_crash_unix_test.go](internal/cli/okta_crash_unix_test.go) do the same with real `SIGKILL`ed processes - the okta one against a mock Okta org in the parent process, which the killed child reaches over TCP.
- **Golden output** ([internal/cli/testdata/golden](internal/cli/testdata/golden)): the exact JSON-lines records for passing and failing runs; every key must be documented in [docs/result-schema.md](docs/result-schema.md).

**Adding a technique:** write a YAML file under `techniques/<platform>/` (or test one with `--corpus-dir`), run `saashound validate <file>`, and run it against a lab tenant. **Adding a platform:** create `providers/<name>/` implementing `provider.Provider`, add one import to `providers/all.go`, put techniques in `techniques/<name>/`, and make the provider pass `conformance.Run`.

## License

Apache-2.0. See [LICENSE](LICENSE).
