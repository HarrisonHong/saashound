# SaaSHound

Adversary emulation with verified detection for SaaS and identity platforms. Run a documented intrusion technique against a tenant you own, prove the cleanup, then check whether the platform logged it and whether your detection fired.

Point it at your own org and, technique by technique, it gives a verdict from the platform's own audit log, with proof it left nothing behind: *verified detection, not just detonation*.

> **Status: core engine, pre-release.** This increment is the platform-agnostic engine: technique corpus and validator, op registry, planner, guardrail gate, write-ahead journal, verified cleanup, telemetry collection and matching, versioned JSON-lines output. It runs end to end against a built-in **simulated platform** (`fake`) with no network and no credentials. Okta and GitHub providers, and the Sigma detection checker, are the next increments.

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

$ ./saashound apply fake.privilege-escalation.admin-role-assign --target lab --yes -q | jq -c '{t: .technique, v: .verdict, cleanup: .cleanup.status}'
{"t":"fake.privilege-escalation.admin-role-assign","v":"pass","cleanup":"verified"}
```

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

## Commands

| Command | What it does |
|---|---|
| `init <target> --platform P` | Declare a target in `targets.yaml` and print its ownership marker. Re-runnable. |
| `auth <target>` | Read-only check: identity, scopes, marker, environment, audit API. |
| `list`, `show <technique>` | The corpus; a technique's steps, inverses, expected events, detections, safety. |
| `validate [file.yaml\|dir ...]` | Validate technique files against the schema and the registered ops. |
| `plan <technique...> --target T [-o plan.json] [--offline]` | Read-only dry run, including the guardrail result. |
| `apply <technique...> --target T` / `apply --plan plan.json` | Detonate, clean up and prove it, collect telemetry, match expectations, report. A saved plan is re-derived from the corpus and refused if it differs. |
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
- **The provider boundary is open.** A platform is one package implementing `provider.Provider` ([internal/provider/provider.go](internal/provider/provider.go)): its op vocabulary, an `AuditSource`, and a `Tenant` with `Whoami`, `ReadMarker`, `Capabilities` and `Sweep`. It registers itself from `init()` and is linked by one import line in [providers/all.go](providers/all.go). Nothing in the core switches on platform names. [providers/fake](providers/fake) is the reference implementation; a provider must pass the conformance suite in [internal/conformance](internal/conformance).
- **Detection checkers are a seam.** [internal/detect](internal/detect) defines the interface the Sigma and `exec` checkers will implement; the engine already folds their results into the verdict.

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
| `internal/report` | Result record, verdicts, exit codes, JSON lines and table. |
| `internal/secret` | The redacting secret type and credential references. |
| `internal/target`, `internal/state`, `internal/fsutil`, `internal/clock` | `targets.yaml`, run directories and locks, atomic private files, time. |
| `providers/fake` | The simulated platform. |
| `techniques` | The embedded, verified corpus. |

## Security of the tool itself

- **No telemetry, no phone-home, no listener.** The tool talks to nothing but the declared tenant's API and exits. The simulated platform makes no network calls at all.
- **Secrets.** Credentials come from an environment variable or a `0600` key file referenced in `targets.yaml`, never from a flag or the file itself. They are held in a type whose every formatting path prints `[redacted]`, and only a provider's transport may read the raw value. They never reach the journal, events, plan, result or logs; a canary test seeds a fake credential, drives every command at `-vv` and fails the build if it appears in any output or file.
- **Local state** lives under the state directory in per-run directories (mode `0700`, files `0600`): `plan.json`, `journal.jsonl`, `events.jsonl`, `result.json`. One run per target at a time, enforced with a lock the kernel releases if the process dies.
- **Architecture tests** ([internal/policy](internal/policy)) fail the build on `os/exec`, `text/template`, `plugin`, `reflect` or `unsafe` anywhere, on network imports outside real provider packages, on any listener, and on reading a raw secret outside a provider transport.
- **Minimal dependencies:** the standard library, `go.yaml.in/yaml/v3` (the YAML project's maintained successor to `gopkg.in/yaml.v3`) and `github.com/spf13/cobra`.

## Development

```sh
go build ./...                 # compile everything
go test ./...                  # unit, conformance, crash-injection, golden and canary tests
go test -race ./...
go vet ./... && gofmt -l .
go test ./internal/cli -run Golden -update   # after an intended change to the result record
```

What the suites prove:

- **Op conformance** ([providers/fake/fake_test.go](providers/fake/fake_test.go) via [internal/conformance](internal/conformance)): every registered op goes Do, Gone false, Locate (exact name only), Sweep, declared events with the run's User-Agent, Undo, Gone true, Undo again (idempotent), tenant unchanged. The suite itself is tested against deliberately broken providers.
- **Technique conformance** ([internal/engine/engine_test.go](internal/engine/engine_test.go)): every embedded technique validates, plans, applies, cleans up verified, observes its telemetry and leaves the tenant byte-identical.
- **Crash injection**: the run is killed at every point of every step of every technique (after the intent, after the call but before the result, after the result, after undo but before its record, between undo and gone, after gone), and a fresh cleaner, reading only the journal, must recover with nothing orphaned; a second cleanup must change nothing. [internal/cli/crash_unix_test.go](internal/cli/crash_unix_test.go) does the same with real `SIGKILL`ed processes and a file-backed simulated tenant.
- **Golden output** ([internal/cli/testdata/golden](internal/cli/testdata/golden)): the exact JSON-lines records for passing and failing runs; every key must be documented in [docs/result-schema.md](docs/result-schema.md).

**Adding a technique:** write a YAML file under `techniques/<platform>/` (or test one with `--corpus-dir`), run `saashound validate <file>`, and run it against a lab tenant. **Adding a platform:** create `providers/<name>/` implementing `provider.Provider`, add one import to `providers/all.go`, put techniques in `techniques/<name>/`, and make the provider pass `conformance.Run`.

## License

Apache-2.0. See [LICENSE](LICENSE).
