# Result record: `saashound.result` version 2

`saashound apply` writes one JSON object per technique run to stdout when stdout is not a terminal (or always, with `--jsonl`). The same record is saved as `result.json` in the run's state directory. On a terminal, stdout shows the table view instead; progress always goes to stderr.

This document is the contract. `internal/cli/testdata/golden/*.jsonl` pins the exact shape, and a test fails if a key appears in a record without being documented here.

## Compatibility

- `schema` and `version` identify the record. `version` changes only on a breaking change: a key removed, renamed, or given a different meaning or type.
- Adding a key, or a new value to an enumerated field, is not breaking. Consumers must ignore keys they do not know and treat an unknown enumerated value as "not pass".
- Keys use `snake_case`. Times are RFC 3339 in UTC. Durations are seconds, as numbers, with a `_s` suffix.

Version history:

- `2`: an expectation can be met by an event correlated without its User-Agent (see [Correlation](#correlation)), so `observed` no longer implies the platform recorded the run's marker. `telemetry.expectations[].correlation` says how each matching event was attributed to the run.
- `1`: the first published record.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every expectation met (verdicts `pass`, `skipped`, `telemetry-unsupported`). |
| 1 | An expectation failed: `telemetry-missing`, `detection-missing` or `detonate-failed`. |
| 2 | Usage, configuration or guardrail refusal. Nothing was run and no record is printed. The one exception: when a later technique of an `apply` cannot be started, the techniques before it have already run, so their records are still printed. |
| 3 | Cleanup not verified (`cleanup-unverified`). Overrides 1. |

## Top-level fields

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | Always `"saashound.result"`. |
| `version` | integer | Record version, `2`. |
| `run` | string | Run ID (six characters). Every object the run created is named `saashound-<run>-<step>`, and every request carried `saashound/<version> (run=<run>; phase=<phase>)` as its User-Agent. The phases are `preflight` (read-only guardrail and plan calls), `detonate`, `cleanup`, `collect` (the audit-log reads made after cleanup) and `sweep`. |
| `technique` | string | Technique ID, `<platform>.<tactic>.<verb-object>`. |
| `corpus` | string | `"verified"` for the corpus embedded in the binary, `"unverified"` for one loaded with `--corpus-dir`. |
| `corpus_version` | string | Version of the embedded corpus, e.g. `"2026.11.0"`. |
| `target` | string | Target name from `targets.yaml`. |
| `platform` | string | Provider name. |
| `environment` | string | `"lab"` or `"production"`. |
| `ticket` | string or null | The `--ticket` change reference; required for production. |
| `tool` | string | `"saashound/<version>"`. |
| `started` | string | When the run started. |
| `finished` | string | When the record was produced. |
| `detonate` | object | What the executor did; see below. |
| `cleanup` | object | What the cleaner proved; see below. |
| `telemetry` | object | What the platform's audit log showed; see below. |
| `detections` | array | One entry per detection checked; empty when the technique references no rule to check. See [`detections`](#detections). |
| `verdict` | string | See [Verdicts](#verdicts). |
| `reason` | string | One sentence explaining any verdict other than `pass`. Omitted on `pass`. |

## `detonate`

| Key | Type | Meaning |
|---|---|---|
| `detonate.status` | string | `ok`, `failed` (an op returned an error), `interrupted` (Ctrl-C) or `not-run` (skipped). |
| `detonate.steps` | integer | Steps in the plan. |
| `detonate.completed` | integer | Steps whose result was journalled. |
| `detonate.failed_step` | string | The step that stopped detonation. Omitted when `ok`. |
| `detonate.error` | string | Its error. Omitted when `ok`. |

## `cleanup`

| Key | Type | Meaning |
|---|---|---|
| `cleanup.status` | string | `verified`: every step that was started was undone and its `Gone` check returned true. `unverified`: at least one was not. `not-run`: the technique was skipped. |
| `cleanup.objects` | integer | Steps that were started and are proven undone. |
| `cleanup.orphans` | array | Steps not proven undone; empty when verified. |
| `cleanup.orphans[].step` | string | Step ID. |
| `cleanup.orphans[].op` | string | The op that created or changed the object. |
| `cleanup.orphans[].name` | string | The object's deterministic name. |
| `cleanup.orphans[].id` | string | The platform's ID for it, when known. |
| `cleanup.orphans[].error` | string | Why it is not proven gone. |
| `cleanup.retry` | string | The exact command to retry, e.g. `"saashound cleanup k3v9q2"`. Present only when unverified. |

## `telemetry`

Telemetry is collected after cleanup, from the platform's own audit log, keeping only the events it can attribute to this run (see [Correlation](#correlation)). Expectations match detonation-phase events only. The collector's own reads carry the run's User-Agent with `phase=collect`. Collection stops once every expectation is resolved, or after a short bounded drain when a referenced detection rule has not fired yet (see [`detections`](#detections)).

An expectation is only ever met by an event that was actually read. If collection could not start, failed or was interrupted (Ctrl-C), the expectations it did not resolve are `not-run`, `telemetry.error` says why, and the verdict is `telemetry-missing`, never `pass`.

| Key | Type | Meaning |
|---|---|---|
| `telemetry.status` | string | `observed` (all expectations met in time), `late`, `missing`, `unsupported` (this tenant's tier has no audit API), `incomplete` (some expectations were never checked: their step never ran, or collection failed or was interrupted) or `not-run` (the technique was skipped). |
| `telemetry.source` | string | The audit source, e.g. `"fake.audit"`. |
| `telemetry.expected` | integer | Number of expectations. |
| `telemetry.observed` | integer | Met by their deadline. |
| `telemetry.late` | integer | Seen, but after their deadline (see `telemetry.expectations[].status`). |
| `telemetry.missing` | integer | Not seen by the time collection stopped. |
| `telemetry.max_latency_s` | number or null | Largest latency among observed and late expectations. |
| `telemetry.events_file` | string | The run's raw events, verbatim, one JSON object per line, relative to the state directory. |
| `telemetry.error` | string | Why collection did not resolve every expectation, if it did not: a persistent audit API error, a failed capabilities call, or an interruption. |
| `telemetry.expectations` | array | One entry per expectation, in technique order. |
| `telemetry.expectations[].after` | string | The step whose action should produce the event. |
| `telemetry.expectations[].event_type` | string | The expected event type. |
| `telemetry.expectations[].status` | string | `observed`, `late`, `missing`, `unsupported` or `not-run` (never checked: the step never completed, or collection failed or was interrupted before resolving it). `late` means the event was first read after the deadline although an earlier successful poll, at or before the deadline, did not return it. Collection only starts after cleanup; when its first successful poll is already past the deadline, the platform's own event timestamp decides instead: `observed` if it is at or before the step's completion plus the deadline, otherwise `late` (an event without a timestamp is `late`). |
| `telemetry.expectations[].match` | object | The resolved field values that had to match, keyed by field path (`target[].id` matches any element of `target`). |
| `telemetry.expectations[].deadline_s` | number | The deadline, measured from the step's completion. |
| `telemetry.expectations[].latency_s` | number or null | Time from the step completing to the event first being read from the audit API. Because collection starts after cleanup, this is an upper bound on the platform's logging delay, and it can exceed the deadline of an `observed` expectation whose event the platform stamped in time. |
| `telemetry.expectations[].event_id` | string | The matching event's ID. Omitted when not seen. |
| `telemetry.expectations[].correlation` | string | How the matching event was attributed to this run: `user-agent` (its recorded User-Agent carries the run's marker), `name-prefix` (the platform did not record the User-Agent whole, and the event names one of the run's `saashound-<run>-<step>` objects) or `hashed-token` (the platform did not record the User-Agent whole, and it recorded the run's own credential for the request: GitHub's `hashed_token`). Anything but `user-agent` is a degraded match; see [Correlation](#correlation). Omitted when not seen. |

### Correlation

An event belongs to the run when one of these holds, and never otherwise:

1. **`user-agent`**: the User-Agent the platform recorded carries this run's marker, `saashound/<version> (run=<run>; phase=<phase>)`. The marker also says which phase made the request. A marker naming another run rules the event out, whatever else it carries.
2. **`name-prefix`** or **`hashed-token`**: the platform recorded no User-Agent, or only a truncated piece of the marker that names no other run, and the event carries another signal specific to this run: one of the run's object names in the fields where the platform names the objects an event acted on (an Okta target's `displayName` or `alternateId`, a GitHub event's `repo` or `repository`), or, on GitHub, the `hashed_token` of the token this run authenticated with (the base64-encoded SHA-256 of the token).

Every correlation is bounded by the run window: from the run's first mutation (its first journalled intent) to the end of cleanup, widened by one minute on each side for clock differences between this machine and the platform. An event the platform stamped outside it is not the run's, whatever it carries; an event correlated by `name-prefix` or `hashed-token` must also have a platform timestamp to place in it. The window is never a signal on its own: an event with nothing specific to this run is never attributed to it because of when it happened.

The fallback never attributes an event the platform recorded with another client's User-Agent (a person in the admin console, the platform itself, another tool, even one using this run's credential), an event that names another run's object, or an event whose remaining piece of marker names another run.

A `name-prefix` or `hashed-token` match carries no marker to say which phase made it, so the phase is read off the platform's timestamp: more than the one-minute tolerance before the end of detonation it is detonation, more than the tolerance after it cleanup. In between, a cleanup call cannot be told from the last detonation call by time alone, and the event is assumed to be detonation so it can still meet the expectation of the step that caused it (`-vv` says which events were assumed). An expectation takes the earliest matching event on the platform's clock, and a step's own event comes before the one its undo causes. Two consequences of a degraded match: if the platform lost the step's own event but logged the matching event its undo caused (an event of the same type), the expectation is met by the undo's event; and the detection checkers see the run's early cleanup events among its detonation-phase events. `correlation` makes every such match visible, and `-v` and the progress line report how many events were matched without the User-Agent. A platform's coverage gap drops an event type, not one event, so it still shows as `missing`.

`hashed-token` has a tighter lower edge than the rest of the window. Consecutive runs on one target authenticate with the same credential, and the one-minute tolerance before a run's first mutation reaches back into the run before it, so the credential alone cannot tell the two runs' events apart there; and the platform's clock may lead or lag this machine's, so neither run's own times can serve as the boundary. An event whose only signal is `hashed-token` must therefore be stamped after the midpoint between the previous run's last mutation on the same target (the last step or undo record of that run's journal in the local state directory, not the records written after its telemetry was collected) and this run's first mutation. One stamped at or before the midpoint is closer to the previous run than to this one: it is not correlated, and `-vv` explains it. This leaves half the gap between the two runs as clock tolerance each way: a platform clock that leads by less than that cannot carry the previous run's events into this run, and one that lags by less than that cannot push this run's events out. Beyond it, an event is left uncorrelated (`missing`) or attributed to the neighbouring run. The gap is the time the previous run spent proving its cleanup and collecting its telemetry, plus whatever passed before this run began, so the tolerance is small when two runs follow each other quickly; once the gap exceeds two minutes the midpoint lies outside the window, and the edge is the window's own, one minute before the first mutation. The first run on a target has no such edge. `name-prefix` and the User-Agent marker name the run itself and keep the whole window.

The midpoint rule only knows the runs recorded in the local state directory. The per-target lock keeps one run per target at a time on one machine and one state directory, so those runs never overlap, but a run against the same tenant with the same credential from another machine, another state directory or another target entry is not known here: an event of such a run that carries only `hashed_token` (no User-Agent, no run object name) and is stamped inside this run's window can still be attributed to this run. The User-Agent marker and `name-prefix` stay safe in that case, because they name the run.

## `detections`

Each entry is one detection a checker evaluated. The `sigma` checker ships: it evaluates the technique's referenced Sigma rules locally, against exactly the events the run produced (its detonation-phase events), and reports per rule whether the rule fired. A technique's `sigma: null` mapping is a published coverage-gap statement ("no public rule covers this"), not a runtime check, so it produces no entry. The `exec` (operator-SIEM) checker is a later increment; the interface (`internal/detect`) is the shared seam.

| Key | Type | Meaning |
|---|---|---|
| `detections[].checker` | string | `sigma`, `exec`, ... |
| `detections[].rule` | string | Rule title. |
| `detections[].id` | string | Stable rule ID (a Sigma rule's UUID), or the reference as written when the rule was not found. |
| `detections[].author` | string | Rule author, carried as the Detection Rule License 1.1 requires for reported matches. |
| `detections[].name` | string | For `exec`, the configured check's name. |
| `detections[].status` | string | `fired` (the rule matched an event), `not-fired` (evaluated, matched nothing), `unknown` (the referenced rule was not found in the loaded rules, or the reference is ambiguous: an id declared by more than one rule, a title shared by several rules, or a path to a file holding several rules), `unsupported` (the rule uses a construct the checker cannot evaluate, such as a Sigma v2 correlation rule or a modifier or condition the evaluator cannot parse; `error` carries the parse error), or `error` (the checker failed, or the drain was interrupted or ended on a failed audit API poll before a rule that had not fired yet could be judged on every event; see below). `unknown`, `unsupported` and `error` never count as a pass and never as a "did not fire": they are reported, and `fired` is null. |
| `detections[].fired` | boolean or null | Whether the detection fired; null unless `status` is `fired` (true) or `not-fired` (false), so a detection the checker could not decide is neither a pass nor a failure. |
| `detections[].latency_s` | number | Time to fire, when known. |
| `detections[].error` | string | Why the checker could not decide (`unknown`, `unsupported` or `error`). |

Only a `not-fired` detection fails the run: it makes the verdict `detection-missing` (exit 1) when telemetry otherwise passed. An `unknown`, `unsupported` or `error` detection is surfaced in the record and the table (the `DETECTIONS` column shows, e.g., `0/1 (unknown)`) but does not by itself fail the run, because the checker makes no "did not fire" claim it cannot stand behind. So a run whose drain was cut short (see below) can still be `pass`, with the undecided rule reported as `error`.

The `sigma` checker judges `fired` / `not-fired` over exactly the events the telemetry collector captured (verbatim; the checker never reads the audit log itself). Collection is driven by the technique's expectations, so a referenced rule's keyed events must be declared as expectations: see [Every event a referenced rule keys on must be an expectation](technique-authoring.md#every-event-a-referenced-rule-keys-on-must-be-an-expectation). As a safety net, once every expected event has been seen, collection does not stop while a referenced rule has not fired yet: it drains, polling the audit log up to 5 more times, one poll interval apart (10 s on Okta and GitHub, where the poll interval is 2 s; 1.25 s on the simulated platform), and stops as soon as every referenced rule has fired. A rule that still has not fired after the drain is `not-fired`. The drain never changes `telemetry`: every expectation is resolved before it starts. A failed drain poll is retried on the next one and never becomes `telemetry.error`. If the drain is interrupted (Ctrl-C), or the audit API fails on its last poll, while a rule has not fired yet, that rule is reported as `error`, not `not-fired`, because its event may simply not have been read; `detections[].error` says which.

A field-less Sigma keyword search is matched against the whole raw event, not one field.

Operator-supplied Sigma rules are loaded from the directory named by `apply --sigma-rules <dir>`, else `$SAASHOUND_SIGMA_RULES`, else a `sigma-rules/` directory beside `targets.yaml`. A small set of example rules for the simulated `fake` platform is always bundled; SigmaHQ's rule repository is never vendored.

## Verdicts

Precedence is top to bottom: an unproven cleanup outranks everything, because it may be a live backdoor.

| `verdict` | Meaning | Exit |
|---|---|---|
| `cleanup-unverified` | At least one object could not be proven gone. Later techniques in the same `apply` are skipped. | 3 |
| `skipped` | The technique was not run; `reason` says why. | 0 |
| `detonate-failed` | Detonation stopped early (error or interrupt); cleanup still ran. | 1 |
| `telemetry-unsupported` | This tenant's tier has no API for the audit log. | 0 |
| `telemetry-missing` | An expected event was missing or late, or telemetry collection failed or was interrupted so not every expectation was checked; `reason` says which. | 1 |
| `detection-missing` | Telemetry arrived but a configured detection did not fire. | 1 |
| `pass` | Every expectation was met and cleanup is verified. | 0 |

`detonate-failed` is an addition to the verdict list in the design report (section 6), which did not cover a detonation that stops early.
