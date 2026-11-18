# Result record: `saashound.result` version 1

`saashound apply` writes one JSON object per technique run to stdout when stdout is not a terminal (or always, with `--jsonl`). The same record is saved as `result.json` in the run's state directory. On a terminal, stdout shows the table view instead; progress always goes to stderr.

This document is the contract. `internal/cli/testdata/golden/*.jsonl` pins the exact shape, and a test fails if a key appears in a record without being documented here.

## Compatibility

- `schema` and `version` identify the record. `version` changes only on a breaking change: a key removed, renamed, or given a different meaning or type.
- Adding a key, or a new value to an enumerated field, is not breaking. Consumers must ignore keys they do not know and treat an unknown enumerated value as "not pass".
- Keys use `snake_case`. Times are RFC 3339 in UTC. Durations are seconds, as numbers, with a `_s` suffix.

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
| `version` | integer | Record version, `1`. |
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
| `detections` | array | One entry per detection checked; empty when no detection checker is configured. |
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

Telemetry is collected after cleanup, from the platform's own audit log, keeping only events whose recorded User-Agent carries this run's ID. Expectations match detonation-phase events only. The collector's own reads carry the run's User-Agent with `phase=collect`.

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

## `detections`

Each entry is one detection a checker evaluated. No checker ships in this version; the interface (`internal/detect`) is in place for the Sigma and `exec` checkers.

| Key | Type | Meaning |
|---|---|---|
| `detections[].checker` | string | `sigma`, `exec`, ... |
| `detections[].rule` | string | Rule title. |
| `detections[].id` | string | Stable rule ID (a Sigma rule's UUID). |
| `detections[].author` | string | Rule author, carried as the Detection Rule License 1.1 requires for reported matches. |
| `detections[].name` | string | For `exec`, the configured check's name. |
| `detections[].fired` | boolean or null | Whether the detection fired; null if the checker could not decide. |
| `detections[].latency_s` | number | Time to fire, when known. |
| `detections[].error` | string | Why the checker could not decide. |

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
