# Writing a technique

A technique is one YAML file that strings registered operations together, says exactly what the platform must log when they run, and says how they are undone. It is data, not code: it can only name ops the binary registers, fill their typed parameters with a fixed `{{...}}` substitution, and declare expectations. It has no host, URL or command field anywhere.

The verified corpus lives in [techniques/](../techniques/) (`techniques/<platform>/<tactic>.<verb-object>.yaml`) and is embedded in the binary. To try a technique of your own without rebuilding, put it in a directory and pass `--corpus-dir <dir>`; its records say `"corpus": "unverified"`.

## A complete example

[techniques/fake/privilege-escalation.admin-role-assign.yaml](../techniques/fake/privilege-escalation.admin-role-assign.yaml), for the simulated platform:

```yaml
id: fake.privilege-escalation.admin-role-assign
name: Grant an admin role to a user
description: >
  After taking over an account, attackers grant admin roles to other accounts
  they control. ...
author: [saashound-maintainers]
platform: fake
attack: [T1098.003]
tradecraft:
  - title: "Okta: cross-tenant impersonation (help-desk MFA reset, second IdP)"
    url: https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
    date: 2023-08-31
evidence: guidance
safety: {production_safe: true, modifies_existing: false, third_party_contact: none}
steps:
  - id: victim
    op: fake.user.create
  - id: grant
    op: fake.role.assign
    with: {user: "{{steps.victim.id}}", role: READ_ONLY_ADMIN}
expect:
  - after: victim
    source: fake.audit
    match: {eventType: user.lifecycle.create, "target[].alternateId": "{{steps.victim.login}}"}
  - after: grant
    source: fake.audit
    match: {eventType: user.account.privilege.grant, "target[].id": "{{steps.grant.id}}", "target[].displayName": READ_ONLY_ADMIN}
cleanup:
  order: [grant, victim]
detections:
  - sigma: 5aa5c0de-face-4d00-8b00-0000feedface
```

## Fields

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | `<platform>.<tactic>.<verb-object>`, lowercase. Permanent once released. The tactic is one of the tool's own frozen list (`initial-access`, `persistence`, `privilege-escalation`, `defense-impairment`, `credential-access`, `discovery`, `lateral-movement`, `collection`, `exfiltration`, `impact`), not ATT&CK's, so an ATT&CK reshuffle never renames a technique. |
| `name` | yes | One line, at most 120 characters. |
| `description` | no | What an attacker does and what this technique does instead, in plain words. |
| `author` | yes | Credit for the contributor. |
| `platform` | yes | A registered provider, and the prefix of `id`. |
| `attack` | no | ATT&CK technique IDs such as `T1098` or `T1098.005`. |
| `tradecraft` | no | Dated public write-ups (`title`, an `https` `url`, `date` as `YYYY-MM-DD`). Documentation only: the tool never fetches them. |
| `evidence` | yes | How well attested the technique is: `incident`, `guidance` or `rules-only`. |
| `safety` | yes | `production_safe` (touches only objects the run creates, makes no change a real user would notice, leaves no surviving secret), `modifies_existing` (never production-safe; any op that changes an object the run did not create needs it), and `third_party_contact`, which must be `none`. |
| `steps` | yes | One to 32 op invocations, run in order. |
| `expect` | yes | One to 64 audit events the platform must log. |
| `cleanup` | yes | `order`: every step ID, last step first. |
| `detections` | no | Public detection rules the technique maps to. |

## Steps and substitution

Each step is an `id` (lowercase words joined by `-`), a registered `op` of the technique's platform, and its parameters in `with`. Every op is reversible by construction (it has an inverse, a proof the inverse worked, and crash recovery), so a technique cannot contain an irreversible step.

Parameter values may use exactly these placeholders, and nothing else (no functions, conditionals, loops or environment lookups):

- `{{run.id}}`, `{{run.prefix}}`: the run's ID and its object-name prefix.
- `{{target.name}}`, `{{target.test_domain}}`: from `targets.yaml`.
- `{{steps.<id>.id}}`, `{{steps.<id>.name}}`, or an output the step's op declares (such as `login`): from an earlier step's journalled result.

A parameter that refers to another object must be exactly `{{steps.<id>.id}}` of an earlier step that created that kind of object.

## Expectations

Each `expect` entry is one audit event the platform must log after a step:

- `after`: the step whose action produces the event. Latency is measured from that step's completion.
- `source`: the platform's audit source (`fake.audit`, `okta.system_log`, `github.audit_log`).
- `match`: field paths to values; every entry must match. `target[].id` matches any element of the `target` array. The match must include the platform's event-type field (`eventType` on Okta and the simulated platform, `action` on GitHub), and that event must be one the `after` step's op is declared to produce. Placeholders may refer to the `after` step and anything earlier.
- `deadline`: optional, between `1s` and `24h`. It defaults to the platform's documented lag (30 s on the simulated platform, 5 minutes on Okta and GitHub).

The collector keeps only the events it can attribute to this run (see [Correlation](result-schema.md#correlation)) and matches expectations against detonation-phase events only, so cleanup traffic never satisfies one. An event that does not arrive by its deadline makes the verdict `telemetry-missing`.

## Detections

`detections` maps the technique to public rules, each one of `sigma: <uuid>` or `elastic: <uuid>`, always by the rule's UUID (rule paths move). `null` is a first-class statement: no public rule of that kind covers the technique, a published coverage gap. Say why in a comment:

```yaml
detections:
  - sigma: null    # no public SigmaHQ rule alerts on user.mfa.factor.activate (2026-11-14)
```

At `apply` time the `sigma` checker evaluates every referenced Sigma rule against the run's detonation-phase events and reports it `fired` or `not-fired`; a `not-fired` rule makes the verdict `detection-missing` (exit 1). The rules are the operator's own, loaded with `--sigma-rules`, so a rule is never available when the technique is validated. See [result-schema.md](result-schema.md#detections).

### Every event a referenced rule keys on must be an expectation

**A referenced rule's keyed events MUST be covered by the technique's declared expectations.** For every event this run is meant to fire the rule on, declare an `expect` entry for that event type after the step that produces it.

Why: the expectations drive collection. The collector polls the audit log until every expected event has arrived or its deadline has passed, and then stops; the checker judges the rule on exactly the events collected by then. Nothing makes the collector wait for an event no expectation asked for. If the rule keys on event B, the technique expects only event A, and B lands a few seconds after A, collection ends without B, the rule is judged on an event set that does not contain it, and the run reports `not-fired` and `detection-missing` for a detection that works. For a tool whose output is "this public rule fires, this one does not", that is being wrong in public about someone else's rule.

With B declared, the collector waits for B up to its deadline, and the run can only end in one of two honest ways: B arrived and the rule was judged on it, or B never arrived and the verdict is `telemetry-missing` (the gap is the platform's logging, not the rule).

In the example above, the bundled rule keys on `user.account.privilege.grant`, and the technique expects exactly that event after the `grant` step. Removing that expectation would leave the rule's verdict to chance.

The validator cannot check this rule for you, because it never sees the operator's rules. Check it when you add or change a `sigma:` reference: read the rule's `detection` selections, find the event types it selects on, and make sure each one this technique triggers has an expectation.

**The drain is a safety net, not a substitute.** While a referenced rule has not fired yet, the collector does not stop at the moment the expectations are met: it polls up to 5 more times, one poll interval apart (10 s on Okta and GitHub, where the poll interval is 2 s; 1.25 s on the simulated platform), and stops as soon as every referenced rule has fired. That catches an undeclared event running a few seconds behind the declared ones. It does not wait the minutes an expectation's deadline allows, and a rule whose event is still missing after the drain is reported `not-fired` (or `error`, if the drain was interrupted or the audit API failed on its last poll, since the event may simply not have been read).

## Validate and test

```sh
saashound validate my-technique.yaml          # schema, ops, parameters, events, cleanup order
saashound --corpus-dir ./mine show fake.privilege-escalation.my-technique
saashound --corpus-dir ./mine plan fake.privilege-escalation.my-technique --target lab
saashound --corpus-dir ./mine apply fake.privilege-escalation.my-technique --target lab --yes
```

The validator lists every problem at once: unknown fields, unregistered ops or ops of another platform, irreversible ops, forward references, an expectation for an event its step's op does not produce, a cleanup order that does not undo every step in reverse, a rule referenced by anything but its UUID.

Run it against the simulated platform first. Its target options make the slow paths reproducible: `audit_lag/<eventType>: 40s` delays one event type, `audit_drop: <eventType>` never logs it. Delaying an event your rule keys on is a quick check that the technique expects it: with the expectation, the run waits for the event up to its deadline; without it, the rule comes back `not-fired` as soon as the delay outlasts the drain.
