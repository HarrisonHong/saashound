# Security policy

SaaSHound is built to hold a credential that can create a super admin in an identity provider. Its own trustworthiness is part of what it offers, so vulnerabilities in the tool itself are taken seriously and handled privately.

This policy covers vulnerabilities in SaaSHound: the binary, its embedded technique corpus and its build. For what the tool is and is not for, see [Authorized use](README.md#authorized-use).

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (direct link: <https://github.com/HarrisonHong/saashound/security/advisories/new>). Only the maintainers can read the report.

Please include:

- the version (`saashound version`) or commit;
- what an attacker can do, and what they need first (a crafted technique file, local access, a malicious tenant response, ...);
- steps to reproduce, ideally against the simulated `fake` platform so no real tenant is involved;
- whether any real credential or tenant was exposed, so we can help you contain it.

Never send a real token, key or tenant data in a report. If a secret leaked, describe where it appeared, rotate it, and send a recognisable fake value instead.

## What to expect

| Step | Target |
|---|---|
| Acknowledge the report | within 7 days |
| Confirm or rule out the issue, and agree a fix plan | as soon as practical, and we keep you updated |
| Coordinated disclosure | within 90 days of the report, or earlier once a fixed release is available |

Fixes ship as a new release with a GitHub security advisory. We request CVEs through GitHub's CVE Numbering Authority, and credit the reporter in the advisory unless you ask not to be named.

## In scope

These are the properties the tool promises (design report, section 7), so a way to break any of them is a vulnerability:

- **Secret exposure.** A credential or token appearing in any output: stdout, stderr, `-v`/`-vv` logs, the run journal, `events.jsonl`, `plan.json`, `result.json`, fixtures, `targets.yaml`, error messages or crash output.
- **Corpus escape.** A technique file (embedded or loaded with `--corpus-dir`) that can execute code, read local files, choose a request destination, or cause a request to any host other than the declared tenant's API.
- **Guardrail bypass.** Touching a tenant without every check passing: allowlist, live tenant and principal match, the human-placed ownership marker, the environment class, or confirmation. Includes `apply --plan` executing anything other than what the corpus would plan.
- **False verified cleanup.** A run reporting `cleanup: verified` while an object it created, or a value it changed, remains.
- **Wrong-object cleanup.** Cleanup or `sweep` touching an object the tool did not create (for example by matching names loosely), or replaying a journal against a different tenant.
- **Path traversal.** Any file written outside the state directory or an explicit output path.
- **Listener or remote control.** Anything that makes the tool accept network connections or commands from anywhere but its own command line.
- **Supply chain.** A dependency or build issue that would put untrusted code in the released binary.

## Out of scope

- Misuse by someone who already holds admin credentials for a tenant they do not own. Every technique is documented tradecraft that `curl` reproduces; the guardrails make accidents hard and misuse loud, they cannot prove legal ownership. See [Authorized use](README.md#authorized-use).
- Vulnerabilities in the platforms themselves (Okta, GitHub, ...). Report those to the vendor.
- A public detection rule that does not fire on real events. That is a finding the tool exists to produce: report it to the rule's maintainers.
- Issues that need a compromised local machine or an already-modified binary.

## Supported versions

SaaSHound is pre-release. Fixes go to the latest release and `main` only.
