# Detection Test Harness

Replays synthetic Microsoft Entra ID and Microsoft 365 attack telemetry against my KQL hunting queries and Sigma rules, offline, and reports a pass/fail table per rule.

> **Synthetic data only.** Every user, IP address, and event in this repo is invented. Users sit under the reserved `.example` TLD, IPs come from the RFC 5737 documentation ranges, and no row was copied from a real tenant. A PASS here means a rule behaved as its own description says on this data. It does not mean the rule has been validated against a real tenant.

## Problem

My detection repos say "not tested against a real tenant", and that is still true. But there is a gap between "never run" and "run in production": I can at least check that each query parses, executes, fires on the attack pattern it describes, and stays quiet on the benign look-alikes I can think of. Without a tenant, that needs data I generate myself and a query engine I can run locally.

## Approach

1. **Scenarios** (`src/dth/scenarios.py`) build Sentinel-shaped rows for eight attack patterns. Each scenario mixes attack users with benign control users. Column names and types come from the Azure Monitor table definitions shipped in pySigma-backend-kusto, so the tables have real column names, not invented ones.
2. **KQL rules** run on [duckdb-kql](https://github.com/mmaitre314/duckdb-kql) 1.1.3, which parses KQL and translates it to DuckDB SQL. `ago()` is evaluated against a fixed query time (2026-11-16 22:00 UTC) so results are reproducible.
3. **Sigma rules** are converted with pySigma's SQLite backend and run against the same rows, flattened into one table. The SQLite backend supports Sigma correlation rules, so the temporal correlation draft runs too.
4. **Scoring** (`src/dth/rules.py`) lists, for every rule, the users it should fire on, the users it should not, and users that are only observed. Expectations come from each rule's own description, not from its output.
5. **Mutation checks** (`tests/test_rules.py`) weaken one piece of logic at a time (a grace period, a window, a join) and assert that the matching control user then shows up. That shows each control case actually exercises the logic it is meant to.

No network calls, cloud accounts, paid APIs, or LLMs are used at run time. Installing the dependencies needs PyPI once.

### Rules under test

| ID | Rule | Owner | Source |
| --- | --- | --- | --- |
| K03 / K03a | MFA fatigue (repeated MFA denials, then success) | Mike | `entra-account-compromise-ir` query 03 |
| K06 | Inbox rule changes that forward, redirect, delete, or hide mail | Mike | `entra-account-compromise-ir` query 06 |
| K08 | MFA / security info change after a user risk detection | Mike | `entra-account-compromise-ir` query 08 |
| K09 | Device code flow sign-ins | Mike | `entra-account-compromise-ir` query 09 |
| S15555 | Successful sign-in after account disabled | Mike | Azure-Sentinel PR #15555 (merged) |
| S15656 | Sign-in from pre-reset IP after admin password reset | Mike | Azure-Sentinel PR #15656 (open) |
| S15653 | Sign-in from pre-revocation IP after session revocation | Mike | Azure-Sentinel PR #15653 (open) |
| SG-CORR | Auth method change after risk detection (temporal correlation + 2 base rules) | Mike | Unpublished Sigma draft |
| SG-FWD | M365 suspicious email forwarding activity (threat hunting) | SigmaHQ | SigmaHQ/sigma master `54967d6` |
| SG-AUTHM | Azure change to authentication method | SigmaHQ | SigmaHQ/sigma master `54967d6` |
| SG-SPRAY | Azure Identity Protection password spray | SigmaHQ | SigmaHQ/sigma master `54967d6` |
| SG-DEVCODE | Azure application device code authentication | SigmaHQ | SigmaHQ/sigma master `54967d6` |

The upstream SigmaHQ rules are included for context next to my own rules for the same scenarios. Exact source commits and SHA-256 hashes of every vendored file are in [`rules/PROVENANCE.json`](rules/PROVENANCE.json), and a test fails if a vendored file drifts. SigmaHQ rules are under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md); their author fields are kept unchanged.

### Scenarios

| Scenario | Technique | Attack users | Control users |
| --- | --- | --- | --- |
| `mfa_fatigue` | T1621 | 6 declined pushes then success; 3 fraud reports then success | 1 declined push then success |
| `device_code` | T1566.002 / T1078.004 | interactive and non-interactive `deviceCode` sign-ins | normal browser sign-in |
| `inbox_forwarding` | T1114.003 / T1564.008 | ForwardTo rule; delete + mark-read rule; `Set-Mailbox` forwarding; Outlook `UpdateInboxRules` forward | category-only rule; `Set-InboxRule` with `DeleteMessage=False` |
| `auth_method_after_risk` | T1556.006 | high risk then MFA registration 2h later; registration then offline risk 3h later | registration without risk; low risk; medium risk 3 days earlier |
| `password_spray` | T1110.003 | 13 accounts fail from one IP, one then succeeds and gets an ID Protection `passwordSpray` detection | unrelated `unfamiliarFeatures` detection |
| `signin_after_disable` | T1078.004 | success 1h after disable; renamed UPN with the same object ID | sign-in inside the 15m grace; disabled then re-enabled |
| `signin_after_admin_reset` | T1078.004 | pre-reset IP signs in 3h after reset | new IP only; same IP inside the 90m grace |
| `signin_after_revocation` | T1078.004 | pre-revocation IP signs in 3h after revocation | new IP only; same IP inside the 90m grace |

Run `dth scenarios` for the per-user list.

## Setup

Python 3.11 or newer. Tested on Linux (Debian 13) only.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

dth scenarios                 # list the synthetic scenarios
dth run                       # print the results table
dth run --out results         # also write results/RESULTS.md and results/results.json
python -m pytest -q           # 45 tests
ruff check . && ruff format --check .
```

`dth run --strict` exits non-zero unless every rule passes, for use in CI once the open items below are resolved.

## Results

Run on 17 Nov 2026 with Python 3.13.5, duckdb-kql 1.1.3, DuckDB 2.0.0, pySigma 1.5.1, and pySigma-backend-sqlite 2.0.0. Full table with notes: [`results/RESULTS.md`](results/RESULTS.md).

| Rule | Engine | Result | Fired for | Unexpected |
| --- | --- | --- | --- | --- |
| K03 | duckdb-kql | ENGINE_UNSUPPORTED | - | - |
| K03a (adapted) | duckdb-kql | PASS | alice, carmen | - |
| K06 | duckdb-kql | PASS | gabe, hana, lena | - |
| K08 | duckdb-kql | PASS | mara | - |
| K09 | duckdb-kql | PASS | dana, eli | - |
| S15555 | duckdb-kql | PASS | tara, wade | - |
| S15656 | duckdb-kql | PASS | xena | - |
| S15653 | duckdb-kql | PASS | xena | - |
| SG-CORR | pySigma sqlite | PASS | mara, quinn | - |
| SG-FWD | pySigma sqlite | PASS | gabe, ivan, lena | - |
| SG-AUTHM | pySigma sqlite | PASS | mara, nico, omar, pia, quinn | - |
| SG-SPRAY | pySigma sqlite | PASS | rita | - |
| SG-DEVCODE | pySigma sqlite | FIELD_MISSING | - | - |

Totals: 11 PASS, 1 ENGINE_UNSUPPORTED, 1 FIELD_MISSING, out of 13 rule runs. All 10 mutation checks (9 KQL, 1 Sigma correlation) expose their control user. 45 tests pass.

Query 06 was refreshed after `entra-account-compromise-ir@9840541` (merged 2026-11-18 01:44 UTC). It now treats the boolean hide/delete parameters as a hit only when the value is true, so the `Set-InboxRule` control user with `DeleteMessage=False` no longer fires. The audit row shape for that case is still my assumption and has not been checked against tenant logs.

What the non-PASS rows mean:

- **K03 ENGINE_UNSUPPORTED.** duckdb-kql 1.1.3 has no mapping for `make_set_if`. K03a runs the same query with that one aggregate rewritten as `make_set(iff(...))`, which only affects a display column. The original query has still not been executed anywhere.
- **SG-DEVCODE FIELD_MISSING.** The rule matches `properties.message`, which is not a column in Sentinel's `SigninLogs`. With this harness's flattening (no field-mapping pipeline), it cannot be evaluated. It would need a mapping to `AuthenticationProtocol` or a different source log shape.
- **K08 vs SG-CORR on quinn.** Query 08 looks only forward from the risk event; the Sigma correlation draft is unordered on purpose. On the "registration first, risk logged later" case, the correlation fires and the KQL query does not. That is recorded, not scored, for K08.

## Limitations

- **Synthetic data, my assumptions.** Row shapes follow the documented table schemas, but values such as `Parameters` JSON layout, `OperationProperties` for `UpdateInboxRules`, and `Status.additionalDetails` strings are my reconstruction. Real tenants will have fields and values these scenarios do not.
- **Not the Kusto engine.** duckdb-kql translates KQL to SQL. Its README reports agreement with the Kusto emulator on a subset of cases, but I did not run the emulator here (no Docker on this machine), so a PASS is a PASS under duckdb-kql. Subtle differences (for example `has` term matching, null handling in joins, datetime precision) could change results on real Sentinel. `tests/test_engines.py` pins the specific operators the rules use, so an engine upgrade that changes them shows up.
- **Sigma field mapping is minimal.** Field names match Sentinel columns case-insensitively, JSON columns are flattened with dotted names, and lists expose only their first element. No pySigma processing pipeline is applied. Sigma rules written for a different log shape will report FIELD_MISSING instead of a guess.
- **Expectations are mine.** Scores reflect what each rule claims to detect. A rule can PASS here and still be noisy or blind in a real environment.
- **Small scenario set.** One to six users per scenario. No volume, timing jitter, or adversarial evasion testing.
- **No raw-sign-in password spray rule.** The spray scenario only exercises the ID Protection `passwordSpray` Sigma rule; I don't have a published query that detects spray from raw failures.
- **Young dependency.** duckdb-kql was first published in 2026 and has a small user base. It is pinned to an exact version.

## Layout

```text
src/dth/         scenarios, schema, KQL and Sigma runners, scoring, report, CLI
rules/kql/       vendored KQL (entra-account-compromise-ir queries, Sentinel hunting YAML)
rules/sigma/     vendored Sigma (mike-draft/ and upstream/)
rules/PROVENANCE.json  source commit and SHA-256 per vendored file
results/         RESULTS.md and results.json from the last `dth run --out results`
tests/           data, engine, rule, and mutation tests
scripts/         record_provenance.py
```

## License

MIT for the harness code, docs, and my own rules. See [LICENSE](LICENSE). The four SigmaHQ rules in `rules/sigma/upstream/` are not covered by the MIT license. They are under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md), with their `author` fields unchanged and their source commit recorded in `rules/PROVENANCE.json`.
