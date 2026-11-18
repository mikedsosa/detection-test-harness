# Results

Synthetic data only. Query time fixed at 2026-11-16T22:00:00+00:00. KQL ran on duckdb-kql (a KQL-to-DuckDB translator), not on the Kusto engine.

| Rule | Owner | Engine | Scenario | Result | Fired for | Missed | Unexpected | Observed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K03 | mike | duckdb-kql | mfa_fatigue | **ENGINE_UNSUPPORTED** | - | - | - | - |
| K03a | mike | duckdb-kql | mfa_fatigue | **PASS** | alice, carmen | - | - | - |
| K06 | mike | duckdb-kql | inbox_forwarding | **PASS** | gabe, hana, lena | - | - | - |
| K08 | mike | duckdb-kql | auth_method_after_risk | **PASS** | mara | - | - | - |
| K09 | mike | duckdb-kql | device_code | **PASS** | dana, eli | - | - | - |
| S15555 | mike | duckdb-kql | signin_after_disable | **PASS** | tara, wade | - | - | - |
| S15656 | mike | duckdb-kql | signin_after_admin_reset | **PASS** | xena | - | - | - |
| S15653 | mike | duckdb-kql | signin_after_revocation | **PASS** | xena | - | - | - |
| SG-CORR | mike | pySigma sqlite | auth_method_after_risk | **PASS** | mara, quinn | - | - | - |
| SG-FWD | upstream | pySigma sqlite | inbox_forwarding | **PASS** | gabe, ivan, lena | - | - | - |
| SG-AUTHM | upstream | pySigma sqlite | auth_method_after_risk | **PASS** | mara, nico, omar, pia, quinn | - | - | - |
| SG-SPRAY | upstream | pySigma sqlite | password_spray | **PASS** | rita | - | - | - |
| SG-DEVCODE | upstream | pySigma sqlite | device_code | **FIELD_MISSING** | - | - | - | - |

Notes:

- **K03**: unsupported KQL construct 'aggregate:make_set_if' (no DuckDB mapping in this wave; see translate/functions.py).
- **K03a**: ADAPTED: make_set_if is not supported by duckdb-kql, so it is replaced with make_set(iff(...)) before running. Only the SuccessIPs display column changes; it can gain an empty string. Scoring uses the user column only.
- **K06**: ivan uses Set-Mailbox, which this inbox-rule query does not claim to cover. kai's row (Set-InboxRule with DeleteMessage=False) is an assumed audit shape, not verified against tenant logs. After entra-account-compromise-ir@9840541, that row is no longer a hit.
- **K08**: quinn registered before the risk event was logged. The query only looks forward from the first risk event, by design.
- **SG-CORR**: Temporal correlation is unordered, so quinn (registration before the risk event) is expected to fire.
- **SG-FWD**: Upstream rule (Mike's open PR #6633 fixes typos in its comments only).
- **SG-AUTHM**: Single-event rule: every user security info registration should match.
- **SG-DEVCODE**: rule field 'properties.message' does not exist in the Sentinel-shaped events. Only interactive SigninLogs are mapped to azure/signinlogs, so eli is not in scope.

Totals: ENGINE_UNSUPPORTED 1, FIELD_MISSING 1, PASS 11 (of 13 rule runs).
