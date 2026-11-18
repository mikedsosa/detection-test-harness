"""The rules under test, where each one came from, and what it should do on each scenario.

Expectations are written from each rule's own stated intent (its description or
header comment), not from what the rule happens to return. ``observe`` users are
recorded but not scored: the rule makes no claim about them either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules"

ENTRA_IR = "mikedsosa/entra-account-compromise-ir@9840541c6bbdaaacd6e7323a585a4524ae6302e7"
SIGMA_MASTER = "SigmaHQ/sigma@54967d64e6dda2b4daa81f47f7a8bf1f591b68a0 (master)"


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str  # "kql" or "sigma"
    files: tuple[str, ...]
    scenario: str
    owner: str  # "mike" or "upstream"
    source: str
    fire: frozenset[str]
    no_fire: frozenset[str] = frozenset()
    observe: frozenset[str] = frozenset()
    adapt: tuple[tuple[str, str], ...] = ()
    notes: str = ""
    paths: tuple[Path, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "paths", tuple(RULES / f for f in self.files))


def _f(*names: str) -> frozenset[str]:
    return frozenset(names)


MFA_ADAPT = (("make_set_if(SuccessIP, InWindow, 20)", 'make_set(iff(InWindow, SuccessIP, ""), 20)'),)

REGISTRY: tuple[Rule, ...] = (
    Rule(
        "K03",
        "kql",
        ("kql/03-mfa-fatigue.kql",),
        "mfa_fatigue",
        "mike",
        f"{ENTRA_IR} queries/03-mfa-fatigue.kql",
        fire=_f("alice", "carmen"),
        no_fire=_f("bob"),
    ),
    Rule(
        "K03a",
        "kql",
        ("kql/03-mfa-fatigue.kql",),
        "mfa_fatigue",
        "mike",
        f"{ENTRA_IR} queries/03-mfa-fatigue.kql, adapted",
        fire=_f("alice", "carmen"),
        no_fire=_f("bob"),
        adapt=MFA_ADAPT,
        notes="ADAPTED: make_set_if is not supported by duckdb-kql, so it is replaced with "
        "make_set(iff(...)) before running. Only the SuccessIPs display column changes; "
        "it can gain an empty string. Scoring uses the user column only.",
    ),
    Rule(
        "K06",
        "kql",
        ("kql/06-inbox-rule-changes.kql",),
        "inbox_forwarding",
        "mike",
        f"{ENTRA_IR} queries/06-inbox-rule-changes.kql",
        fire=_f("gabe", "hana", "lena"),
        no_fire=_f("jade", "kai"),
        observe=_f("ivan"),
        notes="ivan uses Set-Mailbox, which this inbox-rule query does not claim to cover. "
        "kai's row (Set-InboxRule with DeleteMessage=False) is an assumed audit shape, "
        "not verified against tenant logs. After entra-account-compromise-ir@9840541, "
        "that row is no longer a hit.",
    ),
    Rule(
        "K08",
        "kql",
        ("kql/08-auth-method-change-after-risk.kql",),
        "auth_method_after_risk",
        "mike",
        f"{ENTRA_IR} queries/08-auth-method-change-after-risk.kql",
        fire=_f("mara"),
        no_fire=_f("nico", "omar", "pia"),
        observe=_f("quinn"),
        notes="quinn registered before the risk event was logged. The query only looks "
        "forward from the first risk event, by design.",
    ),
    Rule(
        "K09",
        "kql",
        ("kql/09-device-code-signins.kql",),
        "device_code",
        "mike",
        f"{ENTRA_IR} queries/09-device-code-signins.kql",
        fire=_f("dana", "eli"),
        no_fire=_f("fern"),
    ),
    Rule(
        "S15555",
        "kql",
        ("kql/SuccessfulSignInAfterAccountDisabled.yaml",),
        "signin_after_disable",
        "mike",
        "Azure/Azure-Sentinel PR #15555 (merged), branch head d6f2b4e4cce1b8db884b1fe478a1a333edbb94fa",
        fire=_f("tara", "wade"),
        no_fire=_f("ugo", "vera"),
    ),
    Rule(
        "S15656",
        "kql",
        ("kql/SuccessfulSignInAfterAdminPasswordReset.yaml",),
        "signin_after_admin_reset",
        "mike",
        "Azure/Azure-Sentinel PR #15656 (open), branch head d2d0376585a410b8ffbb1908764259ecf5f171c0",
        fire=_f("xena"),
        no_fire=_f("yuri", "zane"),
    ),
    Rule(
        "S15653",
        "kql",
        ("kql/SuccessfulSignInAfterSessionRevocation.yaml",),
        "signin_after_revocation",
        "mike",
        "Azure/Azure-Sentinel PR #15653 (open), branch head 2662278291fa91f9e2a44a1c1a56ac67f4c1da5c",
        fire=_f("xena"),
        no_fire=_f("yuri", "zane"),
    ),
    Rule(
        "SG-CORR",
        "sigma",
        (
            "sigma/mike-draft/azure_identity_protection_user_risk_medium_high.yml",
            "sigma/mike-draft/azure_auditlogs_security_info_change.yml",
            "sigma/mike-draft/correlation_azure_auth_method_change_after_risk.yml",
        ),
        "auth_method_after_risk",
        "mike",
        "Unpublished draft, local branch correlation-entra-risk-then-auth-method @ "
        "c5ea96fd1069547135f60fe75bf231aa54f485a8 (Sigma correlation rules are on hold, see #5759)",
        fire=_f("mara", "quinn"),
        no_fire=_f("nico", "omar", "pia"),
        notes="Temporal correlation is unordered, so quinn (registration before the risk "
        "event) is expected to fire.",
    ),
    Rule(
        "SG-FWD",
        "sigma",
        ("sigma/upstream/microsoft365_susp_email_forwarding_activity.yml",),
        "inbox_forwarding",
        "upstream",
        f"{SIGMA_MASTER} rules-threat-hunting/cloud/m365/audit/",
        fire=_f("gabe", "ivan", "lena"),
        no_fire=_f("hana", "jade", "kai"),
        notes="Upstream rule (Mike's open PR #6633 fixes typos in its comments only).",
    ),
    Rule(
        "SG-AUTHM",
        "sigma",
        ("sigma/upstream/azure_change_to_authentication_method.yml",),
        "auth_method_after_risk",
        "upstream",
        f"{SIGMA_MASTER} rules/cloud/azure/audit_logs/",
        fire=_f("mara", "nico", "omar", "pia", "quinn"),
        notes="Single-event rule: every user security info registration should match.",
    ),
    Rule(
        "SG-SPRAY",
        "sigma",
        ("sigma/upstream/azure_identity_protection_password_spray.yml",),
        "password_spray",
        "upstream",
        f"{SIGMA_MASTER} rules/cloud/azure/identity_protection/",
        fire=_f("rita"),
        no_fire=_f("sven"),
    ),
    Rule(
        "SG-DEVCODE",
        "sigma",
        ("sigma/upstream/azure_app_device_code_authentication.yml",),
        "device_code",
        "upstream",
        f"{SIGMA_MASTER} rules/cloud/azure/signin_logs/",
        fire=_f("dana"),
        no_fire=_f("fern"),
        notes="Only interactive SigninLogs are mapped to azure/signinlogs, so eli is not in scope.",
    ),
)
