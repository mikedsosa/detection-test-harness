"""Synthetic attack and control telemetry.

Everything here is invented. Users live under the reserved ``.example`` TLD
(RFC 2606), IP addresses come from the RFC 5737 documentation ranges, and object
IDs are UUIDv5 values derived from the user's short name. No row was copied
from a real tenant.

Each scenario mixes attack users with benign control users so a rule can be
checked for both a hit it should produce and a hit it should not.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

#: The fixed "now" every scenario and every query evaluation uses.
NOW = datetime(2026, 11, 16, 22, 0, 0, tzinfo=UTC)
DOMAIN = "lab.example"
EXTERNAL = "outside.example"
_NS = uuid.UUID("6f0c8a1e-3b7d-4c55-9a51-000000000000")


def upn(name: str) -> str:
    return f"{name}@{DOMAIN}"


def oid(name: str) -> str:
    return str(uuid.uuid5(_NS, name))


def ago(**kw: float) -> datetime:
    return NOW - timedelta(**kw)


@dataclass
class Scenario:
    name: str
    title: str
    attack: str
    users: dict[str, str]
    rows: dict[str, list[dict]] = field(default_factory=dict)

    def add(self, table: str, row: dict) -> None:
        self.rows.setdefault(table, []).append(row)


# ---------------------------------------------------------------- row helpers
def signin(
    name: str,
    t: datetime,
    *,
    ip: str,
    result: str = "0",
    protocol: str = "none",
    app: str = "Office 365 Exchange Online",
    details: str = "",
    actual_upn: str | None = None,
) -> dict:
    return {
        "TimeGenerated": t,
        "UserPrincipalName": actual_upn or upn(name),
        "UserId": oid(name),
        "ResultType": result,
        "ResultDescription": "" if result == "0" else f"synthetic failure {result}",
        "IPAddress": ip,
        "Location": "US",
        "AppDisplayName": app,
        "AppId": str(uuid.uuid5(_NS, app)),
        "ClientAppUsed": "Browser",
        "UserAgent": "synthetic-agent/1.0",
        "ConditionalAccessStatus": "success" if result == "0" else "notApplied",
        "CorrelationId": str(uuid.uuid5(_NS, f"{name}-{t.isoformat()}-{ip}")),
        "AuthenticationProtocol": protocol,
        "Status": {"errorCode": int(result), "additionalDetails": details}
        if details
        else {"errorCode": int(result)},
    }


def noninteractive(name: str, t: datetime, **kw) -> dict:
    row = signin(name, t, **kw)
    # Status is a string column in AADNonInteractiveUserSignInLogs.
    row["Status"] = json.dumps(row["Status"])
    return row


def audit(
    operation: str,
    t: datetime,
    target: str,
    *,
    by: str = "helpdesk",
    service: str = "Core Directory",
    category: str = "UserManagement",
    result: str = "success",
    target_upn: str | None = None,
) -> dict:
    return {
        "TimeGenerated": t,
        "OperationName": operation,
        "Result": result,
        "ResultReason": "",
        "Category": category,
        "LoggedByService": service,
        "TargetResources": [
            {"id": oid(target), "type": "User", "userPrincipalName": target_upn or upn(target)}
        ],
        "InitiatedBy": {"user": {"userPrincipalName": upn(by), "ipAddress": "192.0.2.10"}},
        "CorrelationId": str(uuid.uuid5(_NS, f"{operation}-{target}-{t.isoformat()}")),
    }


def risk(name: str, t: datetime, *, level: str, kind: str, ip: str = "198.51.100.66") -> dict:
    return {
        "TimeGenerated": t,
        "UserPrincipalName": upn(name),
        "UserId": oid(name),
        "RiskLevel": level,
        "RiskEventType": kind,
        "RiskState": "atRisk",
        "IpAddress": ip,
        "Source": "IdentityProtection",
        "DetectionTimingType": "offline",
    }


def office(name: str, t: datetime, operation: str, params: list[tuple[str, str]], **kw) -> dict:
    return {
        "TimeGenerated": t,
        "Operation": operation,
        "UserId": upn(name),
        "MailboxOwnerUPN": upn(name),
        "ClientIP": kw.get("ip", "203.0.113.80"),
        "ClientInfoString": "Client=OWA",
        "ResultStatus": "True",
        "Parameters": json.dumps([{"Name": n, "Value": v} for n, v in params]),
        "OperationProperties": kw.get("op_props", []),
        "OfficeWorkload": "Exchange",
        "RecordType": "ExchangeAdmin",
    }


# ---------------------------------------------------------------- scenarios
def mfa_fatigue() -> Scenario:
    s = Scenario(
        "mfa_fatigue",
        "MFA fatigue (push bombing) followed by an approved prompt",
        "T1621",
        {
            "alice": "attack: 6 denied pushes in 12 minutes, then a success",
            "bob": "control: 1 denied push, then a success",
            "carmen": "attack: 3 pushes reported as fraud, then a success",
        },
    )
    denied = "MFA denied; user declined the authentication"
    for i in range(6):
        s.add(
            "SigninLogs",
            signin("alice", ago(minutes=50 - 2 * i), ip="198.51.100.20", result="500121", details=denied),
        )
    s.add("SigninLogs", signin("alice", ago(minutes=36), ip="198.51.100.20"))
    s.add("SigninLogs", signin("bob", ago(minutes=40), ip="203.0.113.11", result="500121", details=denied))
    s.add("SigninLogs", signin("bob", ago(minutes=39), ip="203.0.113.11"))
    for i in range(3):
        s.add(
            "SigninLogs",
            signin(
                "carmen",
                ago(minutes=30 - i),
                ip="198.51.100.21",
                result="500121",
                details="MFA denied; user reported fraud",
            ),
        )
    s.add("SigninLogs", signin("carmen", ago(minutes=20), ip="198.51.100.21"))
    return s


def device_code() -> Scenario:
    s = Scenario(
        "device_code",
        "Device code phishing sign-ins",
        "T1566.002 / T1078.004",
        {
            "dana": "attack: interactive deviceCode sign-in",
            "eli": "attack: non-interactive deviceCode token refresh",
            "fern": "control: normal browser sign-in",
        },
    )
    s.add(
        "SigninLogs",
        signin("dana", ago(hours=3), ip="198.51.100.30", protocol="deviceCode", app="Microsoft Office"),
    )
    s.add(
        "AADNonInteractiveUserSignInLogs",
        noninteractive(
            "eli", ago(hours=2), ip="198.51.100.31", protocol="deviceCode", app="Microsoft Office"
        ),
    )
    s.add("SigninLogs", signin("fern", ago(hours=1), ip="203.0.113.12"))
    return s


def inbox_forwarding() -> Scenario:
    ext = f"collector@{EXTERNAL}"
    s = Scenario(
        "inbox_forwarding",
        "Inbox and mailbox forwarding after a mailbox compromise",
        "T1114.003 / T1564.008",
        {
            "gabe": "attack: New-InboxRule ForwardTo an external address",
            "hana": "attack: New-InboxRule that deletes and marks as read",
            "ivan": "attack: Set-Mailbox ForwardingSmtpAddress (not an inbox rule)",
            "jade": "control: New-InboxRule that only applies a category",
            "kai": "control: Set-InboxRule turning a delete action off (DeleteMessage=False)",
            "lena": "attack: Outlook client UpdateInboxRules with a forward action",
        },
    )
    s.add(
        "OfficeActivity",
        office(
            "gabe",
            ago(hours=5),
            "New-InboxRule",
            [("Name", "."), ("ForwardTo", ext), ("StopProcessingRules", "True")],
        ),
    )
    s.add(
        "OfficeActivity",
        office(
            "hana",
            ago(hours=4),
            "New-InboxRule",
            [
                ("Name", "x"),
                ("SubjectContainsWords", "invoice"),
                ("DeleteMessage", "True"),
                ("MarkAsRead", "True"),
            ],
        ),
    )
    s.add(
        "OfficeActivity",
        office(
            "ivan",
            ago(hours=3),
            "Set-Mailbox",
            [
                ("Identity", upn("ivan")),
                ("ForwardingSmtpAddress", f"smtp:{ext}"),
                ("DeliverToMailboxAndForward", "True"),
            ],
        ),
    )
    s.add(
        "OfficeActivity",
        office(
            "jade",
            ago(hours=2),
            "New-InboxRule",
            [("Name", "newsletters"), ("FromAddressContainsWords", "news"), ("ApplyCategory", "Newsletters")],
        ),
    )
    s.add(
        "OfficeActivity",
        office("kai", ago(hours=1), "Set-InboxRule", [("Identity", "cleanup"), ("DeleteMessage", "False")]),
    )
    s.add(
        "OfficeActivity",
        office(
            "lena",
            ago(minutes=30),
            "UpdateInboxRules",
            [],
            op_props=[{"Name": "RuleActions", "Value": "ForwardToRecipientsAction"}],
        ),
    )
    return s


def auth_method_after_risk() -> Scenario:
    s = Scenario(
        "auth_method_after_risk",
        "New MFA method registered around a risk detection",
        "T1556.006 / T1098.005",
        {
            "mara": "attack: high risk, then a new security info registration 2h later",
            "nico": "control: security info registration with no risk detection",
            "omar": "control: low risk, then a registration",
            "pia": "control: medium risk, registration 3 days later",
            "quinn": "edge: registration first, offline medium risk logged 3h later",
        },
    )
    auth = {"service": "Authentication Methods", "category": "UserManagement"}
    s.add("AADUserRiskEvents", risk("mara", ago(hours=30), level="high", kind="unfamiliarFeatures"))
    s.add("AuditLogs", audit("User registered security info", ago(hours=28), "mara", by="mara", **auth))
    s.add("AuditLogs", audit("User registered security info", ago(hours=20), "nico", by="nico", **auth))
    s.add("AADUserRiskEvents", risk("omar", ago(hours=12), level="low", kind="unfamiliarFeatures"))
    s.add("AuditLogs", audit("User registered security info", ago(hours=11), "omar", by="omar", **auth))
    s.add("AADUserRiskEvents", risk("pia", ago(days=5), level="medium", kind="anonymizedIPAddress"))
    s.add("AuditLogs", audit("User registered security info", ago(days=2), "pia", by="pia", **auth))
    s.add("AuditLogs", audit("User registered security info", ago(hours=10), "quinn", by="quinn", **auth))
    s.add("AADUserRiskEvents", risk("quinn", ago(hours=7), level="medium", kind="unlikelyTravel"))
    return s


def password_spray() -> Scenario:
    s = Scenario(
        "password_spray",
        "Password spray from one IP, one account falls",
        "T1110.003",
        {
            "rita": "attack: sprayed account that then signed in; ID Protection passwordSpray",
            "sven": "control: ID Protection unfamiliarFeatures detection only",
        },
    )
    spray_ip = "198.51.100.7"
    for i in range(12):
        s.add("SigninLogs", signin(f"user{i:02d}", ago(minutes=60 - i), ip=spray_ip, result="50126"))
    s.add("SigninLogs", signin("rita", ago(minutes=45), ip=spray_ip, result="50126"))
    s.add("SigninLogs", signin("rita", ago(minutes=44), ip=spray_ip))
    s.add("AADUserRiskEvents", risk("rita", ago(minutes=20), level="high", kind="passwordSpray", ip=spray_ip))
    s.add("AADUserRiskEvents", risk("sven", ago(minutes=10), level="medium", kind="unfamiliarFeatures"))
    return s


def signin_after_disable() -> Scenario:
    s = Scenario(
        "signin_after_disable",
        "Successful sign-in after the account was disabled",
        "T1078.004",
        {
            "tara": "attack: non-interactive success 1h after disable",
            "ugo": "control: success 5 minutes after disable (inside the 15m grace)",
            "vera": "control: disabled, re-enabled 30m later, then signs in",
            "wade": "attack: renamed UPN at sign-in, same object ID, 2h after disable",
        },
    )
    for name in ("tara", "ugo", "vera", "wade"):
        s.add("AuditLogs", audit("Disable account", ago(hours=6), name))
    s.add("AADNonInteractiveUserSignInLogs", noninteractive("tara", ago(hours=5), ip="198.51.100.40"))
    s.add("SigninLogs", signin("ugo", ago(hours=6) + timedelta(minutes=5), ip="203.0.113.41"))
    s.add("AuditLogs", audit("Enable account", ago(hours=5, minutes=30), "vera"))
    s.add("SigninLogs", signin("vera", ago(hours=4), ip="203.0.113.42"))
    s.add("SigninLogs", signin("wade", ago(hours=4), ip="198.51.100.43", actual_upn=f"wade.renamed@{DOMAIN}"))
    return s


def _post_change(operation: str, name: str, title: str) -> Scenario:
    s = Scenario(
        name,
        title,
        "T1078.004",
        {
            "xena": "attack: same pre-change IP signs in 3h after the change",
            "yuri": "control: only a new IP after the change",
            "zane": "control: same IP but 30m after the change (inside the 90m grace)",
        },
    )
    for user, pre_ip in (("xena", "198.51.100.50"), ("yuri", "203.0.113.51"), ("zane", "203.0.113.52")):
        s.add("SigninLogs", signin(user, ago(hours=9), ip=pre_ip))
        s.add(
            "AuditLogs",
            audit(
                operation,
                ago(hours=6),
                user,
                service="Self-service Password Management"
                if "password" in operation.lower()
                else "Core Directory",
            ),
        )
    s.add("AADNonInteractiveUserSignInLogs", noninteractive("xena", ago(hours=3), ip="198.51.100.50"))
    s.add("SigninLogs", signin("yuri", ago(hours=3), ip="198.51.100.99"))
    s.add("SigninLogs", signin("zane", ago(hours=5, minutes=30), ip="203.0.113.52"))
    return s


def signin_after_admin_reset() -> Scenario:
    return _post_change(
        "Reset password (by admin)",
        "signin_after_admin_reset",
        "Sign-in from a pre-reset IP after an admin password reset",
    )


def signin_after_revocation() -> Scenario:
    return _post_change(
        "Update StsRefreshTokenValidFrom Timestamp",
        "signin_after_revocation",
        "Sign-in from a pre-revocation IP after sessions were revoked",
    )


ALL = (
    mfa_fatigue,
    device_code,
    inbox_forwarding,
    auth_method_after_risk,
    password_spray,
    signin_after_disable,
    signin_after_admin_reset,
    signin_after_revocation,
)


def build_all() -> dict[str, Scenario]:
    return {sc.name: sc for sc in (f() for f in ALL)}
