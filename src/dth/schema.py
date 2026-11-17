"""Table schemas for the synthetic Microsoft Sentinel tables.

Column names and types come from the Azure Monitor table definitions that ship
inside pySigma-backend-kusto (``sigma.pipelines.azuremonitor.tables``). Only the
columns the rules and scenarios use are created, so a query that names a column
outside this subset fails loudly instead of silently reading NULL.
"""

from __future__ import annotations

from sigma.pipelines.azuremonitor.tables import AZURE_MONITOR_TABLES

COLUMNS: dict[str, tuple[str, ...]] = {
    "SigninLogs": (
        "TimeGenerated",
        "UserPrincipalName",
        "UserId",
        "ResultType",
        "ResultDescription",
        "IPAddress",
        "Location",
        "AppDisplayName",
        "AppId",
        "ClientAppUsed",
        "UserAgent",
        "ConditionalAccessStatus",
        "CorrelationId",
        "AuthenticationProtocol",
        "Status",
    ),
    "AADNonInteractiveUserSignInLogs": (
        "TimeGenerated",
        "UserPrincipalName",
        "UserId",
        "ResultType",
        "ResultDescription",
        "IPAddress",
        "Location",
        "AppDisplayName",
        "AppId",
        "ClientAppUsed",
        "UserAgent",
        "ConditionalAccessStatus",
        "CorrelationId",
        "AuthenticationProtocol",
        "Status",
    ),
    "AuditLogs": (
        "TimeGenerated",
        "OperationName",
        "Result",
        "ResultReason",
        "Category",
        "LoggedByService",
        "TargetResources",
        "InitiatedBy",
        "CorrelationId",
    ),
    "AADUserRiskEvents": (
        "TimeGenerated",
        "UserPrincipalName",
        "UserId",
        "RiskLevel",
        "RiskEventType",
        "RiskState",
        "IpAddress",
        "Source",
        "DetectionTimingType",
    ),
    "OfficeActivity": (
        "TimeGenerated",
        "Operation",
        "UserId",
        "MailboxOwnerUPN",
        "ClientIP",
        "ClientInfoString",
        "ResultStatus",
        "Parameters",
        "OperationProperties",
        "OfficeWorkload",
        "RecordType",
    ),
}

_DUCKDB_TYPES = {"datetime": "TIMESTAMPTZ", "string": "VARCHAR", "dynamic": "JSON"}


def kusto_type(table: str, column: str) -> str:
    """Return the Kusto data type for a column, from the shipped table definitions."""
    try:
        return AZURE_MONITOR_TABLES[table][column]["data_type"]
    except KeyError as exc:  # pragma: no cover - guarded by tests
        raise KeyError(f"{table}.{column} is not in the Azure Monitor table definitions") from exc


def duckdb_ddl(table: str) -> str:
    cols = ", ".join(f'"{col}" {_DUCKDB_TYPES[kusto_type(table, col)]}' for col in COLUMNS[table])
    return f'CREATE TABLE "{table}" ({cols})'


def dynamic_columns(table: str) -> set[str]:
    return {col for col in COLUMNS[table] if kusto_type(table, col) == "dynamic"}
