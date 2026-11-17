"""Hand-checked micro cases for the engine behaviour the rules depend on.

These do not prove duckdb-kql matches Kusto. They pin the specific operators the
vendored queries use, so an engine upgrade that changes them shows up here first.
"""

import json
import sqlite3
from datetime import timedelta

import duckdb_kql
import pytest

from dth import kql, sigma
from dth.scenarios import NOW, audit, office, risk, signin


def _run(query, rows):
    return kql.run(query, rows)


def test_ago_uses_the_fixed_query_time():
    rows = {
        "SigninLogs": [
            signin("a", NOW - timedelta(hours=1), ip="192.0.2.1"),
            signin("b", NOW - timedelta(days=2), ip="192.0.2.2"),
        ]
    }
    out = _run("SigninLogs | where TimeGenerated > ago(1d) | project UserPrincipalName", rows)
    assert [r["UserPrincipalName"] for r in out] == ["a@lab.example"]


def test_mv_expand_and_dynamic_property_access():
    rows = {"AuditLogs": [audit("Disable account", NOW, "a")]}
    out = _run(
        "AuditLogs | mv-expand T = TargetResources | extend U = tostring(T.userPrincipalName), "
        "Ty = tostring(T.type) | project U, Ty",
        rows,
    )
    assert out == [{"U": "a@lab.example", "Ty": "User"}]


def test_has_any_on_a_string_column_is_term_based():
    rows = {
        "OfficeActivity": [
            office("a", NOW, "New-InboxRule", [("ForwardTo", "x@outside.example")]),
            office("b", NOW, "New-InboxRule", [("ForwardToX", "y")]),
        ]
    }
    out = _run('OfficeActivity | where Parameters has_any ("ForwardTo") | project UserId', rows)
    assert [r["UserId"] for r in out] == ["a@lab.example"]


def test_inner_and_leftouter_join_on_different_column_names():
    rows = {
        "AADUserRiskEvents": [risk("a", NOW, level="high", kind="x")],
        "SigninLogs": [signin("a", NOW, ip="192.0.2.1"), signin("b", NOW, ip="192.0.2.2")],
    }
    q = (
        "SigninLogs | project U = UserPrincipalName | join kind={k} "
        "(AADUserRiskEvents | project R = UserPrincipalName, RiskLevel) on $left.U == $right.R "
        "| project U, RiskLevel | order by U asc"
    )
    inner = _run(q.format(k="inner"), rows)
    left = _run(q.format(k="leftouter"), rows)
    assert inner == [{"U": "a@lab.example", "RiskLevel": "high"}]
    assert [r["U"] for r in left] == ["a@lab.example", "b@lab.example"]
    assert left[1]["RiskLevel"] in (None, "")


def test_between_is_inclusive():
    rows = {"SigninLogs": [signin("a", NOW, ip="192.0.2.1")]}
    q = "SigninLogs | where TimeGenerated between (datetime({t}) .. datetime({t})) | count"
    out = _run(q.format(t=NOW.strftime("%Y-%m-%dT%H:%M:%SZ")), rows)
    assert list(out[0].values()) == [1]


def test_unsupported_constructs_raise_instead_of_guessing():
    rows = {"SigninLogs": [signin("a", NOW, ip="192.0.2.1")]}
    with pytest.raises(duckdb_kql.KqlUnsupportedError):
        _run("SigninLogs | summarize make_set_if(IPAddress, true, 5)", rows)


def test_unknown_column_is_an_error_not_null():
    rows = {"SigninLogs": [signin("a", NOW, ip="192.0.2.1")]}
    with pytest.raises(Exception):  # noqa: B017 - any engine error is acceptable here
        _run("SigninLogs | where NotAColumn == 'x'", rows)


def test_sigma_flattening_exposes_first_list_element_and_nested_keys():
    event = sigma.events_for(("AuditLogs",), {"AuditLogs": [audit("Add device", NOW, "a")]})[0]
    assert event["TargetResources.userPrincipalName"] == "a@lab.example"
    assert event["InitiatedBy.user.userPrincipalName"] == "helpdesk@lab.example"
    assert json.loads(event["TargetResources"])[0]["type"] == "User"
    assert event["timestamp"] == NOW.isoformat()


def test_sqlite_equality_is_case_insensitive_like_sigma():
    con = sigma._load_db([{"timestamp": NOW.isoformat(), "RiskLevel": "HIGH"}])
    assert con.execute("SELECT count(*) FROM logs WHERE riskLevel='high'").fetchone()[0] == 1
    con.close()


def test_missing_sigma_field_is_reported(tmp_path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        "title: t\nid: 1d0c8f7e-0000-4000-8000-000000000001\nstatus: test\n"
        "logsource:\n  product: azure\n  service: signinlogs\n"
        "detection:\n  sel:\n    properties.nothing: x\n  condition: sel\nlevel: low\n",
        encoding="utf-8",
    )
    rows = {"SigninLogs": [signin("a", NOW, ip="192.0.2.1")]}
    with pytest.raises(sigma.MissingField) as info:
        sigma.run([rule], rows)
    assert info.value.field == "properties.nothing"


def test_case_folded_field_collision_is_refused():
    with pytest.raises(ValueError):
        sigma._load_db([{"timestamp": "t", "RiskLevel": "x"}, {"timestamp": "t", "riskLevel": "y"}])


def test_sqlite_is_stdlib():
    assert sqlite3.sqlite_version
