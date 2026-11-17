"""The synthetic data is synthetic, deterministic, and matches the declared schema."""

import ipaddress
import json
import re

from dth.scenarios import DOMAIN, EXTERNAL, build_all
from dth.schema import COLUMNS, kusto_type

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+[A-Za-z])")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_every_row_matches_the_table_schema(scenarios):
    for sc in scenarios.values():
        for table, rows in sc.rows.items():
            assert table in COLUMNS
            for row in rows:
                assert set(row) == set(COLUMNS[table]), (sc.name, table)


def test_schema_columns_exist_in_the_azure_monitor_definitions():
    for table, cols in COLUMNS.items():
        for col in cols:
            assert kusto_type(table, col) in {"datetime", "string", "dynamic"}


def test_only_reserved_domains_and_documentation_ips(scenarios):
    for sc in scenarios.values():
        for rows in sc.rows.values():
            for row in rows:
                for key in ("IPAddress", "IpAddress", "ClientIP"):
                    if key in row:
                        ip = ipaddress.ip_address(row[key])
                        assert any(ip in n for n in DOC_NETS), row[key]
                text = json.dumps(row, default=str)
                for domain in EMAIL.findall(text):
                    assert domain in {DOMAIN, EXTERNAL}, domain


def test_generation_is_deterministic():
    a = {k: v.rows for k, v in build_all().items()}
    b = {k: v.rows for k, v in build_all().items()}
    assert json.dumps(a, default=str, sort_keys=True) == json.dumps(b, default=str, sort_keys=True)


def test_every_scenario_has_an_attack_and_a_control(scenarios):
    for sc in scenarios.values():
        roles = " ".join(sc.users.values())
        assert "attack" in roles, sc.name
        assert "control" in roles, sc.name
