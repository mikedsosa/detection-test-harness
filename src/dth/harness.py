"""Run every registered rule against its scenario and score it."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import duckdb_kql

from dth import kql, sigma
from dth.rules import REGISTRY, Rule
from dth.scenarios import DOMAIN, build_all

PASS, FAIL = "PASS", "FAIL"
ENGINE_UNSUPPORTED, FIELD_MISSING, ERROR = "ENGINE_UNSUPPORTED", "FIELD_MISSING", "ERROR"

_USER_KEYS = (
    "UserUpn",
    "TargetUPN",
    "UserPrincipalName",
    "MailboxOwnerUPN",
    "TargetResources.userPrincipalName",
    "UserId",
)


@dataclass
class Outcome:
    rule: str
    kind: str
    owner: str
    scenario: str
    status: str
    hits: list[str]
    missed: list[str]
    unexpected: list[str]
    observed: list[str]
    rows: int
    detail: str = ""


def _short(value: object) -> str | None:
    if not isinstance(value, str) or "@" not in value:
        return None
    local, _, domain = value.partition("@")
    if domain != DOMAIN:
        return None
    return local.split(".")[0]


def users_in(rows: list[dict]) -> set[str]:
    found: set[str] = set()
    for row in rows:
        if "group_keys" in row:
            found.add(_short(json.loads(row["group_keys"]).get("user")) or "")
            continue
        for key in _USER_KEYS:
            short = _short(row.get(key))
            if short:
                found.add(short)
                break
    found.discard("")
    return found


def score(rule: Rule, users: set[str], rows: int) -> Outcome:
    missed = sorted(rule.fire - users)
    unexpected = sorted(users & rule.no_fire)
    status = PASS if not missed and not unexpected else FAIL
    return Outcome(
        rule.id,
        rule.kind,
        rule.owner,
        rule.scenario,
        status,
        sorted(users),
        missed,
        unexpected,
        sorted(users & rule.observe),
        rows,
    )


def run_rule(rule: Rule, scenarios=None) -> Outcome:
    scenarios = scenarios or build_all()
    data = scenarios[rule.scenario].rows
    try:
        if rule.kind == "kql":
            query = kql.load_query(rule.paths[0])
            for old, new in rule.adapt:
                if old not in query:
                    raise ValueError(f"adaptation target not found: {old}")
                query = query.replace(old, new)
            rows = kql.run(query, data)
        else:
            rows, _ = sigma.run(list(rule.paths), data)
    except duckdb_kql.KqlUnsupportedError as exc:
        return Outcome(
            rule.id,
            rule.kind,
            rule.owner,
            rule.scenario,
            ENGINE_UNSUPPORTED,
            [],
            [],
            [],
            [],
            0,
            str(exc).splitlines()[0],
        )
    except sigma.MissingField as exc:
        return Outcome(
            rule.id,
            rule.kind,
            rule.owner,
            rule.scenario,
            FIELD_MISSING,
            [],
            [],
            [],
            [],
            0,
            f"rule field '{exc.field}' does not exist in the Sentinel-shaped events",
        )
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        return Outcome(
            rule.id,
            rule.kind,
            rule.owner,
            rule.scenario,
            ERROR,
            [],
            [],
            [],
            [],
            0,
            f"{type(exc).__name__}: {exc}",
        )
    return score(rule, users_in(rows), len(rows))


def run_all() -> list[Outcome]:
    scenarios = build_all()
    return [run_rule(rule, scenarios) for rule in REGISTRY]


def to_json(outcomes: list[Outcome]) -> str:
    return json.dumps([asdict(o) for o in outcomes], indent=2, sort_keys=True) + "\n"
