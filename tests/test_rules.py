"""The full replay, plus mutation checks that show each control case is load-bearing."""

import hashlib
import json
from pathlib import Path

import pytest

from dth import harness
from dth.harness import ENGINE_UNSUPPORTED, FAIL, FIELD_MISSING, PASS
from dth.rules import REGISTRY, RULES

ROOT = Path(__file__).resolve().parents[1]

#: Recorded on the first run of this harness. A change here means a rule, the
#: data, or an engine changed behaviour, and RESULTS.md should be regenerated.
EXPECTED_STATUS = {
    "K03": ENGINE_UNSUPPORTED,
    "K03a": PASS,
    "K06": FAIL,
    "K08": PASS,
    "K09": PASS,
    "S15555": PASS,
    "S15656": PASS,
    "S15653": PASS,
    "SG-CORR": PASS,
    "SG-FWD": PASS,
    "SG-AUTHM": PASS,
    "SG-SPRAY": PASS,
    "SG-DEVCODE": FIELD_MISSING,
}


@pytest.fixture(scope="module")
def outcomes():
    return {o.rule: o for o in harness.run_all()}


def test_every_rule_has_a_recorded_status(outcomes):
    assert set(outcomes) == set(EXPECTED_STATUS) == {r.id for r in REGISTRY}


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_STATUS))
def test_status_is_unchanged(outcomes, rule_id):
    assert outcomes[rule_id].status == EXPECTED_STATUS[rule_id], outcomes[rule_id]


def test_k06_false_positive_is_the_disabled_delete_action(outcomes):
    assert outcomes["K06"].unexpected == ["kai"]
    assert outcomes["K06"].missed == []


def test_results_file_matches_a_fresh_run(outcomes):
    recorded = json.loads((ROOT / "results" / "results.json").read_text(encoding="utf-8"))
    fresh = json.loads(harness.to_json(list(outcomes.values())))
    key = lambda o: o["rule"]  # noqa: E731
    assert sorted(recorded, key=key) == sorted(fresh, key=key)


def test_vendored_rule_files_match_recorded_hashes():
    recorded = json.loads((RULES / "PROVENANCE.json").read_text(encoding="utf-8"))
    for rel, info in recorded.items():
        digest = hashlib.sha256((RULES / rel).read_bytes()).hexdigest()
        assert digest == info["sha256"], rel


# --- mutation checks -------------------------------------------------------
# Each mutation weakens one piece of a rule's logic. If the matching control user
# then shows up, that control case really exercises that logic.
MUTATIONS = [
    ("K03a", "let denial_threshold = 3;", "let denial_threshold = 1;", "bob"),
    ("K08", "let window = 24h;", "let window = 4d;", "pia"),
    ("S15555", "let gracePeriod = 15m;", "let gracePeriod = 0m;", "ugo"),
    ("S15555", "| where isnull(ReEnabledTime) or TimeGenerated < ReEnabledTime\n", "", "vera"),
    ("S15656", "let gracePeriod = 90m;", "let gracePeriod = 0m;", "zane"),
    ("S15656", "| join kind=inner PreResetIps on UserId, ResetTime, IPAddress\n", "", "yuri"),
    ("S15653", "let gracePeriod = 90m;", "let gracePeriod = 0m;", "zane"),
    ("S15653", "| join kind=inner PreRevocationIps on UserId, RevokedTime, IPAddress\n", "", "yuri"),
    ("K09", '| where AuthenticationProtocol =~ "deviceCode"\n', "", "fern"),
]


@pytest.mark.parametrize(("rule_id", "old", "new", "control"), MUTATIONS)
def test_mutation_exposes_control_user(rule_id, old, new, control, scenarios):
    rule = next(r for r in REGISTRY if r.id == rule_id)
    mutated = type(rule)(
        **{
            **{
                f: getattr(rule, f)
                for f in (
                    "id",
                    "kind",
                    "files",
                    "scenario",
                    "owner",
                    "source",
                    "fire",
                    "no_fire",
                    "observe",
                    "notes",
                )
            },
            "adapt": rule.adapt + ((old, new),),
        }
    )
    outcome = harness.run_rule(mutated, scenarios)
    assert outcome.status == FAIL, outcome
    assert control in outcome.unexpected


def test_sigma_correlation_window_mutation_exposes_pia(tmp_path, scenarios):
    rule = next(r for r in REGISTRY if r.id == "SG-CORR")
    paths = []
    for p in rule.paths:
        text = p.read_text(encoding="utf-8")
        if p.name.startswith("correlation_"):
            assert "timespan: 24h" in text
            text = text.replace("timespan: 24h", "timespan: 4d")
        dest = tmp_path / p.name
        dest.write_text(text, encoding="utf-8")
        paths.append(dest)
    from dth import sigma

    rows, _ = sigma.run(paths, scenarios[rule.scenario].rows)
    assert "pia" in harness.users_in(rows)


def test_wade_is_found_by_object_id_not_upn(scenarios):
    rows = scenarios["signin_after_disable"].rows
    wade = [r for r in rows["SigninLogs"] if r["UserPrincipalName"].startswith("wade")]
    assert wade and wade[0]["UserPrincipalName"] == "wade.renamed@lab.example"
