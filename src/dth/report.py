"""Render outcomes as a Markdown table."""

from __future__ import annotations

from dth.harness import Outcome
from dth.rules import REGISTRY


def _cell(items: list[str]) -> str:
    return ", ".join(items) if items else "-"


def markdown(outcomes: list[Outcome], *, header: str = "") -> str:
    rules = {r.id: r for r in REGISTRY}
    lines = [header] if header else []
    lines += [
        "| Rule | Owner | Engine | Scenario | Result | Fired for | Missed | Unexpected | Observed |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for o in outcomes:
        engine = "duckdb-kql" if o.kind == "kql" else "pySigma sqlite"
        lines.append(
            f"| {o.rule} | {o.owner} | {engine} | {o.scenario} | **{o.status}** | "
            f"{_cell(o.hits)} | {_cell(o.missed)} | {_cell(o.unexpected)} | {_cell(o.observed)} |"
        )
    notes = [(o, rules[o.rule]) for o in outcomes if o.detail or rules[o.rule].notes]
    if notes:
        lines += ["", "Notes:", ""]
        for o, r in notes:
            text = " ".join(t.rstrip(".") + "." for t in (o.detail, r.notes) if t)
            lines.append(f"- **{o.rule}**: {text}")
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    lines += ["", f"Totals: {summary} (of {len(outcomes)} rule runs)."]
    return "\n".join(lines) + "\n"
