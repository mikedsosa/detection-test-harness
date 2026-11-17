"""Command line entry point: ``dth run`` and ``dth scenarios``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dth import __version__
from dth.harness import PASS, run_all, to_json
from dth.report import markdown
from dth.scenarios import NOW, build_all


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dth", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="replay every scenario against every registered rule")
    run.add_argument("--out", type=Path, help="directory for RESULTS.md and results.json")
    run.add_argument("--strict", action="store_true", help="exit 1 unless every rule passes")
    sub.add_parser("scenarios", help="list the synthetic scenarios and their users")
    args = parser.parse_args(argv)

    if args.command == "scenarios":
        for sc in build_all().values():
            total = sum(len(v) for v in sc.rows.values())
            print(f"{sc.name}: {sc.title} [{sc.attack}] ({total} synthetic rows)")
            for user, role in sc.users.items():
                print(f"    {user}: {role}")
        return 0

    outcomes = run_all()
    header = (
        f"Synthetic data only. Query time fixed at {NOW.isoformat()}. "
        "KQL ran on duckdb-kql (a KQL-to-DuckDB translator), not on the Kusto engine.\n"
    )
    text = markdown(outcomes, header=header)
    sys.stdout.write(text)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "RESULTS.md").write_text("# Results\n\n" + text, encoding="utf-8")
        (args.out / "results.json").write_text(to_json(outcomes), encoding="utf-8")
    if args.strict and any(o.status != PASS for o in outcomes):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
