"""Command line interface.

    python -m sentinel.cli scope-check   examples/scope-local.json
    python -m sentinel.cli assess        --scope examples/scope-local.json --mode local --out evidence
    python -m sentinel.cli verify-audit  evidence/audit-*.jsonl
    python -m sentinel.cli capabilities
    python -m sentinel.cli self-check    --out evidence
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from . import __version__
from .audit import verify_chain
from .engine import coverage_table, run
from .errors import SentinelError
from .model import Severity
from .report import write_reports
from .scope import Scope


def _cmd_scope_check(args: argparse.Namespace) -> int:
    scope = Scope.from_file(args.file)
    print(json.dumps(scope.summary(), indent=2, ensure_ascii=False))
    return 0


def _cmd_assess(args: argparse.Namespace) -> int:
    result = run(args.scope, args.mode, args.out, run_id=args.run_id)
    a = result.assessment
    paths = write_reports(a, args.out)

    counts = a.counts_by_severity()
    print(f"Engagement : {a.engagement_id} (run {a.run_id})")
    print(f"Modo       : {a.target_mode}")
    print(f"Activos    : {len(a.assets)}   Hallazgos: {len(a.findings)}")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.NONE):
        if counts.get(sev.value):
            print(f"  {sev.value:<9} {counts[sev.value]}")
    print("")
    for finding in a.sorted_findings()[: args.top]:
        score = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "  -"
        print(f"  [{finding.severity.value.upper():<8}] {score:>4}  {finding.title}")
        print(f"             {finding.asset}" + (f":{finding.port}" if finding.port else "")
              + f"  · {finding.confidence.value}/{finding.validation_state.value}")
    print("")
    print(f"Informe    : {paths['markdown']}")
    print(f"HTML       : {paths['html']}")
    print(f"JSON       : {paths['json']}")
    chain = a.audit_chain or {}
    print(f"Auditoría  : {a.audit_path} ({'consistente internamente' if chain.get('ok') else 'FALLIDA'}, "
          f"{chain.get('records')} registros)")
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    result = verify_chain(args.file)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 2


def _cmd_capabilities(args: argparse.Namespace) -> int:
    print(f"sentinel {__version__} — matriz de capacidades")
    print("")
    print("| ID    | Capacidad                                                        | Estado     |")
    print("|-------|------------------------------------------------------------------|------------|")
    for cap in coverage_table("local"):
        print(f"| {cap.id:<5} | {cap.name[:64]:<64} | {cap.status:<10} |")
        print(f"|       | código: {cap.code_ref[:64]:<64} |            |")
    print("")
    print("'partial' significa que solo se implementó el análisis, sin validación activa.")
    print("'blocked' significa que hay un control explícito que impide la capacidad.")
    return 0


def _cmd_self_check(args: argparse.Namespace) -> int:
    from .selfcheck import render, run_control_checks, run_pipeline_checks

    results = run_control_checks() + run_pipeline_checks()
    report = render(results)
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, "selfcheck.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    print(report)
    print("")
    print(f"Informe de self-check: {path}")
    return 0 if all(r.passed for r in results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=("Agente de evaluación de seguridad con controles de alcance, tier y auditoría. "
                     "Solo detección y validación no destructiva."),
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scope-check", help="valida un archivo de alcance y muestra el resumen")
    p.add_argument("file")
    p.set_defaults(func=_cmd_scope_check)

    p = sub.add_parser("assess", help="ejecuta una evaluación y genera informes")
    p.add_argument("--scope", required=True)
    p.add_argument("--mode", choices=["local", "network"], default="local")
    p.add_argument("--out", default="evidence")
    p.add_argument("--run-id", default=None)
    p.add_argument("--top", type=int, default=15)
    p.set_defaults(func=_cmd_assess)

    p = sub.add_parser("verify-audit", help="comprueba la consistencia interna (no autoría ni completitud) de una cadena")
    p.add_argument("file")
    p.set_defaults(func=_cmd_verify_audit)

    p = sub.add_parser("capabilities", help="muestra la matriz de capacidades")
    p.set_defaults(func=_cmd_capabilities)

    p = sub.add_parser("self-check", help="ejercita los controles y el pipeline completo")
    p.add_argument("--out", default="evidence")
    p.set_defaults(func=_cmd_self_check)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SentinelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
