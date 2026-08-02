"""Lazy CLI dispatcher; command groups are imported only when selected."""
from __future__ import annotations

from importlib import import_module

from .argparse_builder import build_parser
from .dialect_selection import extract_explicit_e2e_dialect

_COMMAND_GROUPS: dict[str, str] = {
    "inventory": "inventory",
    "inventory-dir": "inventory",
    "run-corpus": "inventory",
    "parse-spike": "analysis",
    "parse-db2-script": "analysis",
    "analyze-phase1": "analysis",
    "analyze-phase4": "analysis",
    "compile-scenarios": "analysis",
    "compile-bdd": "analysis",
    "export-authority-requirements": "analysis",
    "validate-authority": "analysis",
    "plan-runtime-verification": "runtime",
    "verify-runtime-scripted": "runtime",
    "verify-runtime-db2": "runtime",
    "governance-init": "governance",
    "governance-admit-scenarios": "governance",
    "governance-admit-bdd": "governance",
    "governance-admit-runtime": "governance",
    "governance-register-baseline": "governance",
    "governance-compare-baseline": "governance",
    "governance-amend-scenario": "governance",
    "governance-bind-decision": "governance",
    "governance-bind-certification": "governance",
    "governance-history": "governance",
    "runtime-evidence-status": "support",
    "run-bdd-test-package": "support",
    "generate": "support",
    "run-end-to-end": "support",
    "doctor": "support",
    "commercial-export-templates": "commercial",
    "commercial-seal-artifact": "commercial",
    "commercial-validate-capabilities": "commercial",
    "commercial-validate-custody": "commercial",
    "commercial-run-organic-validation": "commercial",
    "commercial-run-public-repository-validation": "commercial",
    "commercial-assess-readiness": "commercial",
    "commercial-create-disposition": "commercial",
    "commercial-build-procedure-checks": "commercial",
    "commercial-plan-relational-fixtures": "commercial",
    "commercial-assess-composition": "commercial",
    "commercial-build-knowledge-graph": "commercial",
    "commercial-generate-sbom": "commercial",
    "commercial-build-support-bundle": "commercial",
    "commercial-serve": "commercial",
    "catalog-build-from-ddl": "enterprise",
    "catalog-capture-db2": "enterprise",
    "catalog-resolve-lineage": "enterprise",
    "commercial-compile-executable-fixtures": "enterprise",
    "commercial-infer-composition": "enterprise",
    "commercial-build-decision-model": "enterprise",
    "commercial-evaluate-decision": "enterprise",
    "runtime-reconcile": "enterprise",
    "graph-ingest": "enterprise",
    "graph-search": "enterprise",
    "graph-neighborhood": "enterprise",
    "dialect-registry": "enterprise",
    "dialect-inventory": "enterprise",
    "check-tools": "support",
}


def main(argv: list[str] | None = None) -> int:
    normalized, explicit_dialect = extract_explicit_e2e_dialect(argv)
    args = build_parser().parse_args(normalized)
    if explicit_dialect is not None:
        args.dialect = explicit_dialect
    group = _COMMAND_GROUPS.get(args.command)
    if group is None:
        raise RuntimeError(f"No command handler registered for {args.command!r}.")
    module = import_module(f"{__package__}.commands.{group}")
    result = module.handle(args)
    if result is None:
        raise RuntimeError(f"Command group {group!r} did not handle {args.command!r}.")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
