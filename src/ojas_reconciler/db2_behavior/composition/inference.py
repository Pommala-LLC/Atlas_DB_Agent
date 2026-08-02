from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from ..commercial.models import CompositionKind, CompositionTransactionRelationship, ParameterMapping
from ..core.canonical_json import canonical_digest
from .models import CompositionCandidateBatch, CompositionCandidateStatus, ProcedureCompositionCandidate


class CompositionInferenceError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifacts(run_dir: Path) -> tuple[Path, Path]:
    parse_candidates = [run_dir / "extraction" / "02-parse.json", run_dir / "02-parse.json"]
    semantic_candidates = [
        run_dir / "extraction" / "03-semantic-phase2-4.json",
        run_dir / "03-semantic-phase2-4.json",
        run_dir / "03-semantic.json",
    ]
    parse = next((value for value in parse_candidates if value.is_file()), None)
    semantic = next((value for value in semantic_candidates if value.is_file()), None)
    if parse is None or semantic is None:
        raise CompositionInferenceError(f"Run lacks parse/semantic artifacts: {run_dir}")
    return parse, semantic


def _split_call_arguments(text: str) -> tuple[str, tuple[str, ...]]:
    upper = text.upper().strip()
    if not upper.startswith("CALL "):
        return "", ()
    body = text.strip()[5:].strip()
    open_at = body.find("(")
    if open_at < 0:
        return body.strip().upper(), ()
    target = body[:open_at].strip().upper()
    close_at = body.rfind(")")
    if close_at < open_at:
        return target, ()
    raw = body[open_at + 1 : close_at]
    values: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(raw):
        ch = raw[i]
        nxt = raw[i + 1] if i + 1 < len(raw) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            values.append(raw[start:i].strip())
            start = i + 1
        i += 1
    if raw[start:].strip():
        values.append(raw[start:].strip())
    return target, tuple(values)


class DirectCallCompositionInferenceService:
    """Infer non-authoritative composition candidates from direct CALL effects."""

    def infer(self, run_dirs: Iterable[Path]) -> CompositionCandidateBatch:
        runs: list[dict[str, Any]] = []
        by_procedure: dict[str, list[dict[str, Any]]] = {}
        for run_dir in (Path(value).resolve() for value in run_dirs):
            parse_path, semantic_path = _artifacts(run_dir)
            parsed = _load(parse_path)
            semantic = _load(semantic_path)
            ast = parsed.get("ast") or {}
            procedure_ref = ".".join(
                value for value in [str(ast.get("schema_name") or ""), str(ast.get("procedure_name") or "")] if value
            ).upper()
            record = {
                "run_dir": run_dir,
                "parse_path": parse_path,
                "semantic_path": semantic_path,
                "parse": parsed,
                "semantic": semantic,
                "procedure_ref": procedure_ref,
                "semantic_digest": str(semantic.get("content_digest") or canonical_digest(semantic)),
                "parameters": tuple(ast.get("parameters", [])),
                "nodes": {str(item.get("node_id")): item for item in ast.get("nodes", [])},
            }
            runs.append(record)
            by_procedure.setdefault(procedure_ref, []).append(record)

        candidates: list[ProcedureCompositionCandidate] = []
        for upstream in runs:
            for effect in upstream["semantic"].get("effects", []):
                if str(effect.get("effect_kind")) != "CALL":
                    continue
                target = str(effect.get("target") or "").upper()
                node_ref = str(effect.get("source_node_ref") or "")
                node = upstream["nodes"].get(node_ref) or {}
                invocation_text = str(node.get("text") or f"CALL {target}")
                parsed_target, arguments = _split_call_arguments(invocation_text)
                target = parsed_target or target
                matches = by_procedure.get(target, [])
                blockers: list[str] = []
                downstream_digest: str | None = None
                mappings: list[ParameterMapping] = []
                if len(matches) == 1:
                    downstream = matches[0]
                    downstream_digest = downstream["semantic_digest"]
                    status = CompositionCandidateStatus.SOURCE_CALL_RESOLVED
                    parameters = downstream["parameters"]
                    for index, argument in enumerate(arguments):
                        parameter_name = (
                            str(parameters[index].get("name") or parameters[index].get("parameter_name") or f"ARG_{index+1}")
                            if index < len(parameters)
                            else f"ARG_{index+1}"
                        )
                        mappings.append(
                            ParameterMapping(
                                upstream_ref=argument,
                                downstream_ref=parameter_name,
                                mapping_expression=argument,
                                evidence_refs=(node_ref,),
                            )
                        )
                    if len(arguments) != len(parameters):
                        blockers.append("CALL_PARAMETER_ARITY_REQUIRES_REVIEW")
                elif len(matches) > 1:
                    status = CompositionCandidateStatus.TARGET_AMBIGUOUS
                    blockers.append("OVERLOADED_TARGET_REQUIRES_SIGNATURE_RESOLUTION")
                else:
                    status = CompositionCandidateStatus.TARGET_SOURCE_UNAVAILABLE
                    blockers.append("DOWNSTREAM_SOURCE_UNAVAILABLE")
                candidate_id = "composition-candidate-" + hashlib.sha256(
                    (upstream["procedure_ref"] + "|" + target + "|" + node_ref).encode()
                ).hexdigest()[:20]
                candidates.append(
                    ProcedureCompositionCandidate(
                        candidate_id=candidate_id,
                        composition_kind=CompositionKind.DIRECT_CALL,
                        upstream_procedure_ref=upstream["procedure_ref"],
                        downstream_procedure_ref=target,
                        upstream_semantic_digest=upstream["semantic_digest"],
                        downstream_semantic_digest=downstream_digest,
                        invocation_site_ref=node_ref,
                        invocation_text=invocation_text,
                        parameter_mappings=tuple(mappings),
                        transaction_relationship=CompositionTransactionRelationship.SAME_UOW,
                        status=status,
                        blockers=tuple(blockers),
                        evidence_refs=(upstream["parse_path"].as_posix(), upstream["semantic_path"].as_posix(), node_ref),
                    )
                )
        payload = {
            "schema_version": "composition-candidate-batch-1.0",
            "batch_id": "composition-batch-" + hashlib.sha256(
                "|".join(sorted(item["semantic_digest"] for item in runs)).encode()
            ).hexdigest()[:18],
            "candidates": tuple(sorted(candidates, key=lambda item: item.candidate_id)),
        }
        return CompositionCandidateBatch(**payload, content_digest=canonical_digest(payload))
