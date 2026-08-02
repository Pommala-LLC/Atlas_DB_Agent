from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst, SourceRange, StateAccessKind
from ojas_reconciler.db2_behavior.analysis.dataflow import ReachingDefinitionAnalysis
from ojas_reconciler.db2_behavior.analysis.models import (
    CfgEdgeKind,
    ControlFlowGraph,
    EffectCandidate,
    EffectKind,
    EffectObservability,
    SemanticFinding,
    SemanticFindingCode,
    DynamicSqlResolutionStatus,
    DynamicSqlSite,
    DynamicSqlStatementKind,
    DynamicSqlVariant,
)


class DirectEffectAnalyzer:
    """Preliminary Phase 1 direct-effect and handler-state analysis."""

    def analyze(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
        *,
        dynamic_sites: tuple[DynamicSqlSite, ...] = (),
        dynamic_variants: tuple[DynamicSqlVariant, ...] = (),
    ) -> tuple[tuple[EffectCandidate, ...], tuple[SemanticFinding, ...]]:
        by_id = {node.node_id: node for node in ast.nodes}
        out_names = {parameter.name.upper() for parameter in ast.parameters if parameter.mode in {"OUT", "INOUT"}}
        effects: list[EffectCandidate] = []
        findings: list[SemanticFinding] = []
        dynamic_site_by_node = {site.execute_node_ref: site for site in dynamic_sites}
        dynamic_variant_by_id = {variant.variant_id: variant for variant in dynamic_variants}
        loop_descendants: set[str] = set()
        def collect_loop_descendants(ref: str) -> None:
            if ref in loop_descendants:
                return
            loop_descendants.add(ref)
            child = by_id.get(ref)
            if child is not None:
                for nested in child.child_refs:
                    collect_loop_descendants(nested)
        for candidate in ast.nodes:
            if candidate.kind == NodeKind.LOOP_REGION:
                for child_ref in candidate.child_refs:
                    collect_loop_descendants(child_ref)

        returning_cursors = {
            declaration.cursor_name: declaration
            for declaration in ast.returned_cursor_declarations
        }

        reaching = ReachingDefinitionAnalysis(ast, cfg)
        definitions_by_symbol: dict[str, list[tuple[str, str | None]]] = defaultdict(list)
        for site in reaching.all_definition_sites():
            if site.symbol_name in out_names:
                definitions_by_symbol[site.symbol_name].append(
                    (site.source_node_ref, site.expression_text)
                )

        for symbol, definition_sites in definitions_by_symbol.items():
            normal_reaching_refs = set(reaching.definitions_at_normal_exit(symbol))
            exceptional_reaching_refs = set(reaching.definitions_at_exceptional_exit(symbol))
            for ref, expression_text in definition_sites:
                node = by_id[ref]
                if ref in normal_reaching_refs:
                    observability = EffectObservability.ESCAPING_EFFECT
                    exit_refs = (cfg.normal_exit_ref,)
                    code = SemanticFindingCode.OUT_ASSIGNMENT_REACHES_NORMAL_EXIT
                    message = f"Assignment to OUT parameter {symbol} reaches a normal procedure exit."
                elif ref in exceptional_reaching_refs:
                    observability = EffectObservability.INTERMEDIATE_EFFECT
                    exit_refs = (cfg.exceptional_exit_ref,)
                    code = None
                    message = ""
                else:
                    observability = EffectObservability.OVERWRITTEN_OUTPUT_ASSIGNMENT
                    exit_refs = ()
                    code = SemanticFindingCode.OUT_ASSIGNMENT_OVERWRITTEN
                    message = f"Assignment to OUT parameter {symbol} is overwritten or cannot reach a normal exit."
                effects.append(
                    self._effect(
                        kind=EffectKind.OUT_PARAMETER_ASSIGNMENT,
                        node_ref=ref,
                        target=symbol,
                        value_expression=expression_text,
                        observability=observability,
                        reaches_exit_refs=exit_refs,
                    )
                )
                if code is not None:
                    findings.append(
                        self._finding(
                            code,
                            message,
                            (ref,),
                            (node.source_range,),
                            "OUT assignments remain technical effect candidates; no ScenarioSpec is emitted.",
                        )
                    )

        for node in ast.nodes:
            binding = node.assignment_binding
            sequence_match = (
                re.fullmatch(
                    r"NEXT\s+VALUE\s+FOR\s+([A-Za-z_][A-Za-z0-9_.$]*)",
                    binding.expression_text.strip(),
                    flags=re.IGNORECASE,
                )
                if binding is not None
                else None
            )
            if (
                binding is not None
                and binding.target_name.upper() not in out_names
                and node.node_id in loop_descendants
                and re.search(
                    rf"\b{re.escape(binding.target_name)}\b\s*[+\-]",
                    binding.expression_text,
                    flags=re.IGNORECASE,
                )
            ):
                effects.append(
                    self._effect(
                        kind=EffectKind.STATE_ASSIGNMENT,
                        node_ref=node.node_id,
                        target=binding.target_name.upper(),
                        value_expression=binding.expression_text,
                        observability=EffectObservability.INTERMEDIATE_EFFECT,
                    )
                )

            if sequence_match:
                sequence_name = sequence_match.group(1).upper()
                effects.append(
                    self._effect(
                        kind=EffectKind.SEQUENCE_VALUE_ACQUISITION,
                        node_ref=node.node_id,
                        target=sequence_name,
                        value_expression=binding.expression_text,
                        observability=EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                    )
                )
                findings.append(
                    self._finding(
                        SemanticFindingCode.SEQUENCE_ADVANCE_ROLLBACK_SEMANTICS_DIALECT_DEFINED,
                        f"NEXT VALUE FOR {sequence_name} advances external sequence state.",
                        (node.node_id,),
                        (node.source_range,),
                        (
                            "Sequence value acquisition is nondeterministic and its rollback/gap "
                            "semantics require the configured Db2 dialect profile."
                        ),
                    )
                )

            if node.kind == NodeKind.SELECT_INTO:
                final_table = re.search(
                    r'\bFINAL\s+TABLE\s*\(\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_.$"]*)',
                    node.text,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                if final_table:
                    target = final_table.group(1).strip('"').upper()
                    effects.append(
                        self._effect(
                            kind=EffectKind.DML,
                            node_ref=node.node_id,
                            target=target,
                            value_expression="FINAL_TABLE_INSERT_WITH_RETURNED_ROW",
                            observability=EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
                        )
                    )
                    findings.append(
                        self._finding(
                            SemanticFindingCode.FINAL_TABLE_DATA_CHANGE_EFFECT,
                            f"FINAL TABLE wraps an INSERT into {target} and returns the inserted row.",
                            (node.node_id,),
                            (node.source_range,),
                            "The INSERT and generated-value capture must be modeled as one data-change effect bundle.",
                        )
                    )

            if node.kind == NodeKind.OPEN_CURSOR:
                open_match = re.search(r"\bOPEN\s+([A-Za-z_][A-Za-z0-9_$]*)\b", node.text, re.IGNORECASE)
                cursor_name = open_match.group(1).upper() if open_match else None
                if cursor_name in returning_cursors:
                    returned = returning_cursors[cursor_name]
                    effects.append(
                        self._effect(
                            kind=EffectKind.RESULT_SET_RETURN,
                            node_ref=node.node_id,
                            target=cursor_name,
                            value_expression=f"WITH RETURN {returned.return_scope}",
                            observability=EffectObservability.ESCAPING_EFFECT,
                            reaches_exit_refs=(cfg.normal_exit_ref,),
                        )
                    )
                    findings.append(
                        self._finding(
                            SemanticFindingCode.RETURNED_RESULT_SET,
                            (
                                f"Opening cursor {cursor_name} returns a dynamic result set "
                                f"with scope {returned.return_scope}."
                            ),
                            (returned.declaration_node_ref, node.node_id),
                            (returned.source_range, node.source_range),
                            "The returned result set is an externally observable effect and must be composed into the reaching path.",
                        )
                    )

            if node.kind == NodeKind.DML:
                effects.append(
                    self._effect(
                        kind=EffectKind.DML,
                        node_ref=node.node_id,
                        target=self._dml_target(node.text),
                        value_expression=None,
                        observability=EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
                    )
                )
            elif node.kind == NodeKind.CALL:
                effects.append(
                    self._effect(
                        kind=EffectKind.CALL,
                        node_ref=node.node_id,
                        target=self._call_target(node.text),
                        value_expression=None,
                        observability=EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                    )
                )
                findings.append(
                    self._finding(
                        SemanticFindingCode.UNRESOLVED_CALL_EFFECT_BOUNDARY,
                        "CALL target was retained as an unresolved effect boundary.",
                        (node.node_id,),
                        (node.source_range,),
                        "No callee effects were inferred.",
                    )
                )
            elif node.kind in {NodeKind.EXECUTE, NodeKind.EXECUTE_IMMEDIATE}:
                site = dynamic_site_by_node.get(node.node_id)
                if site is None:
                    effects.append(
                        self._effect(
                            kind=EffectKind.DYNAMIC_SQL,
                            node_ref=node.node_id,
                            target=None,
                            value_expression=node.text,
                            observability=EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                        )
                    )
                    findings.append(
                        self._finding(
                            SemanticFindingCode.DYNAMIC_SQL_EFFECT_BOUNDARY,
                            "Dynamic SQL site has no static resolution record.",
                            (node.node_id,),
                            (node.source_range,),
                            "No dynamic DML, call, or query effect was inferred.",
                        )
                    )
                    continue
                variants = [
                    dynamic_variant_by_id[ref]
                    for ref in site.variant_refs
                    if ref in dynamic_variant_by_id
                ]
                dml_variants = [
                    value for value in variants
                    if value.statement_kind in {
                        DynamicSqlStatementKind.INSERT,
                        DynamicSqlStatementKind.UPDATE,
                        DynamicSqlStatementKind.DELETE,
                        DynamicSqlStatementKind.MERGE,
                    }
                ]
                call_variants = [value for value in variants if value.statement_kind == DynamicSqlStatementKind.CALL]
                if dml_variants:
                    targets = tuple(sorted({
                        target
                        for value in dml_variants
                        for target in (self._dml_target(value.template_text),)
                        if target
                    }))
                    effects.append(
                        self._effect(
                            kind=EffectKind.DYNAMIC_SQL,
                            node_ref=node.node_id,
                            target=",".join(targets) or None,
                            value_expression=site.site_id,
                            observability=EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
                        )
                    )
                elif call_variants:
                    targets = tuple(sorted({value.call_target for value in call_variants if value.call_target}))
                    effects.append(
                        self._effect(
                            kind=EffectKind.DYNAMIC_SQL,
                            node_ref=node.node_id,
                            target=",".join(targets) or None,
                            value_expression=site.site_id,
                            observability=EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                        )
                    )
                elif site.resolution_status in {
                    DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED,
                    DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL,
                    DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED,
                }:
                    effects.append(
                        self._effect(
                            kind=EffectKind.DYNAMIC_SQL,
                            node_ref=node.node_id,
                            target=None,
                            value_expression=site.site_id,
                            observability=EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                        )
                    )
                    findings.append(
                        self._finding(
                            SemanticFindingCode.DYNAMIC_SQL_EFFECT_BOUNDARY,
                            f"Dynamic SQL remains unresolved at status {site.resolution_status.value}.",
                            site.evidence_refs,
                            tuple(by_id[ref].source_range for ref in site.evidence_refs if ref in by_id),
                            "No dynamic DML, call, or query effect was inferred.",
                        )
                    )
            elif node.kind == NodeKind.COMMIT:
                effects.append(
                    self._effect(
                        kind=EffectKind.COMMIT,
                        node_ref=node.node_id,
                        target=None,
                        value_expression=None,
                        observability=EffectObservability.COMMITTED_EFFECT,
                    )
                )
            elif node.kind == NodeKind.ROLLBACK:
                effects.append(
                    self._effect(
                        kind=EffectKind.ROLLBACK,
                        node_ref=node.node_id,
                        target=None,
                        value_expression=None,
                        observability=EffectObservability.ROLLED_BACK_EFFECT,
                    )
                )
            elif node.kind == NodeKind.RESIGNAL:
                effects.append(
                    self._effect(
                        kind=EffectKind.RESIGNAL,
                        node_ref=node.node_id,
                        target=None,
                        value_expression=node.text,
                        observability=EffectObservability.UNHANDLED_ESCAPING_CONDITION,
                        reaches_exit_refs=(cfg.exceptional_exit_ref,),
                    )
                )
            elif node.kind == NodeKind.SIGNAL:
                effects.append(
                    self._effect(
                        kind=EffectKind.SIGNAL,
                        node_ref=node.node_id,
                        target=None,
                        value_expression=node.text,
                        observability=EffectObservability.UNHANDLED_ESCAPING_CONDITION,
                        reaches_exit_refs=(cfg.exceptional_exit_ref,),
                    )
                )

        findings.extend(self._handler_state_findings(ast, cfg))
        return (
            tuple(sorted(effects, key=lambda effect: effect.effect_id)),
            tuple(sorted(findings, key=lambda finding: finding.finding_id)),
        )

    def _handler_state_findings(
        self,
        ast: ProcedureAst,
        cfg: ControlFlowGraph,
    ) -> list[SemanticFinding]:
        node_by_id = {node.node_id: node for node in ast.nodes}
        defs_by_node: dict[str, set[str]] = defaultdict(set)
        uses_by_node: dict[str, set[str]] = defaultdict(set)
        for fact in ast.state_access_facts:
            target = defs_by_node if fact.access_kind == StateAccessKind.DEF else uses_by_node
            target[fact.source_node_ref].add(fact.symbol_name)

        findings: list[SemanticFinding] = []
        bindings_by_handler: dict[str, list[str]] = defaultdict(list)
        for binding in cfg.handler_bindings:
            bindings_by_handler[binding.handler_region_ref].append(binding.source_ast_node_ref)

        for handler_ref, source_refs in bindings_by_handler.items():
            handler = node_by_id[handler_ref]
            region = handler.handler_region
            if region is None or region.handler_kind.value != "CONTINUE":
                continue
            assigned_symbols: set[str] = set()
            for assignment_ref in region.state_assignment_refs:
                assigned_symbols.update(defs_by_node.get(assignment_ref, set()))
            if not assigned_symbols or len(source_refs) < 2:
                continue
            use_refs = tuple(
                sorted(
                    {
                        node_ref
                        for node_ref, symbols in uses_by_node.items()
                        if symbols & assigned_symbols
                    },
                    key=lambda ref: node_by_id[ref].source_range.start_offset,
                )
            )
            if use_refs:
                evidence_refs = tuple([handler_ref, *sorted(source_refs), *use_refs])
                ranges = tuple(node_by_id[ref].source_range for ref in evidence_refs)
                findings.append(
                    self._finding(
                        SemanticFindingCode.SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE,
                        (
                            f"CONTINUE handler writes {sorted(assigned_symbols)} and is shared by "
                            f"{len(source_refs)} possible condition sources before later state uses."
                        ),
                        evidence_refs,
                        ranges,
                        "State may carry across unrelated SQL statements; manual review is required.",
                    )
                )

            loop_nodes = [node for node in ast.nodes if node.kind == NodeKind.LOOP_REGION and node.loop_region is not None]
            for loop in loop_nodes:
                loop_start = loop.source_range.start_offset
                loop_descendants = self._descendants(loop.node_id, node_by_id)
                fetches = [
                    node_by_id[ref]
                    for ref in loop_descendants
                    if node_by_id[ref].kind == NodeKind.FETCH_CURSOR
                ]
                uses_in_loop = [
                    node_by_id[ref]
                    for ref in loop_descendants
                    if uses_by_node.get(ref, set()) & assigned_symbols
                ]
                if not fetches or not uses_in_loop:
                    continue
                prior_sources = [
                    node_by_id[ref]
                    for ref in source_refs
                    if node_by_id[ref].source_range.end_offset < loop_start
                ]
                if not prior_sources:
                    continue
                for symbol in assigned_symbols:
                    latest_source = max(prior_sources, key=lambda node: node.source_range.end_offset)
                    reset_between = any(
                        symbol in defs_by_node.get(node.node_id, set())
                        and latest_source.source_range.end_offset < node.source_range.start_offset < loop_start
                        and node.node_id not in region.state_assignment_refs
                        for node in ast.nodes
                    )
                    if reset_between:
                        continue
                    first_fetch = min(fetches, key=lambda node: node.source_range.start_offset)
                    first_use = min(uses_in_loop, key=lambda node: node.source_range.start_offset)
                    if first_use.source_range.start_offset >= first_fetch.source_range.start_offset:
                        evidence_refs = (handler_ref, latest_source.node_id, loop.node_id, first_fetch.node_id, first_use.node_id)
                        findings.append(
                            self._finding(
                                SemanticFindingCode.STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE,
                                (
                                    f"{symbol} may be set by a pre-loop NOT FOUND source and consumed "
                                    "after the first cursor FETCH without an intervening reset."
                                ),
                                evidence_refs,
                                tuple(node_by_id[ref].source_range for ref in evidence_refs),
                                "The first successfully fetched row may be skipped or the loop may exit early.",
                            )
                        )
        return findings

    def _descendants(self, root_ref: str, node_by_id: dict[str, object]) -> set[str]:
        result: set[str] = set()
        stack = [root_ref]
        while stack:
            current = stack.pop()
            node = node_by_id[current]
            child_refs = getattr(node, "child_refs")
            for child in child_refs:
                if child not in result:
                    result.add(child)
                    stack.append(child)
        return result

    def _effect(
        self,
        *,
        kind: EffectKind,
        node_ref: str,
        target: str | None,
        value_expression: str | None,
        observability: EffectObservability,
        reaches_exit_refs: tuple[str, ...] = (),
    ) -> EffectCandidate:
        payload = f"{kind.value}|{node_ref}|{target or ''}|{value_expression or ''}|{observability.value}"
        return EffectCandidate(
            effect_id="effect-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            effect_kind=kind,
            source_node_ref=node_ref,
            target=target,
            value_expression=value_expression,
            observability=observability,
            reaches_exit_refs=reaches_exit_refs,
            evidence_refs=(node_ref,),
        )

    def _finding(
        self,
        code: SemanticFindingCode,
        message: str,
        evidence_refs: tuple[str, ...],
        source_ranges: tuple[SourceRange, ...],
        consequence: str,
    ) -> SemanticFinding:
        payload = f"{code.value}|{'|'.join(evidence_refs)}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=evidence_refs,
            source_ranges=source_ranges,
            consequence=consequence,
        )

    @staticmethod
    def _dml_target(text: str) -> str | None:
        normalized = " ".join(text.strip().split())
        patterns = [
            r"^UPDATE\s+([\w.\"]+)",
            r"^INSERT\s+INTO\s+([\w.\"]+)",
            r"^DELETE\s+FROM\s+([\w.\"]+)",
            r"^MERGE\s+INTO\s+([\w.\"]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, normalized, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip('"').upper()
        return None

    @staticmethod
    def _call_target(text: str) -> str | None:
        match = re.search(r"\bCALL\s+([\w.\"]+)", text, flags=re.IGNORECASE)
        return match.group(1).strip('"').upper() if match else None
