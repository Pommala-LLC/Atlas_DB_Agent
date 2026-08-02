from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from itertools import product

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token, TokenKind
from ojas_reconciler.db2_behavior.parsing.models import AstNode, NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.query_summaries import QuerySourceSummaryBuilder
from ojas_reconciler.db2_behavior.analysis.models import (
    ControlFlowGraph,
    DynamicCallResolution,
    DynamicIdentifierResolutionStatus,
    DynamicQueryOutputBinding,
    DynamicRelationResolution,
    DynamicResolutionCatalog,
    DynamicObjectVerificationStatus,
    DynamicSqlResolutionStatus,
    DynamicSqlSite,
    DynamicSqlStatementKind,
    DynamicSqlVariant,
    QueryBindingFact,
    QueryBindingKind,
    QuerySourceSummary,
    QuerySummaryKind,
    RuntimeCaptureContract,
    SemanticFinding,
    SemanticFindingCode,
)


@dataclass(frozen=True, slots=True)
class _ValueVariant:
    text: str
    placeholders: frozenset[str]
    source_refs: frozenset[str]


@dataclass(frozen=True, slots=True)
class _FlowState:
    variable_defs: dict[str, frozenset[str]]
    prepared_defs: dict[str, frozenset[str]]


@dataclass(frozen=True, slots=True)
class DynamicSqlAnalysis:
    variants: tuple[DynamicSqlVariant, ...]
    sites: tuple[DynamicSqlSite, ...]
    query_summaries: tuple[QuerySourceSummary, ...]
    query_bindings: tuple[QueryBindingFact, ...]
    dynamic_query_bindings: tuple[DynamicQueryOutputBinding, ...]
    relation_resolutions: tuple[DynamicRelationResolution, ...]
    call_resolutions: tuple[DynamicCallResolution, ...]
    runtime_capture_contracts: tuple[RuntimeCaptureContract, ...]
    findings: tuple[SemanticFinding, ...]


class DynamicSqlAnalyzer:
    """Bounded, control-flow-sensitive static reconstruction of DB2 dynamic SQL.

    It never executes SQL. Runtime capture is represented only as a deferred contract.
    """

    MAX_VARIANTS = 10
    MAX_EVAL_DEPTH = 12

    def __init__(self, catalog: DynamicResolutionCatalog | None = None) -> None:
        self._scanner = Db2LexicalScanner()
        self._query_builder = QuerySourceSummaryBuilder()
        self._catalog = catalog
        self._catalog_relations = {name.upper() for name in catalog.relation_names} if catalog is not None else set()
        self._catalog_routines = {name.upper() for name in catalog.routine_names} if catalog is not None else set()

    def analyze(self, ast: ProcedureAst, cfg: ControlFlowGraph) -> DynamicSqlAnalysis:
        self._ast = ast
        self._cfg = cfg
        self._node_by_id = {node.node_id: node for node in ast.nodes}
        self._cfg_by_ast = {
            node.ast_node_ref: node.cfg_node_id
            for node in cfg.nodes
            if node.ast_node_ref is not None
        }
        self._incoming = self._build_reaching_definitions()

        variants_by_id: dict[str, DynamicSqlVariant] = {}
        sites: list[DynamicSqlSite] = []
        query_summaries: list[QuerySourceSummary] = []
        query_bindings: list[QueryBindingFact] = []
        dynamic_query_bindings: list[DynamicQueryOutputBinding] = []
        relation_resolutions: list[DynamicRelationResolution] = []
        call_resolutions: list[DynamicCallResolution] = []
        captures: list[RuntimeCaptureContract] = []
        findings: list[SemanticFinding] = []

        for node in sorted(ast.nodes, key=lambda item: item.source_range.start_offset):
            if node.kind not in {NodeKind.EXECUTE, NodeKind.EXECUTE_IMMEDIATE}:
                continue
            binding = node.dynamic_execute_binding
            if binding is None:
                site, site_findings, capture = self._unresolved_site(node, "EXECUTE binding was not parsed.")
                sites.append(site)
                findings.extend(site_findings)
                captures.append(capture)
                continue

            values, budget_exceeded = self._values_for_execute(node)
            dynamic_variants = self._build_variants(node, values)
            for variant in dynamic_variants:
                variants_by_id[variant.variant_id] = variant

            status = self._resolution_status(dynamic_variants, budget_exceeded)
            site_id = self._stable_id("dynamic-site", node.node_id, *(variant.variant_id for variant in dynamic_variants))
            relation_status, site_relations = self._relation_resolutions(node, site_id, dynamic_variants)
            call_status, site_calls = self._call_resolutions(node, site_id, dynamic_variants)
            if (
                status == DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED
                and (
                    relation_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
                    or call_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
                )
            ):
                status = DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED
            relation_resolutions.extend(site_relations)
            call_resolutions.extend(site_calls)
            completeness = "COMPLETE" if status in {
                DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED,
                DynamicSqlResolutionStatus.ENUMERABLE_VARIANTS,
                DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED,
            } else "PARTIAL"
            statement_kinds = tuple(sorted({variant.statement_kind for variant in dynamic_variants}, key=lambda value: value.value))
            evidence_refs = tuple(sorted({node.node_id, *(ref for value in values for ref in value.source_refs)}))
            site = DynamicSqlSite(
                site_id=site_id,
                execute_node_ref=node.node_id,
                execution_kind=binding.execution_kind,
                prepared_statement_name=binding.statement_name,
                source_expression=binding.source_expression,
                resolution_status=status,
                variant_refs=tuple(variant.variant_id for variant in dynamic_variants),
                into_target_names=binding.into_target_names,
                using_expressions=binding.using_expressions,
                statement_kinds=statement_kinds,
                relation_resolution_status=relation_status,
                call_resolution_status=call_status,
                analysis_completeness=completeness,
                evidence_refs=evidence_refs,
            )
            sites.append(site)
            findings.extend(self._site_findings(node, site))

            if status in {
                DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED,
                DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED,
                DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL,
                DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED,
            }:
                captures.append(self._capture_contract(site, node))

            summaries, bindings, dynamic_bindings, binding_findings = self._dynamic_query_outputs(
                node,
                site,
                dynamic_variants,
            )
            query_summaries.extend(summaries)
            query_bindings.extend(bindings)
            dynamic_query_bindings.extend(dynamic_bindings)
            findings.extend(binding_findings)

        return DynamicSqlAnalysis(
            variants=tuple(sorted(variants_by_id.values(), key=lambda item: item.variant_id)),
            sites=tuple(sorted(sites, key=lambda item: item.site_id)),
            query_summaries=tuple(sorted(query_summaries, key=lambda item: item.query_summary_id)),
            query_bindings=tuple(sorted(query_bindings, key=lambda item: item.binding_id)),
            dynamic_query_bindings=tuple(sorted(dynamic_query_bindings, key=lambda item: item.binding_id)),
            relation_resolutions=tuple(sorted(relation_resolutions, key=lambda item: item.resolution_id)),
            call_resolutions=tuple(sorted(call_resolutions, key=lambda item: item.resolution_id)),
            runtime_capture_contracts=tuple(sorted(captures, key=lambda item: item.capture_contract_id)),
            findings=tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    def _build_reaching_definitions(self) -> dict[str, _FlowState]:
        ast_by_cfg = {
            node.cfg_node_id: node.ast_node_ref
            for node in self._cfg.nodes
            if node.ast_node_ref is not None
        }
        predecessors: dict[str, set[str]] = defaultdict(set)
        successors: dict[str, set[str]] = defaultdict(set)
        for edge in self._cfg.edges:
            predecessors[edge.target_ref].add(edge.source_ref)
            successors[edge.source_ref].add(edge.target_ref)

        initial_variables: dict[str, frozenset[str]] = {}
        for node in self._ast.nodes:
            if node.kind != NodeKind.DECLARE_VARIABLE:
                continue
            name, expression = self._declaration_default(node)
            if name is not None and expression is not None:
                initial_variables[name] = frozenset({node.node_id})

        incoming: dict[str, _FlowState] = {
            self._cfg.entry_ref: _FlowState(initial_variables, {})
        }
        outgoing: dict[str, _FlowState] = {}
        work = deque([self._cfg.entry_ref])
        queued = {self._cfg.entry_ref}
        while work:
            cfg_ref = work.popleft()
            queued.discard(cfg_ref)
            state = incoming.get(cfg_ref, _FlowState({}, {}))
            variables = dict(state.variable_defs)
            prepared = dict(state.prepared_defs)
            ast_ref = ast_by_cfg.get(cfg_ref)
            if ast_ref is not None:
                node = self._node_by_id[ast_ref]
                if node.assignment_binding is not None:
                    variables[node.assignment_binding.target_name] = frozenset({ast_ref})
                if node.dynamic_prepare_binding is not None:
                    prepared[node.dynamic_prepare_binding.statement_name] = frozenset({ast_ref})
            out_state = _FlowState(variables, prepared)
            if out_state == outgoing.get(cfg_ref):
                continue
            outgoing[cfg_ref] = out_state
            for target in successors.get(cfg_ref, set()):
                merged_vars: dict[str, frozenset[str]] = {}
                merged_prepared: dict[str, frozenset[str]] = {}
                for predecessor in predecessors[target]:
                    pred_state = outgoing.get(predecessor)
                    if pred_state is None:
                        continue
                    for symbol, refs in pred_state.variable_defs.items():
                        merged_vars[symbol] = merged_vars.get(symbol, frozenset()) | refs
                    for name, refs in pred_state.prepared_defs.items():
                        merged_prepared[name] = merged_prepared.get(name, frozenset()) | refs
                merged = _FlowState(merged_vars, merged_prepared)
                if merged != incoming.get(target):
                    incoming[target] = merged
                    if target not in queued:
                        work.append(target)
                        queued.add(target)
        return {
            ast_ref: incoming.get(cfg_ref, _FlowState({}, {}))
            for ast_ref, cfg_ref in self._cfg_by_ast.items()
        }

    def _values_for_execute(self, node: AstNode) -> tuple[tuple[_ValueVariant, ...], bool]:
        binding = node.dynamic_execute_binding
        assert binding is not None
        if binding.execution_kind == "IMMEDIATE":
            assert binding.source_expression is not None
            return self._eval_expression(binding.source_expression, node.node_id, 0, frozenset())
        state = self._incoming.get(node.node_id, _FlowState({}, {}))
        prepare_refs = state.prepared_defs.get(binding.statement_name or "", frozenset())
        values: list[_ValueVariant] = []
        exceeded = False
        for prepare_ref in sorted(prepare_refs):
            prepare_node = self._node_by_id[prepare_ref]
            prepare_binding = prepare_node.dynamic_prepare_binding
            if prepare_binding is None:
                continue
            resolved, local_exceeded = self._eval_expression(
                prepare_binding.source_expression,
                prepare_ref,
                0,
                frozenset(),
            )
            values.extend(resolved)
            exceeded = exceeded or local_exceeded
        return self._dedupe_values(values), exceeded

    def _eval_expression(
        self,
        expression: str,
        at_node_ref: str,
        depth: int,
        visited: frozenset[tuple[str, str]],
    ) -> tuple[tuple[_ValueVariant, ...], bool]:
        if depth >= self.MAX_EVAL_DEPTH:
            name = f"EXPR_{hashlib.sha256(expression.encode('utf-8')).hexdigest()[:8]}"
            return (_ValueVariant(f"${{{name}}}", frozenset({name}), frozenset()),), False
        tokens = list(self._scanner.scan(expression).tokens)
        groups = self._split_concat(tokens)
        if not groups:
            return (), False
        alternatives: list[tuple[_ValueVariant, ...]] = []
        exceeded = False
        for group in groups:
            values, local_exceeded = self._eval_atom(group, at_node_ref, depth, visited)
            alternatives.append(values)
            exceeded = exceeded or local_exceeded
        if any(not values for values in alternatives):
            return (), exceeded
        product_count = 1
        for values in alternatives:
            product_count *= len(values)
        if product_count > self.MAX_VARIANTS:
            exceeded = True
        result: list[_ValueVariant] = []
        for combination in product(*alternatives):
            text = "".join(value.text for value in combination)
            placeholders = frozenset().union(*(value.placeholders for value in combination))
            refs = frozenset().union(*(value.source_refs for value in combination))
            result.append(_ValueVariant(text, placeholders, refs))
            if len(result) >= self.MAX_VARIANTS:
                break
        return self._dedupe_values(result), exceeded

    def _eval_atom(
        self,
        tokens: list[Token],
        at_node_ref: str,
        depth: int,
        visited: frozenset[tuple[str, str]],
    ) -> tuple[tuple[_ValueVariant, ...], bool]:
        tokens = self._strip_outer_parentheses(tokens)
        if len(tokens) == 1:
            token = tokens[0]
            if token.kind == TokenKind.STRING:
                return (_ValueVariant(self._decode_string(token.value), frozenset(), frozenset()),), False
            if token.kind == TokenKind.NUMBER:
                return (_ValueVariant(token.value, frozenset(), frozenset()),), False
            if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
                symbol = token.value.strip('"').upper()
                state = self._incoming.get(at_node_ref, _FlowState({}, {}))
                refs = state.variable_defs.get(symbol, frozenset())
                key = (at_node_ref, symbol)
                if refs and key not in visited:
                    values: list[_ValueVariant] = []
                    exceeded = False
                    for ref in sorted(refs):
                        definition = self._node_by_id[ref]
                        expression = self._definition_expression(definition)
                        if expression is None:
                            continue
                        nested, local_exceeded = self._eval_expression(
                            expression,
                            ref,
                            depth + 1,
                            visited | {key},
                        )
                        values.extend(
                            _ValueVariant(value.text, value.placeholders, value.source_refs | {ref})
                            for value in nested
                        )
                        exceeded = exceeded or local_exceeded
                    if values:
                        return self._dedupe_values(values), exceeded
                return (_ValueVariant(f"${{{symbol}}}", frozenset({symbol}), frozenset()),), False
        rendered = self._render_tokens(tokens)
        placeholder = f"EXPR_{hashlib.sha256(rendered.encode('utf-8')).hexdigest()[:8]}"
        return (_ValueVariant(f"${{{placeholder}}}", frozenset({placeholder}), frozenset()),), False

    def _build_variants(self, node: AstNode, values: tuple[_ValueVariant, ...]) -> tuple[DynamicSqlVariant, ...]:
        result: list[DynamicSqlVariant] = []
        for value in values:
            sql_text = value.text.strip()
            kind = self._statement_kind(sql_text)
            relations, _ = self._extract_relations(sql_text, kind)
            call_target = self._extract_call_target(sql_text) if kind == DynamicSqlStatementKind.CALL else None
            without_digest = {
                "template_text": sql_text,
                "concrete_sql": sql_text if not value.placeholders else None,
                "placeholder_names": tuple(sorted(value.placeholders)),
                "statement_kind": kind,
                "relation_refs": relations,
                "call_target": call_target,
                "source_definition_refs": tuple(sorted(value.source_refs)),
                "analysis_completeness": "COMPLETE" if kind != DynamicSqlStatementKind.UNKNOWN else "PARTIAL",
            }
            digest = canonical_digest(without_digest)
            result.append(
                DynamicSqlVariant(
                    variant_id="dynamic-variant-" + digest.removeprefix("sha256:")[:20],
                    **without_digest,
                    content_digest=digest,
                )
            )
        return tuple(sorted({value.variant_id: value for value in result}.values(), key=lambda item: item.variant_id))

    def _resolution_status(
        self,
        variants: tuple[DynamicSqlVariant, ...],
        budget_exceeded: bool,
    ) -> DynamicSqlResolutionStatus:
        if budget_exceeded:
            return DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED
        if not variants:
            return DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL
        if all(value.statement_kind != DynamicSqlStatementKind.UNKNOWN for value in variants):
            if all(not value.placeholder_names for value in variants):
                return (
                    DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED
                    if len(variants) == 1
                    else DynamicSqlResolutionStatus.ENUMERABLE_VARIANTS
                )
            if all(not self._structure_placeholder(value.template_text) for value in variants):
                return DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED
            return DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED
        return DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED

    def _relation_resolutions(
        self,
        node: AstNode,
        site_id: str,
        variants: tuple[DynamicSqlVariant, ...],
    ) -> tuple[DynamicIdentifierResolutionStatus, tuple[DynamicRelationResolution, ...]]:
        records: list[DynamicRelationResolution] = []
        unresolved = False
        names: dict[tuple[str, str], list[str]] = defaultdict(list)
        for variant in variants:
            _, roles = self._extract_relations(variant.template_text, variant.statement_kind)
            if self._structure_placeholder(variant.template_text) and not variant.relation_refs:
                unresolved = True
            for relation, role in roles:
                if "${" in relation:
                    unresolved = True
                names[(relation, role)].append(variant.variant_id)
        if not names:
            status = DynamicIdentifierResolutionStatus.NOT_APPLICABLE
        elif unresolved:
            status = DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
        elif len(variants) > 1:
            status = DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED
        else:
            status = DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
        for (name, role), refs in sorted(names.items()):
            local_status = (
                DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
                if "${" in name
                else DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED
                if len(variants) > 1
                else DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
            )
            records.append(
                DynamicRelationResolution(
                    resolution_id=self._stable_id("dynamic-relation", node.node_id, name, role),
                    site_ref=site_id,
                    relation_name=name,
                    role=role,
                    status=local_status,
                    verification_status=self._verification_status(name, relation=True),
                    variant_refs=tuple(sorted(refs)),
                )
            )
        return status, tuple(records)

    def _call_resolutions(
        self,
        node: AstNode,
        site_id: str,
        variants: tuple[DynamicSqlVariant, ...],
    ) -> tuple[DynamicIdentifierResolutionStatus, tuple[DynamicCallResolution, ...]]:
        targets: dict[str, list[str]] = defaultdict(list)
        unresolved_targets: dict[str, list[str]] = defaultdict(list)
        for variant in variants:
            if variant.statement_kind != DynamicSqlStatementKind.CALL:
                continue
            if variant.call_target is None:
                unresolved_targets["<UNRESOLVED_CALL_TARGET>"].append(variant.variant_id)
            elif "${" in variant.call_target:
                unresolved_targets[variant.call_target].append(variant.variant_id)
            else:
                targets[variant.call_target].append(variant.variant_id)
        if not targets and not unresolved_targets:
            return DynamicIdentifierResolutionStatus.NOT_APPLICABLE, ()
        status = (
            DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
            if unresolved_targets
            else DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED
            if len(variants) > 1
            else DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
        )
        records: list[DynamicCallResolution] = []
        for target, refs in sorted(targets.items()):
            records.append(
                DynamicCallResolution(
                    resolution_id=self._stable_id("dynamic-call", node.node_id, target),
                    site_ref=site_id,
                    call_target=target,
                    status=(
                        DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED
                        if len(variants) > 1
                        else DynamicIdentifierResolutionStatus.RESOLVED_LITERAL
                    ),
                    verification_status=self._verification_status(target, relation=False),
                    variant_refs=tuple(sorted(refs)),
                )
            )
        for target, refs in sorted(unresolved_targets.items()):
            records.append(
                DynamicCallResolution(
                    resolution_id=self._stable_id("dynamic-call", node.node_id, target),
                    site_ref=site_id,
                    call_target=target,
                    status=DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER,
                    verification_status=DynamicObjectVerificationStatus.NOT_VERIFIED,
                    variant_refs=tuple(sorted(refs)),
                )
            )
        return status, tuple(records)

    def _verification_status(self, name: str, *, relation: bool) -> DynamicObjectVerificationStatus:
        if "${" in name:
            return DynamicObjectVerificationStatus.NOT_VERIFIED
        if self._catalog is None:
            return DynamicObjectVerificationStatus.NOT_VERIFIED
        values = self._catalog_relations if relation else self._catalog_routines
        if name.upper() not in values:
            return DynamicObjectVerificationStatus.NOT_VERIFIED
        return (
            DynamicObjectVerificationStatus.VERIFIED_CATALOG
            if self._catalog.source_kind == "CATALOG"
            else DynamicObjectVerificationStatus.VERIFIED_SOURCE
        )

    def _dynamic_query_outputs(
        self,
        node: AstNode,
        site: DynamicSqlSite,
        variants: tuple[DynamicSqlVariant, ...],
    ) -> tuple[
        tuple[QuerySourceSummary, ...],
        tuple[QueryBindingFact, ...],
        tuple[DynamicQueryOutputBinding, ...],
        tuple[SemanticFinding, ...],
    ]:
        targets = site.into_target_names
        select_variants = [value for value in variants if value.statement_kind == DynamicSqlStatementKind.SELECT]
        if not targets or not select_variants:
            return (), (), (), ()
        summaries: list[QuerySourceSummary] = []
        for variant in select_variants:
            query_text = self._remove_dynamic_into(variant.template_text)
            summaries.append(
                self._query_builder.summarize_text(
                    source_node_ref=node.node_id,
                    kind=QuerySummaryKind.DYNAMIC_QUERY,
                    query_text=query_text,
                    evidence_refs=tuple(sorted({node.node_id, *variant.source_definition_refs})),
                )
            )
        projections_by_index: list[set[str]] = [set() for _ in targets]
        all_arity_match = True
        for summary in summaries:
            if len(summary.projection_expressions) != len(targets):
                all_arity_match = False
            for index in range(min(len(targets), len(summary.projection_expressions))):
                projections_by_index[index].add(summary.projection_expressions[index])
        query_bindings: list[QueryBindingFact] = []
        dynamic_bindings: list[DynamicQueryOutputBinding] = []
        findings: list[SemanticFinding] = []
        single_summary_ref = summaries[0].query_summary_id if len(summaries) == 1 else None
        for index, target in enumerate(targets):
            expressions = projections_by_index[index]
            expression = next(iter(expressions)) if len(expressions) == 1 else None
            complete = all_arity_match and expression is not None
            payload = f"{node.node_id}|{target}|{index}|{expression or ''}"
            query_bindings.append(
                QueryBindingFact(
                    binding_id="query-binding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    source_node_ref=node.node_id,
                    query_summary_ref=single_summary_ref,
                    binding_kind=QueryBindingKind.EXECUTE_INTO,
                    target_symbol=target,
                    projection_index=index,
                    projection_expression=expression,
                    analysis_completeness="COMPLETE" if complete else "PARTIAL",
                )
            )
            dynamic_bindings.append(
                DynamicQueryOutputBinding(
                    binding_id="dynamic-query-binding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    site_ref=site.site_id,
                    target_symbol=target,
                    projection_index=index,
                    projection_expression=expression,
                    analysis_completeness="COMPLETE" if complete else "PARTIAL",
                )
            )
            if not complete:
                findings.append(
                    self._finding(
                        SemanticFindingCode.DYNAMIC_QUERY_BINDING_PARTIAL,
                        f"Dynamic query output target {target} could not be reconciled to one stable projection.",
                        (node.node_id,),
                        "No complete dynamic query-to-variable binding was emitted.",
                    )
                )
        return tuple(summaries), tuple(query_bindings), tuple(dynamic_bindings), tuple(findings)

    def _site_findings(self, node: AstNode, site: DynamicSqlSite) -> tuple[SemanticFinding, ...]:
        code_by_status = {
            DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED: SemanticFindingCode.DYNAMIC_SQL_STATICALLY_RECONSTRUCTED,
            DynamicSqlResolutionStatus.ENUMERABLE_VARIANTS: SemanticFindingCode.DYNAMIC_SQL_ENUMERABLE_VARIANTS,
            DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED: SemanticFindingCode.DYNAMIC_SQL_PARTIALLY_RECONSTRUCTED,
            DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED: SemanticFindingCode.DYNAMIC_SQL_RUNTIME_CAPTURE_REQUIRED,
            DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL: SemanticFindingCode.DYNAMIC_SQL_UNRESOLVED,
            DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED: SemanticFindingCode.DYNAMIC_VARIANT_BUDGET_EXCEEDED,
        }
        consequence_by_status = {
            DynamicSqlResolutionStatus.STATICALLY_RECONSTRUCTED: "The reconstructed SQL may participate in query or effect analysis.",
            DynamicSqlResolutionStatus.ENUMERABLE_VARIANTS: "All bounded variants may participate in analysis.",
            DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED: "Static SQL structure is available; runtime values remain placeholders.",
            DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED: "No static effect assertion is admitted for unresolved SQL structure.",
            DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL: "The site remains an unresolved effect boundary.",
            DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED: "Enumeration was truncated and the site remains partial.",
        }
        result = [
            self._finding(
                code_by_status[site.resolution_status],
                f"Dynamic SQL site resolved as {site.resolution_status.value}.",
                site.evidence_refs,
                consequence_by_status[site.resolution_status],
            )
        ]
        if site.relation_resolution_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER:
            result.append(
                self._finding(
                    SemanticFindingCode.DYNAMIC_RELATION_UNRESOLVED,
                    "One or more dynamic relation identifiers could not be statically resolved.",
                    site.evidence_refs,
                    "Relation-level lineage and effect closure remain partial.",
                )
            )
        if site.call_resolution_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER:
            result.append(
                self._finding(
                    SemanticFindingCode.DYNAMIC_CALL_UNRESOLVED,
                    "A dynamic CALL target could not be statically resolved.",
                    site.evidence_refs,
                    "No callee effects were inferred.",
                )
            )
        return tuple(result)

    def _unresolved_site(
        self,
        node: AstNode,
        reason: str,
    ) -> tuple[DynamicSqlSite, tuple[SemanticFinding, ...], RuntimeCaptureContract]:
        site_id = self._stable_id("dynamic-site", node.node_id)
        site = DynamicSqlSite(
            site_id=site_id,
            execute_node_ref=node.node_id,
            execution_kind="IMMEDIATE" if node.kind == NodeKind.EXECUTE_IMMEDIATE else "PREPARED",
            resolution_status=DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL,
            variant_refs=(),
            relation_resolution_status=DynamicIdentifierResolutionStatus.NOT_APPLICABLE,
            call_resolution_status=DynamicIdentifierResolutionStatus.NOT_APPLICABLE,
            analysis_completeness="PARTIAL",
            evidence_refs=(node.node_id,),
        )
        finding = self._finding(
            SemanticFindingCode.DYNAMIC_SQL_UNRESOLVED,
            reason,
            (node.node_id,),
            "The site remains an unresolved effect boundary.",
        )
        return site, (finding,), self._capture_contract(site, node)

    def _capture_contract(self, site: DynamicSqlSite, node: AstNode) -> RuntimeCaptureContract:
        return RuntimeCaptureContract(
            capture_contract_id=self._stable_id("runtime-capture", site.site_id),
            site_ref=site.site_id,
            reason=f"Static resolution ended with {site.resolution_status.value}.",
            required_fields=(
                "final_sql_text",
                "prepared_statement_name",
                "bound_parameter_types",
                "resolved_relation_names",
                "resolved_call_target",
                "execution_sqlstate",
            ),
            evidence_refs=(node.node_id,),
        )

    def _finding(
        self,
        code: SemanticFindingCode,
        message: str,
        evidence_refs: tuple[str, ...],
        consequence: str,
    ) -> SemanticFinding:
        ranges = tuple(self._node_by_id[ref].source_range for ref in evidence_refs if ref in self._node_by_id)
        payload = f"{code.value}|{'|'.join(evidence_refs)}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=evidence_refs,
            source_ranges=ranges,
            consequence=consequence,
        )

    def _declaration_default(self, node: AstNode) -> tuple[str | None, str | None]:
        tokens = list(self._scanner.scan(node.text).tokens)
        if len(tokens) < 3 or tokens[0].upper != "DECLARE":
            return None, None
        default_index = next((i for i, token in enumerate(tokens) if token.upper == "DEFAULT"), None)
        if default_index is None or default_index + 1 >= len(tokens):
            return tokens[1].value.strip('"').upper(), None
        expression = self._render_tokens(tokens[default_index + 1 :]).rstrip(";")
        return tokens[1].value.strip('"').upper(), expression

    def _definition_expression(self, node: AstNode) -> str | None:
        if node.assignment_binding is not None:
            return node.assignment_binding.expression_text
        if node.kind == NodeKind.DECLARE_VARIABLE:
            _, expression = self._declaration_default(node)
            return expression
        return None

    def _split_concat(self, tokens: list[Token]) -> list[list[Token]]:
        groups: list[list[Token]] = [[]]
        depth = 0
        for token in tokens:
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth = max(0, depth - 1)
            if token.value == "||" and depth == 0:
                groups.append([])
            else:
                groups[-1].append(token)
        return [group for group in groups if group]

    @staticmethod
    def _strip_outer_parentheses(tokens: list[Token]) -> list[Token]:
        result = list(tokens)
        while len(result) >= 2 and result[0].value == "(" and result[-1].value == ")":
            depth = 0
            balanced = True
            for index, token in enumerate(result):
                if token.value == "(":
                    depth += 1
                elif token.value == ")":
                    depth -= 1
                    if depth == 0 and index != len(result) - 1:
                        balanced = False
                        break
            if not balanced:
                break
            result = result[1:-1]
        return result

    @staticmethod
    def _decode_string(raw: str) -> str:
        if len(raw) >= 2 and raw[0] == raw[-1] == "'":
            return raw[1:-1].replace("''", "'")
        return raw

    @staticmethod
    def _dedupe_values(values: list[_ValueVariant] | tuple[_ValueVariant, ...]) -> tuple[_ValueVariant, ...]:
        unique: dict[tuple[str, tuple[str, ...]], _ValueVariant] = {}
        for value in values:
            key = (value.text, tuple(sorted(value.placeholders)))
            existing = unique.get(key)
            if existing is None:
                unique[key] = value
            else:
                unique[key] = _ValueVariant(
                    value.text,
                    value.placeholders,
                    existing.source_refs | value.source_refs,
                )
        return tuple(sorted(unique.values(), key=lambda item: (item.text, tuple(sorted(item.placeholders)))))

    @staticmethod
    def _statement_kind(sql_text: str) -> DynamicSqlStatementKind:
        match = re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE|MERGE|CALL|VALUES)\b", sql_text, flags=re.IGNORECASE)
        return DynamicSqlStatementKind(match.group(1).upper()) if match else DynamicSqlStatementKind.UNKNOWN

    def _extract_relations(
        self,
        sql_text: str,
        kind: DynamicSqlStatementKind,
    ) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
        roles: list[tuple[str, str]] = []
        patterns: list[tuple[str, str]] = []
        if kind == DynamicSqlStatementKind.INSERT:
            patterns.append((r"\bINSERT\s+INTO\s+([^\s(,;]+)", "TARGET"))
        elif kind == DynamicSqlStatementKind.UPDATE:
            patterns.append((r"\bUPDATE\s+([^\s(,;]+)", "TARGET"))
        elif kind == DynamicSqlStatementKind.DELETE:
            patterns.append((r"\bDELETE\s+FROM\s+([^\s(,;]+)", "TARGET"))
        elif kind == DynamicSqlStatementKind.MERGE:
            patterns.append((r"\bMERGE\s+INTO\s+([^\s(,;]+)", "TARGET"))
        if kind in {DynamicSqlStatementKind.SELECT, DynamicSqlStatementKind.INSERT, DynamicSqlStatementKind.UPDATE, DynamicSqlStatementKind.MERGE}:
            patterns.extend([
                (r"\bFROM\s+([^\s(,;]+)", "SOURCE"),
                (r"\bJOIN\s+([^\s(,;]+)", "SOURCE"),
                (r"\bUSING\s+([^\s(,;]+)", "SOURCE"),
            ])
        for pattern, role in patterns:
            for match in re.finditer(pattern, sql_text, flags=re.IGNORECASE):
                name = match.group(1).strip('"').upper()
                if name not in {"SELECT", "VALUES"}:
                    roles.append((name, role))
        unique_roles = tuple(sorted(dict.fromkeys(roles)))
        return tuple(sorted({name for name, _ in unique_roles})), unique_roles

    @staticmethod
    def _extract_call_target(sql_text: str) -> str | None:
        match = re.search(r"\bCALL\s+([^\s(,;]+)", sql_text, flags=re.IGNORECASE)
        return match.group(1).strip('"').upper() if match else None

    @staticmethod
    def _structure_placeholder(sql_text: str) -> bool:
        structural_patterns = [
            r"\b(?:FROM|JOIN|UPDATE|INTO|MERGE\s+INTO|CALL)\s+\$\{",
            r"^\s*\$\{",
        ]
        return any(re.search(pattern, sql_text, flags=re.IGNORECASE) for pattern in structural_patterns)

    @staticmethod
    def _remove_dynamic_into(sql_text: str) -> str:
        # DB2 SQL PL may place INTO markers inside a prepared SELECT while EXECUTE also binds targets.
        return re.sub(
            r"\bINTO\s+\?(?:\s*,\s*\?)*\s+(?=FROM\b)",
            "",
            sql_text,
            count=1,
            flags=re.IGNORECASE,
        )

    @staticmethod
    def _render_tokens(tokens: list[Token]) -> str:
        parts: list[str] = []
        for token in tokens:
            if not parts:
                parts.append(token.value)
            elif token.value in {",", ")", ";", "."}:
                parts[-1] += token.value
            elif parts[-1].endswith("(") or token.value == "(":
                parts.append(token.value)
            else:
                parts.append(" " + token.value)
        return "".join(parts).strip()

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join(parts)
        return prefix + "-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def validate_dynamic_resolution_catalog(catalog: DynamicResolutionCatalog) -> None:
    payload = catalog.model_dump(mode="python", exclude={"content_digest"})
    expected = canonical_digest(payload)
    if catalog.content_digest != expected:
        raise ValueError(
            f"Dynamic resolution catalog digest mismatch: expected {expected}, got {catalog.content_digest}."
        )
