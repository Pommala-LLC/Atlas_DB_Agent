from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token, TokenKind
from ojas_reconciler.db2_behavior.parsing.models import AstNode, NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    QueryBindingFact,
    QueryBindingKind,
    QueryClauseSummary,
    QueryJoinSummary,
    QuerySourceSummary,
    QuerySummaryKind,
    QuerySemanticsCatalog,
    WindowFunctionSummary,
    WindowModelStatus,
    SemanticFinding,
    SemanticFindingCode,
)


@dataclass(frozen=True, slots=True)
class _QueryParts:
    projections: tuple[str, ...]
    relations: tuple[str, ...]
    joins: tuple[QueryJoinSummary, ...]
    cte_names: tuple[str, ...]
    clauses: tuple[QueryClauseSummary, ...]
    window_functions: tuple[str, ...]
    window_models: tuple[WindowFunctionSummary, ...]
    window_model_status: WindowModelStatus | None
    subquery_count: int
    complete: bool


class QuerySourceSummaryBuilder:
    """Builds deterministic lexical query summaries without claiming a DB2 query AST."""

    _clause_starts = {
        "WHERE",
        "HAVING",
        "ORDER",
        "GROUP",
        "FETCH",
        "FOR",
        "UNION",
        "EXCEPT",
        "INTERSECT",
    }
    _relation_stops = _clause_starts | {"ON", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS"}
    _window_names = {
        "ROW_NUMBER",
        "RANK",
        "DENSE_RANK",
        "LAG",
        "LEAD",
        "FIRST_VALUE",
        "LAST_VALUE",
        "NTILE",
    }

    def __init__(self, query_semantics_catalog: QuerySemanticsCatalog | None = None) -> None:
        self._scanner = Db2LexicalScanner()
        self._query_semantics_catalog = query_semantics_catalog

    def build(
        self,
        ast: ProcedureAst,
    ) -> tuple[tuple[QuerySourceSummary, ...], tuple[QueryBindingFact, ...], tuple[SemanticFinding, ...]]:
        summaries: list[QuerySourceSummary] = []
        bindings: list[QueryBindingFact] = []
        findings: list[SemanticFinding] = []
        cursor_by_name: dict[str, QuerySourceSummary] = {}

        for node in sorted(ast.nodes, key=lambda item: item.source_range.start_offset):
            if node.kind == NodeKind.DECLARE_CURSOR:
                cursor_name, query_text = self._cursor_query(node.text)
                if cursor_name is None or query_text is None:
                    findings.append(self._finding(ast, node, SemanticFindingCode.QUERY_SUMMARY_PARTIAL, "Cursor query could not be isolated."))
                    continue
                summary = self._summary(node, QuerySummaryKind.CURSOR_QUERY, query_text, cursor_name=cursor_name)
                summaries.append(summary)
                findings.extend(self._window_findings(ast, node, summary))
                cursor_by_name[cursor_name.upper()] = summary
            elif node.kind == NodeKind.SELECT_INTO and node.select_into_binding is not None:
                summary = self._summary(
                    node,
                    QuerySummaryKind.SELECT_INTO_QUERY,
                    node.select_into_binding.residual_query_text,
                )
                summaries.append(summary)
                findings.extend(self._window_findings(ast, node, summary))
                targets = node.select_into_binding.target_names
                for index, target in enumerate(targets):
                    projection = summary.projection_expressions[index] if index < len(summary.projection_expressions) else None
                    complete = projection is not None and node.select_into_binding.arity_status == "ARITY_MATCHED"
                    binding = self._binding(
                        source_node_ref=node.node_id,
                        query_summary_ref=summary.query_summary_id,
                        binding_kind=QueryBindingKind.SELECT_INTO,
                        target_symbol=target,
                        projection_index=index,
                        projection_expression=projection,
                        completeness="COMPLETE" if complete else "PARTIAL",
                    )
                    bindings.append(binding)
                    if not complete:
                        findings.append(
                            self._finding(
                                ast,
                                node,
                                SemanticFindingCode.QUERY_BINDING_ARITY_UNRESOLVED,
                                f"SELECT INTO target {target} could not be reconciled to one projection.",
                            )
                        )

        for node in sorted(ast.nodes, key=lambda item: item.source_range.start_offset):
            if node.kind != NodeKind.FETCH_CURSOR or node.fetch_binding is None:
                continue
            cursor = cursor_by_name.get(node.fetch_binding.cursor_name.upper())
            for index, target in enumerate(node.fetch_binding.target_names):
                projection = cursor.projection_expressions[index] if cursor is not None and index < len(cursor.projection_expressions) else None
                complete = cursor is not None and projection is not None and len(cursor.projection_expressions) == len(node.fetch_binding.target_names)
                bindings.append(
                    self._binding(
                        source_node_ref=node.node_id,
                        query_summary_ref=cursor.query_summary_id if cursor is not None else None,
                        binding_kind=QueryBindingKind.FETCH,
                        target_symbol=target,
                        projection_index=index,
                        projection_expression=projection,
                        completeness="COMPLETE" if complete else "PARTIAL",
                    )
                )
                if not complete:
                    findings.append(
                        self._finding(
                            ast,
                            node,
                            SemanticFindingCode.CURSOR_QUERY_BINDING_UNRESOLVED,
                            f"FETCH target {target} could not be reconciled to cursor {node.fetch_binding.cursor_name} projection {index + 1}.",
                        )
                    )

        return (
            tuple(sorted(summaries, key=lambda item: item.query_summary_id)),
            tuple(sorted(bindings, key=lambda item: item.binding_id)),
            tuple(sorted(findings, key=lambda item: item.finding_id)),
        )

    def summarize_text(
        self,
        *,
        source_node_ref: str,
        kind: QuerySummaryKind,
        query_text: str,
        evidence_refs: tuple[str, ...],
        cursor_name: str | None = None,
    ) -> QuerySourceSummary:
        parts = self._parse_parts(query_text, source_node_ref=source_node_ref)
        payload = f"{source_node_ref}|{kind.value}|{canonical_digest(query_text)}|{cursor_name or ''}"
        query_summary_id = "query-summary-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        return QuerySourceSummary(
            query_summary_id=query_summary_id,
            source_node_ref=source_node_ref,
            summary_kind=kind,
            cursor_name=cursor_name,
            query_text_digest=canonical_digest(query_text),
            projection_expressions=parts.projections,
            relation_refs=parts.relations,
            joins=parts.joins,
            cte_names=parts.cte_names,
            clauses=parts.clauses,
            window_functions=parts.window_functions,
            window_models=parts.window_models,
            window_model_status=parts.window_model_status,
            subquery_count=parts.subquery_count,
            analysis_completeness="COMPLETE" if parts.complete else "PARTIAL",
            evidence_refs=evidence_refs,
        )

    def _summary(
        self,
        node: AstNode,
        kind: QuerySummaryKind,
        query_text: str,
        *,
        cursor_name: str | None = None,
    ) -> QuerySourceSummary:
        return self.summarize_text(
            source_node_ref=node.node_id,
            kind=kind,
            query_text=query_text,
            cursor_name=cursor_name,
            evidence_refs=(node.node_id,),
        )

    def _parse_parts(self, query_text: str, *, source_node_ref: str) -> _QueryParts:
        tokens = list(self._scanner.scan(query_text).tokens)
        if not tokens:
            return _QueryParts((), (), (), (), (), (), (), None, 0, False)
        depths = self._depths(tokens)
        main_select = self._main_select_index(tokens, depths)
        if main_select is None:
            models, status = self._window_models(tokens, depths, source_node_ref=source_node_ref)
            return _QueryParts((), (), (), self._cte_names(tokens, depths), (), self._window_functions(tokens), models, status, 0, False)
        main_from = self._find_keyword(tokens, depths, "FROM", main_select + 1, target_depth=depths[main_select])
        projections: tuple[str, ...] = ()
        complete = main_from is not None
        if main_from is not None:
            projections = self._split_expressions(tokens[main_select + 1 : main_from])
        relations = self._relations(tokens, depths)
        joins = self._joins(tokens, depths)
        clauses = self._clauses(tokens, depths, main_select)
        select_count = sum(1 for token in tokens if token.upper == "SELECT")
        window_models, window_status = self._window_models(tokens, depths, source_node_ref=source_node_ref)
        window_complete = not window_models or all(
            model.model_status in {WindowModelStatus.WINDOW_MODEL_COMPLETE, WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION}
            for model in window_models
        )
        return _QueryParts(
            projections=projections,
            relations=relations,
            joins=joins,
            cte_names=self._cte_names(tokens, depths),
            clauses=clauses,
            window_functions=self._window_functions(tokens),
            window_models=window_models,
            window_model_status=window_status,
            subquery_count=max(0, select_count - 1),
            complete=complete and bool(projections) and window_complete,
        )

    def _cursor_query(self, text: str) -> tuple[str | None, str | None]:
        tokens = list(self._scanner.scan(text).tokens)
        if len(tokens) < 5 or tokens[0].upper != "DECLARE":
            return None, None
        cursor_name = tokens[1].value.strip('"')
        for_index = next((index for index, token in enumerate(tokens) if token.upper == "FOR"), None)
        if for_index is None or for_index + 1 >= len(tokens):
            return cursor_name, None
        start = tokens[for_index + 1].offset
        return cursor_name, text[start:].strip().rstrip(";").strip()

    @staticmethod
    def _depths(tokens: list[Token]) -> list[int]:
        result: list[int] = []
        depth = 0
        for token in tokens:
            result.append(depth)
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth = max(0, depth - 1)
        return result

    def _main_select_index(self, tokens: list[Token], depths: list[int]) -> int | None:
        base = min(depths) if depths else 0
        candidates = [index for index, token in enumerate(tokens) if token.upper == "SELECT" and depths[index] == base]
        return candidates[-1] if candidates else None

    @staticmethod
    def _find_keyword(
        tokens: list[Token],
        depths: list[int],
        keyword: str,
        start: int,
        *,
        target_depth: int,
    ) -> int | None:
        for index in range(start, len(tokens)):
            if depths[index] == target_depth and tokens[index].upper == keyword:
                return index
        return None

    def _split_expressions(self, tokens: list[Token]) -> tuple[str, ...]:
        if not tokens:
            return ()
        pieces: list[list[Token]] = [[]]
        depth = 0
        for token in tokens:
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth = max(0, depth - 1)
            if token.value == "," and depth == 0:
                pieces.append([])
            else:
                pieces[-1].append(token)
        return tuple(self._render(piece) for piece in pieces if piece)

    def _relations(self, tokens: list[Token], depths: list[int]) -> tuple[str, ...]:
        values: list[str] = []
        for index, token in enumerate(tokens):
            if token.upper not in {"FROM", "JOIN"}:
                continue
            next_index = index + 1
            if next_index >= len(tokens) or tokens[next_index].value == "(":
                continue
            relation_tokens: list[Token] = []
            while next_index < len(tokens):
                candidate = tokens[next_index]
                if depths[next_index] != depths[index]:
                    break
                if candidate.upper in self._relation_stops or candidate.value in {",", ";"}:
                    break
                if candidate.kind == TokenKind.WORD or candidate.kind == TokenKind.QUOTED_IDENTIFIER or candidate.value == ".":
                    relation_tokens.append(candidate)
                    next_index += 1
                    if len(relation_tokens) >= 3 and candidate.value != ".":
                        break
                    continue
                break
            if relation_tokens:
                relation = self._render(relation_tokens)
                # Strip a likely alias while preserving qualified names.
                words = relation.split()
                if len(words) > 1:
                    relation = words[0]
                values.append(relation)
        return tuple(sorted(dict.fromkeys(values)))

    def _joins(self, tokens: list[Token], depths: list[int]) -> tuple[QueryJoinSummary, ...]:
        result: list[QueryJoinSummary] = []
        for index, token in enumerate(tokens):
            if token.upper != "JOIN":
                continue
            prefix = tokens[index - 1].upper if index > 0 and depths[index - 1] == depths[index] else ""
            if prefix == "OUTER" and index > 1:
                prefix = tokens[index - 2].upper
            join_kind = prefix if prefix in {"INNER", "LEFT", "RIGHT", "FULL", "CROSS"} else "INNER"
            on_index = self._find_keyword(tokens, depths, "ON", index + 1, target_depth=depths[index])
            condition: str | None = None
            if on_index is not None:
                end = on_index + 1
                while end < len(tokens):
                    if depths[end] == depths[on_index] and tokens[end].upper in self._clause_starts | {"JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS"}:
                        break
                    end += 1
                condition = self._render(tokens[on_index + 1 : end]) or None
            payload = f"{index}|{join_kind}|{condition or ''}"
            result.append(
                QueryJoinSummary(
                    join_id="query-join-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    join_kind=join_kind,
                    condition_text=condition,
                    null_producing_side=("RIGHT" if join_kind == "LEFT" else "LEFT" if join_kind == "RIGHT" else "BOTH" if join_kind == "FULL" else "NONE"),
                )
            )
        return tuple(result)

    def _cte_names(self, tokens: list[Token], depths: list[int]) -> tuple[str, ...]:
        if not tokens or tokens[0].upper != "WITH":
            return ()
        result: list[str] = []
        for index in range(1, len(tokens) - 2):
            if depths[index] != 0 or tokens[index].kind not in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
                continue
            next_index = index + 1
            if tokens[next_index].value == "(":
                # Optional CTE column list: find matching close before AS.
                depth = depths[next_index]
                next_index += 1
                while next_index < len(tokens) and not (tokens[next_index].value == ")" and depths[next_index] == depth + 1):
                    next_index += 1
                next_index += 1
            if next_index < len(tokens) and tokens[next_index].upper == "AS":
                result.append(tokens[index].value.strip('"'))
        return tuple(result)

    def _clauses(self, tokens: list[Token], depths: list[int], main_select: int) -> tuple[QueryClauseSummary, ...]:
        depth = depths[main_select]
        starts: list[tuple[int, str]] = []
        index = main_select + 1
        while index < len(tokens):
            if depths[index] != depth:
                index += 1
                continue
            upper = tokens[index].upper
            if upper in {"WHERE", "HAVING"}:
                starts.append((index, upper))
            elif upper in {"GROUP", "ORDER"} and index + 1 < len(tokens) and tokens[index + 1].upper == "BY":
                starts.append((index, f"{upper}_BY"))
            index += 1
        result: list[QueryClauseSummary] = []
        for position, (start, kind) in enumerate(starts):
            body_start = start + (2 if kind in {"GROUP_BY", "ORDER_BY"} else 1)
            body_end = starts[position + 1][0] if position + 1 < len(starts) else len(tokens)
            text = self._render(tokens[body_start:body_end]).rstrip(";")
            result.append(QueryClauseSummary(clause_kind=kind, expression_text=text))
        return tuple(result)

    def _window_functions(self, tokens: list[Token]) -> tuple[str, ...]:
        names: list[str] = []
        for index, token in enumerate(tokens[:-1]):
            if token.upper in self._window_names and tokens[index + 1].value == "(":
                names.append(token.upper)
        return tuple(sorted(dict.fromkeys(names)))

    def _window_models(
        self,
        tokens: list[Token],
        depths: list[int],
        *,
        source_node_ref: str,
    ) -> tuple[tuple[WindowFunctionSummary, ...], WindowModelStatus | None]:
        models: list[WindowFunctionSummary] = []
        for index, token in enumerate(tokens[:-1]):
            if token.upper not in self._window_names or tokens[index + 1].value != "(":
                continue
            function_close = self._matching_close(tokens, index + 1)
            if function_close is None:
                continue
            over_index = next(
                (i for i in range(function_close + 1, min(len(tokens), function_close + 5)) if tokens[i].upper == "OVER"),
                None,
            )
            if over_index is None or over_index + 1 >= len(tokens) or tokens[over_index + 1].value != "(":
                status = WindowModelStatus.WINDOW_MODEL_PARTIAL
                models.append(self._window_model(source_node_ref, index, token.upper, None, (), (), None, None, "UNKNOWN", status))
                continue
            over_close = self._matching_close(tokens, over_index + 1)
            if over_close is None:
                status = WindowModelStatus.WINDOW_MODEL_PARTIAL
                models.append(self._window_model(source_node_ref, index, token.upper, self._render(tokens[index + 2:function_close]), (), (), None, None, "UNKNOWN", status))
                continue
            over_tokens = tokens[over_index + 2:over_close]
            partition_by, order_by = self._window_spec_parts(over_tokens)
            select_index = self._nearest_select(tokens, depths, index)
            relation, where_text = self._window_input(tokens, depths, select_index)
            cardinality = self._input_cardinality(relation, where_text)
            order_deterministic = self._order_deterministic(relation, order_by)
            if cardinality == "ZERO_OR_ONE" and token.upper in {"LAG", "LEAD"}:
                status = WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION
            elif cardinality == "UNKNOWN":
                status = WindowModelStatus.WINDOW_INPUT_CARDINALITY_UNKNOWN
            elif order_deterministic is False:
                status = WindowModelStatus.WINDOW_ORDER_NONDETERMINISTIC
            else:
                status = WindowModelStatus.WINDOW_MODEL_COMPLETE
            models.append(self._window_model(
                source_node_ref, index, token.upper, self._render(tokens[index + 2:function_close]),
                partition_by, order_by, relation, where_text, cardinality, status, order_deterministic
            ))
        if not models:
            return (), None
        statuses = {model.model_status for model in models}
        if WindowModelStatus.WINDOW_MODEL_PARTIAL in statuses:
            overall = WindowModelStatus.WINDOW_MODEL_PARTIAL
        elif WindowModelStatus.WINDOW_INPUT_CARDINALITY_UNKNOWN in statuses:
            overall = WindowModelStatus.WINDOW_INPUT_CARDINALITY_UNKNOWN
        elif WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION in statuses:
            overall = WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION
        else:
            overall = WindowModelStatus.WINDOW_MODEL_COMPLETE
        return tuple(models), overall

    @staticmethod
    def _matching_close(tokens: list[Token], open_index: int) -> int | None:
        depth = 0
        for index in range(open_index, len(tokens)):
            if tokens[index].value == "(":
                depth += 1
            elif tokens[index].value == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def _window_spec_parts(self, tokens: list[Token]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        partition: tuple[str, ...] = ()
        order: tuple[str, ...] = ()
        upper = [token.upper for token in tokens]
        if "PARTITION" in upper:
            start = upper.index("PARTITION") + 1
            if start < len(tokens) and tokens[start].upper == "BY":
                start += 1
            end = upper.index("ORDER") if "ORDER" in upper else len(tokens)
            partition = self._split_expressions(tokens[start:end])
        if "ORDER" in upper:
            start = upper.index("ORDER") + 1
            if start < len(tokens) and tokens[start].upper == "BY":
                start += 1
            order = self._split_expressions(tokens[start:])
        return partition, order

    @staticmethod
    def _nearest_select(tokens: list[Token], depths: list[int], before: int) -> int | None:
        target_depth = depths[before]
        values = [i for i in range(before - 1, -1, -1) if tokens[i].upper == "SELECT" and depths[i] == target_depth]
        return values[0] if values else None

    def _window_input(
        self, tokens: list[Token], depths: list[int], select_index: int | None
    ) -> tuple[str | None, str | None]:
        if select_index is None:
            return None, None
        depth = depths[select_index]
        from_index = self._find_keyword(tokens, depths, "FROM", select_index + 1, target_depth=depth)
        if from_index is None or from_index + 1 >= len(tokens):
            return None, None
        relation = tokens[from_index + 1].value.strip('"')
        where_index = self._find_keyword(tokens, depths, "WHERE", from_index + 1, target_depth=depth)
        if where_index is None:
            return relation, None
        end = where_index + 1
        while end < len(tokens):
            if depths[end] < depth:
                break
            if depths[end] == depth and tokens[end].upper in {"GROUP", "ORDER", "HAVING", "UNION"}:
                break
            end += 1
        return relation, self._render(tokens[where_index + 1:end])

    def _input_cardinality(self, relation: str | None, where_text: str | None) -> str:
        if relation is None or self._query_semantics_catalog is None:
            return "UNKNOWN"
        if where_text is None:
            return "MULTIPLE_POSSIBLE"
        import re
        normalized_relation = relation.upper().split(".")[-1]
        for key in self._query_semantics_catalog.unique_keys:
            if key.relation_name.upper().split(".")[-1] != normalized_relation or len(key.column_names) != 1:
                continue
            column = re.escape(key.column_names[0])
            if re.search(rf"(?:\b[A-Z_][A-Z0-9_]*\.)?{column}\s*=\s*[^\s,)]+", where_text, re.IGNORECASE):
                return "ZERO_OR_ONE"
        return "MULTIPLE_POSSIBLE"

    def _order_deterministic(self, relation: str | None, order_by: tuple[str, ...]) -> bool | None:
        if relation is None or self._query_semantics_catalog is None or not order_by:
            return None
        normalized_relation = relation.upper().split(".")[-1]
        ordered_columns = {value.upper().split()[0].split(".")[-1] for value in order_by}
        keys = [key for key in self._query_semantics_catalog.unique_keys if key.relation_name.upper().split(".")[-1] == normalized_relation]
        if not keys:
            return None
        return any(set(column.upper() for column in key.column_names).issubset(ordered_columns) for key in keys)

    @staticmethod
    def _window_model(
        source_node_ref: str, index: int, function_name: str, argument_text: str | None,
        partition_by: tuple[str, ...], order_by: tuple[str, ...], relation: str | None,
        where_text: str | None, cardinality: str, status: WindowModelStatus,
        order_deterministic: bool | None = None
    ) -> WindowFunctionSummary:
        payload = f"{source_node_ref}|{index}|{function_name}|{argument_text or ''}|{status.value}"
        return WindowFunctionSummary(
            window_id="window-model-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            function_name=function_name,
            argument_text=argument_text,
            partition_by=partition_by,
            order_by=order_by,
            input_relation_ref=relation,
            input_filter_text=where_text,
            input_cardinality=cardinality,
            order_deterministic=order_deterministic,
            model_status=status,
            evidence_refs=(source_node_ref,),
        )

    @staticmethod
    def _render(tokens: list[Token]) -> str:
        if not tokens:
            return ""
        output = ""
        previous: Token | None = None
        for token in tokens:
            if not output:
                output = token.value
            elif token.value in {",", ")", ";"}:
                output += token.value
            elif previous is not None and previous.value in {"(", "."}:
                output += token.value
            elif token.value == ".":
                output += token.value
            elif token.value == "(":
                output += " " + token.value
            else:
                output += " " + token.value
            previous = token
        return " ".join(output.split())

    def _window_findings(
        self, ast: ProcedureAst, node: AstNode, summary: QuerySourceSummary
    ) -> tuple[SemanticFinding, ...]:
        result: list[SemanticFinding] = []
        if summary.window_functions and not summary.window_models:
            result.append(self._finding(
                ast, node, SemanticFindingCode.QUERY_SUMMARY_COMPLETE_WITHOUT_WINDOW_MODEL,
                "Window function text was found but no window semantic model was produced.",
            ))
        for model in summary.window_models:
            if model.model_status in {
                WindowModelStatus.WINDOW_MODEL_PARTIAL,
                WindowModelStatus.WINDOW_INPUT_CARDINALITY_UNKNOWN,
            }:
                code = (
                    SemanticFindingCode.WINDOW_MODEL_PARTIAL
                    if model.model_status == WindowModelStatus.WINDOW_MODEL_PARTIAL
                    else SemanticFindingCode.WINDOW_INPUT_CARDINALITY_UNKNOWN
                )
                result.append(self._finding(
                    ast, node, code,
                    f"Window model for {model.function_name} is incomplete: {model.model_status.value}.",
                ))
            elif model.model_status == WindowModelStatus.WINDOW_ORDER_NONDETERMINISTIC:
                result.append(self._finding(
                    ast, node, SemanticFindingCode.WINDOW_ORDER_NONDETERMINISTIC,
                    f"Window ordering for {model.function_name} does not include a catalog-verified unique key.",
                ))
            elif model.model_status == WindowModelStatus.WINDOW_OVER_SINGLE_ROW_PARTITION:
                result.append(self._finding(
                    ast, node, SemanticFindingCode.WINDOW_OVER_SINGLE_ROW_PARTITION,
                    f"{model.function_name} is evaluated over an input constrained to at most one row.",
                ))
        return tuple(result)

    @staticmethod
    def _binding(
        *,
        source_node_ref: str,
        query_summary_ref: str | None,
        binding_kind: QueryBindingKind,
        target_symbol: str,
        projection_index: int,
        projection_expression: str | None,
        completeness: str,
    ) -> QueryBindingFact:
        payload = f"{source_node_ref}|{query_summary_ref or ''}|{binding_kind.value}|{target_symbol}|{projection_index}"
        return QueryBindingFact(
            binding_id="query-binding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            source_node_ref=source_node_ref,
            query_summary_ref=query_summary_ref,
            binding_kind=binding_kind,
            target_symbol=target_symbol,
            projection_index=projection_index,
            projection_expression=projection_expression,
            analysis_completeness=completeness,
        )

    @staticmethod
    def _finding(ast: ProcedureAst, node: AstNode, code: SemanticFindingCode, message: str) -> SemanticFinding:
        payload = f"{code.value}|{node.node_id}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=(node.node_id,),
            source_ranges=(node.source_range,),
            consequence="Affected query lineage or query-to-variable bindings remain partial.",
        )
