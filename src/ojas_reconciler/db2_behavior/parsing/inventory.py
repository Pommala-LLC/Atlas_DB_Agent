from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token, TokenKind
from ojas_reconciler.db2_behavior.parsing.clp import Db2ClpScriptSegmenter
from ojas_reconciler.db2_behavior.parsing.inventory_models import (
    ControlComplexityProfile,
    EffectInventory,
    Eligibility,
    Db2ScriptInventoryReport,
    EstateInventoryReport,
    Finding,
    InventoryBudgets,
    ProcedureHeader,
    ProcedureInventory,
    QueryComplexityProfile,
    Severity,
    SourceIdentity,
)


QUERY_STARTS = {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "VALUES"}
AGGREGATES = {"COUNT", "SUM", "AVG", "MIN", "MAX"}
WINDOW_FUNCS = {"ROW_NUMBER", "RANK", "DENSE_RANK", "LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE"}
LITERAL_WORDS = {"NULL", "TRUE", "FALSE", "CURRENT", "DEFAULT"}


class InventoryAnalyzer:
    """Gate 0 lexical inventory analyzer.

    This is deliberately not advertised as a complete DB2 parser. It measures
    estate complexity and produces explicit findings where a real grammar or
    catalog resolution is required.
    """

    def __init__(self, budgets: InventoryBudgets | None = None) -> None:
        self.budgets = budgets or InventoryBudgets()
        self.scanner = Db2LexicalScanner()

    def analyze_path(self, path: Path) -> ProcedureInventory:
        data = path.read_bytes()
        text = data.decode("utf-8-sig")
        return self._analyze_text(
            text=text,
            raw_bytes=data,
            source_path=path,
            source_unit_index=None,
            source_unit_count=None,
            source_unit_start_offset=None,
            source_unit_end_offset=None,
            detected_terminator=None,
        )

    def analyze_script_path(self, path: Path) -> Db2ScriptInventoryReport:
        data = path.read_bytes()
        text = data.decode("utf-8-sig")
        segmenter = Db2ClpScriptSegmenter()
        script = segmenter.segment_text(text, source_name=path.name)
        reports: list[ProcedureInventory] = []
        for unit in script.source_units:
            unit_bytes = unit.source_text.encode("utf-8")
            reports.append(
                self._analyze_text(
                    text=unit.source_text,
                    raw_bytes=unit_bytes,
                    source_path=path,
                    source_unit_index=unit.unit_index,
                    source_unit_count=script.discovered_source_unit_count,
                    source_unit_start_offset=unit.source_range.start_offset,
                    source_unit_end_offset=unit.source_range.end_offset,
                    detected_terminator=script.detected_terminator,
                )
            )
        findings: list[Finding] = []
        if script.expected_source_unit_count != script.discovered_source_unit_count:
            findings.append(
                Finding(
                    code="SOURCE_UNIT_COUNT_MISMATCH",
                    severity=Severity.ERROR,
                    message=(
                        f"Expected {script.expected_source_unit_count} CREATE PROCEDURE units but "
                        f"discovered {script.discovered_source_unit_count}."
                    ),
                )
            )
        if script.unclassified_fragment_count:
            findings.append(
                Finding(
                    code="UNCLASSIFIED_SCRIPT_FRAGMENTS",
                    severity=Severity.WARNING,
                    message=f"{script.unclassified_fragment_count} script fragments remain unclassified.",
                )
            )
        source = SourceIdentity(
            path=str(path.resolve()),
            filename=path.name,
            content_digest="sha256:" + hashlib.sha256(data).hexdigest(),
            byte_count=len(data),
            line_count=text.count("\n") + (0 if text.endswith("\n") else 1),
            code_line_count=len(self.scanner.scan(text).code_lines),
            detected_terminator=script.detected_terminator,
        )
        return Db2ScriptInventoryReport(
            source=source,
            detected_terminator=script.detected_terminator,
            terminator_detection=script.terminator_detection,
            expected_source_unit_count=script.expected_source_unit_count,
            discovered_source_unit_count=script.discovered_source_unit_count,
            procedure_reports=tuple(reports),
            unclassified_script_fragment_count=script.unclassified_fragment_count,
            source_unit_count_matches=(
                script.expected_source_unit_count == script.discovered_source_unit_count
            ),
            findings=tuple(findings),
        )

    def _analyze_text(
        self,
        *,
        text: str,
        raw_bytes: bytes,
        source_path: Path,
        source_unit_index: int | None,
        source_unit_count: int | None,
        source_unit_start_offset: int | None,
        source_unit_end_offset: int | None,
        detected_terminator: str | None,
    ) -> ProcedureInventory:
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        lex = self.scanner.scan(text)
        findings: list[Finding] = []
        if lex.unterminated_string:
            findings.append(Finding(code="UNTERMINATED_LITERAL", severity=Severity.ERROR, message="Unterminated SQL literal or quoted identifier."))
        if lex.unterminated_comment:
            findings.append(Finding(code="UNTERMINATED_COMMENT", severity=Severity.ERROR, message="Unterminated block comment."))

        tokens = list(lex.tokens)
        header = self._extract_header(tokens)
        if header.name is None:
            findings.append(Finding(code="PROCEDURE_DECLARATION_NOT_FOUND", severity=Severity.ERROR, message="No CREATE PROCEDURE declaration was identified."))

        body_tokens = self._body_tokens(tokens)
        statements = self._split_statements(body_tokens)
        query = self._query_profile(body_tokens, statements)
        findings.extend(self._counter_invariant_findings(query))
        control = self._control_profile(body_tokens, statements)
        effects = self._effect_inventory(body_tokens, statements, header, len(lex.code_lines))
        dynamic_sql = effects.prepare_count > 0 or effects.execute_immediate_count > 0
        temporary_table = self._contains_sequence(body_tokens, ("DECLARE", "GLOBAL", "TEMPORARY", "TABLE")) or self._contains_sequence(body_tokens, ("CREATE", "GLOBAL", "TEMPORARY", "TABLE"))
        transaction_control = effects.commit_count > 0 or effects.rollback_count > 0
        unresolved_calls = effects.call_count

        if query.join_count:
            findings.append(Finding(code="JOIN_SEMANTICS_REQUIRE_QUERY_IR", severity=Severity.INFO, message="Join counts are lexical inventory only; ownership, cardinality and domain relationship are not inferred."))
        if dynamic_sql:
            findings.append(Finding(code="DYNAMIC_SQL_PRESENT", severity=Severity.WARNING, message="Dynamic SQL requires bounded reconstruction in Phase 4."))
        if query.recursive_cte_count:
            findings.append(Finding(code="RECURSIVE_CTE_PRESENT", severity=Severity.WARNING, message="Recursive CTE requires Phase 3 semantic analysis."))
        if control.handler_count:
            findings.append(Finding(code="HANDLER_REGIONS_PRESENT", severity=Severity.INFO, message="Handlers require lexical-scope and continuation analysis beyond Gate 0."))
        if control.loop_count:
            findings.append(Finding(code="LOOP_REGIONS_PRESENT", severity=Severity.INFO, message="Loops require proof or conservative summaries beyond Gate 0."))
        if effects.call_count:
            findings.append(Finding(code="CALL_OWNERSHIP_BINDING_REQUIRED", severity=Severity.INFO, message="CALL sites are counted but remain unresolved until catalog/source ownership is bound."))

        eligibility, reasons = self._eligibility(header, len(lex.code_lines), query, control, effects, findings)
        filename = source_path.name if source_unit_index is None else f"{source_path.name}#unit-{source_unit_index:03d}"
        source = SourceIdentity(
            path=str(source_path.resolve()),
            filename=filename,
            content_digest=digest,
            byte_count=len(raw_bytes),
            line_count=text.count("\n") + (0 if text.endswith("\n") else 1),
            code_line_count=len(lex.code_lines),
            source_unit_index=source_unit_index,
            source_unit_count=source_unit_count,
            source_unit_start_offset=source_unit_start_offset,
            source_unit_end_offset=source_unit_end_offset,
            detected_terminator=detected_terminator,
        )
        return ProcedureInventory(
            source=source,
            procedure=header,
            statement_count=len(statements),
            query_complexity=query,
            control_complexity=control,
            effects=effects,
            dynamic_sql_present=dynamic_sql,
            temporary_table_present=temporary_table,
            transaction_control_present=transaction_control,
            unresolved_call_count=unresolved_calls,
            eligibility=eligibility,
            eligibility_reasons=tuple(reasons),
            findings=tuple(findings),
        )

    def analyze_directory(self, root: Path, patterns: tuple[str, ...] = ("*.sql", "*.ddl", "*.spsql", "*.db2")) -> EstateInventoryReport:
        paths: set[Path] = set()
        for pattern in patterns:
            paths.update(root.rglob(pattern))
        script_reports = [self.analyze_script_path(path) for path in sorted(paths)]
        return EstateInventoryReport.from_script_reports(root, script_reports)

    @staticmethod
    def _body_begin_index(tokens: list[Token]) -> int | None:
        # The first BEGIN after the procedure header opens the native SQL body.
        return next((index for index, token in enumerate(tokens) if token.upper == "BEGIN"), None)

    @classmethod
    def _body_tokens(cls, tokens: list[Token]) -> list[Token]:
        begin = cls._body_begin_index(tokens)
        if begin is None:
            return tokens
        end = next((index for index in range(len(tokens) - 1, begin, -1) if tokens[index].upper == "END"), None)
        if end is None:
            return tokens[begin + 1 :]
        return tokens[begin + 1 : end]

    @staticmethod
    def _split_statements(tokens: list[Token]) -> list[list[Token]]:
        statements: list[list[Token]] = []
        current: list[Token] = []
        for token in tokens:
            current.append(token)
            if token.value == ";":
                statements.append(current)
                current = []
        if current:
            statements.append(current)
        return [statement for statement in statements if any(t.kind != TokenKind.SYMBOL or t.value != ";" for t in statement)]

    def _extract_header(self, tokens: list[Token]) -> ProcedureHeader:
        create_idx = self._find_sequence(tokens, ("CREATE", "PROCEDURE"))
        if create_idx is None:
            create_idx = self._find_sequence(tokens, ("CREATE", "OR", "REPLACE", "PROCEDURE"))
        if create_idx is None:
            return ProcedureHeader()

        proc_idx = next(i for i in range(create_idx, min(create_idx + 5, len(tokens))) if tokens[i].upper == "PROCEDURE")
        name_tokens: list[str] = []
        i = proc_idx + 1
        while i < len(tokens) and tokens[i].value != "(":
            if tokens[i].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER} or tokens[i].value == ".":
                name_tokens.append(tokens[i].value.strip('"'))
            i += 1
        full_name = "".join(name_tokens)
        schema, name = (full_name.rsplit(".", 1) if "." in full_name else (None, full_name or None))

        parameter_names: list[str] = []
        out_params: list[str] = []
        inout_params: list[str] = []
        if i < len(tokens) and tokens[i].value == "(":
            depth = 1
            i += 1
            segment: list[Token] = []
            while i < len(tokens) and depth:
                tok = tokens[i]
                if tok.value == "(":
                    depth += 1
                elif tok.value == ")":
                    depth -= 1
                    if depth == 0:
                        if segment:
                            self._consume_parameter(segment, parameter_names, out_params, inout_params)
                        break
                if depth == 1 and tok.value == ",":
                    self._consume_parameter(segment, parameter_names, out_params, inout_params)
                    segment = []
                else:
                    segment.append(tok)
                i += 1

        header_tokens = tokens[: self._body_begin_index(tokens) or len(tokens)]
        language = self._value_after_keyword(header_tokens, "LANGUAGE")
        specific_name = self._value_after_sequence(header_tokens, ("SPECIFIC",))
        routine_version_id = self._value_after_sequence(header_tokens, ("VERSION",))
        commit_on_return = self._value_after_sequence(header_tokens, ("COMMIT", "ON", "RETURN"))
        return ProcedureHeader(
            schema_name=schema.upper() if schema else None,
            name=name.upper() if name else None,
            specific_name=specific_name.upper() if specific_name else None,
            language=language.upper() if language else None,
            routine_version_id=routine_version_id.upper() if routine_version_id else None,
            commit_on_return=commit_on_return.upper() if commit_on_return else None,
            parameter_names=tuple(parameter_names),
            out_parameter_names=tuple(out_params),
            inout_parameter_names=tuple(inout_params),
        )

    @staticmethod
    def _consume_parameter(segment: list[Token], names: list[str], outs: list[str], inouts: list[str]) -> None:
        words = [token.upper for token in segment if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}]
        if not words:
            return
        direction = "IN"
        idx = 0
        if words[0] in {"IN", "OUT", "INOUT"}:
            direction = words[0]
            idx = 1
        if idx >= len(words):
            return
        name = words[idx]
        names.append(name)
        if direction == "OUT":
            outs.append(name)
        elif direction == "INOUT":
            inouts.append(name)

    def _query_profile(self, tokens: list[Token], statements: list[list[Token]]) -> QueryComplexityProfile:
        uppers = [token.upper for token in tokens]
        counts = {keyword: uppers.count(keyword) for keyword in QUERY_STARTS}
        join_count, inner, left, right, full, cross = self._join_breakdown(tokens)
        lateral = uppers.count("LATERAL")
        max_depth = 0
        depth = 0
        subqueries = 0
        for index, token in enumerate(tokens):
            if token.value == "(":
                depth += 1
                max_depth = max(max_depth, depth)
                if index + 1 < len(tokens) and tokens[index + 1].upper in {"SELECT", "WITH"}:
                    subqueries += 1
            elif token.value == ")":
                depth = max(0, depth - 1)
        recursive = self._recursive_cte_count(tokens)
        window = uppers.count("OVER")
        aggregates = sum(uppers.count(name) for name in AGGREGATES)
        query_count = sum(1 for s in statements if any(t.upper in QUERY_STARTS for t in s[:5]))
        weighted = (
            len(tokens) // 20
            + join_count * 2
            + left * 2
            + full * 4
            + lateral * 4
            + subqueries * 3
            + recursive * 10
            + window * 2
            + max_depth
        )
        return QueryComplexityProfile(
            query_count=query_count,
            select_count=counts["SELECT"],
            insert_count=counts["INSERT"],
            update_count=counts["UPDATE"],
            delete_count=counts["DELETE"],
            merge_count=counts["MERGE"],
            with_clause_count=counts["WITH"],
            recursive_cte_count=recursive,
            subquery_count=subqueries,
            max_parenthesis_depth=max_depth,
            join_count=join_count,
            inner_join_count=inner,
            left_join_count=left,
            right_join_count=right,
            full_join_count=full,
            cross_join_count=cross,
            lateral_join_count=lateral,
            window_function_count=window,
            aggregate_function_count=aggregates,
            weighted_score=weighted,
        )

    @classmethod
    def _recursive_cte_count(cls, tokens: list[Token]) -> int:
        """Count recursive CTE definitions by structural self-reference.

        Db2 recursive CTEs do not require a ``WITH RECURSIVE`` keyword.  A CTE is
        recursive when its query body references its own declared name.  This
        parser intentionally counts CTE definitions, not lexical WITH tokens.
        """
        recursive_names: set[tuple[int, str]] = set()
        for with_index, token in enumerate(tokens):
            if token.upper != "WITH":
                continue
            cursor = with_index + 1
            if cursor < len(tokens) and tokens[cursor].upper == "RECURSIVE":
                cursor += 1
            while cursor < len(tokens):
                name_token = tokens[cursor]
                if name_token.kind not in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
                    break
                name = name_token.upper
                cursor += 1
                # Optional CTE column list.
                if cursor < len(tokens) and tokens[cursor].value == "(":
                    close = cls._matching_parenthesis(tokens, cursor)
                    if close is None:
                        break
                    cursor = close + 1
                if cursor >= len(tokens) or tokens[cursor].upper != "AS":
                    break
                cursor += 1
                if cursor >= len(tokens) or tokens[cursor].value != "(":
                    break
                close = cls._matching_parenthesis(tokens, cursor)
                if close is None:
                    break
                body = tokens[cursor + 1 : close]
                if cls._cte_body_references_name(body, name):
                    recursive_names.add((with_index, name))
                cursor = close + 1
                if cursor >= len(tokens) or tokens[cursor].value != ",":
                    break
                cursor += 1
        return len(recursive_names)

    @staticmethod
    def _matching_parenthesis(tokens: list[Token], opening: int) -> int | None:
        depth = 0
        for index in range(opening, len(tokens)):
            if tokens[index].value == "(":
                depth += 1
            elif tokens[index].value == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _cte_body_references_name(tokens: list[Token], name: str) -> bool:
        # A relation reference is introduced by FROM/JOIN, or by a comma inside
        # a FROM list.  The first two cover the canonical Db2 recursive form and
        # avoid mistaking a column or alias bearing the CTE name for recursion.
        for index, token in enumerate(tokens):
            if token.upper != name:
                continue
            previous = tokens[index - 1].upper if index else ""
            if previous in {"FROM", "JOIN"}:
                return True
        return False

    @staticmethod
    def _join_breakdown(tokens: list[Token]) -> tuple[int, int, int, int, int, int]:
        counts = {"INNER": 0, "LEFT": 0, "RIGHT": 0, "FULL": 0, "CROSS": 0}
        join_count = 0
        for index, token in enumerate(tokens):
            if token.upper != "JOIN":
                continue
            join_count += 1
            cursor = index - 1
            while cursor >= 0 and tokens[cursor].upper == "OUTER":
                cursor -= 1
            qualifier = tokens[cursor].upper if cursor >= 0 else ""
            if qualifier in counts:
                counts[qualifier] += 1
            else:
                counts["INNER"] += 1
        return (
            join_count,
            counts["INNER"],
            counts["LEFT"],
            counts["RIGHT"],
            counts["FULL"],
            counts["CROSS"],
        )

    @staticmethod
    def _counter_invariant_findings(query: QueryComplexityProfile) -> list[Finding]:
        decomposed = (
            query.inner_join_count
            + query.left_join_count
            + query.right_join_count
            + query.full_join_count
            + query.cross_join_count
        )
        if decomposed == query.join_count:
            return []
        return [
            Finding(
                code="COUNTER_INVARIANT_VIOLATION",
                severity=Severity.ERROR,
                message=(
                    "Join-kind counters do not reconcile to join_count: "
                    f"{decomposed} != {query.join_count}."
                ),
            )
        ]

    def _control_profile(self, tokens: list[Token], statements: list[list[Token]]) -> ControlComplexityProfile:
        uppers = [t.upper for t in tokens]
        continue_handlers = self._count_sequence(tokens, ("DECLARE", "CONTINUE", "HANDLER"))
        exit_handlers = self._count_sequence(tokens, ("DECLARE", "EXIT", "HANDLER"))
        undo_handlers = self._count_sequence(tokens, ("DECLARE", "UNDO", "HANDLER"))
        handler_count = continue_handlers + exit_handlers + undo_handlers

        for_count = sum(1 for i, token in enumerate(tokens) if token.upper == "FOR" and self._is_procedural_for(tokens, i))
        while_count = sum(1 for i, token in enumerate(tokens) if token.upper == "WHILE" and not (i > 0 and tokens[i - 1].upper == "END"))
        repeat_count = sum(1 for i, token in enumerate(tokens) if token.upper == "REPEAT" and not (i > 0 and tokens[i - 1].upper == "END"))
        generic_loop_count = sum(1 for i, token in enumerate(tokens) if token.upper == "LOOP" and not (i > 0 and tokens[i - 1].upper == "END"))
        loop_count = for_count + while_count + repeat_count + generic_loop_count

        # CASE expressions and MERGE WHEN arms are query semantics, not procedural CASE arms.
        procedural_case_statements = [statement for statement in statements if statement and statement[0].upper == "CASE"]
        case_count = len(procedural_case_statements)
        case_when_arm_count = sum(sum(1 for token in statement if token.upper == "WHEN") for statement in procedural_case_statements)
        merge_when_arm_count = sum(
            sum(1 for token in statement if token.upper == "WHEN")
            for statement in statements
            if statement and statement[0].upper == "MERGE"
        )

        nesting = 0
        max_nesting = 0
        for i, token in enumerate(tokens):
            starts_control = (
                token.upper in {"IF", "WHILE", "REPEAT", "LOOP"}
                or (token.upper == "FOR" and self._is_procedural_for(tokens, i))
                or (token.upper == "CASE" and any(statement and statement[0] is token for statement in procedural_case_statements))
            )
            if starts_control and not (i > 0 and tokens[i - 1].upper == "END"):
                nesting += 1
                max_nesting = max(max_nesting, nesting)
            elif token.upper == "END" and nesting:
                nesting -= 1

        cursor_declarations = sum(
            1
            for i in range(len(tokens))
            if tokens[i].upper == "DECLARE" and any(t.upper == "CURSOR" for t in tokens[i : min(i + 8, len(tokens))])
        )
        fetch_count = uppers.count("FETCH")
        return ControlComplexityProfile(
            if_count=sum(1 for i, t in enumerate(tokens) if t.upper == "IF" and (i == 0 or tokens[i - 1].upper != "END")),
            elseif_count=uppers.count("ELSEIF"),
            case_count=case_count,
            case_when_arm_count=case_when_arm_count,
            merge_when_arm_count=merge_when_arm_count,
            handler_count=handler_count,
            continue_handler_count=continue_handlers,
            exit_handler_count=exit_handlers,
            undo_handler_count=undo_handlers,
            loop_count=loop_count,
            for_count=for_count,
            while_count=while_count,
            repeat_count=repeat_count,
            generic_loop_count=generic_loop_count,
            max_control_nesting=max_nesting,
            cursor_declaration_count=cursor_declarations,
            fetch_count=fetch_count,
            cursor_loop_count=min(cursor_declarations, loop_count) if fetch_count else 0,
        )

    @staticmethod
    def _is_procedural_for(tokens: list[Token], index: int) -> bool:
        previous = tokens[index - 1].upper if index > 0 else ""
        following = tokens[index + 1].upper if index + 1 < len(tokens) else ""
        if previous in {"CURSOR", "HANDLER", "VALUE", "VALUES"}:
            return False
        if following in {"READ", "UPDATE", "FETCH"}:
            return False
        # Sequence acquisition uses ``NEXT VALUE FOR sequence_name`` and is not
        # a procedural FOR-loop.
        if index >= 2 and tokens[index - 2].upper == "NEXT" and previous == "VALUE":
            return False
        # DECLARE ... HANDLER FOR and DECLARE ... CURSOR FOR may have intervening tokens.
        window = {token.upper for token in tokens[max(0, index - 5) : index]}
        if "DECLARE" in window and ("HANDLER" in window or "CURSOR" in window):
            return False
        return True

    def _effect_inventory(
        self,
        tokens: list[Token],
        statements: list[list[Token]],
        header: ProcedureHeader,
        code_line_count: int,
    ) -> EffectInventory:
        uppers = [token.upper for token in tokens]
        out_names = set(header.out_parameter_names) | set(header.inout_parameter_names)
        derivations: dict[str, set[str]] = defaultdict(set)
        set_count = 0
        out_count = 0
        computed_count = 0
        effect_lines: list[int] = []

        i = 0
        while i < len(tokens):
            if tokens[i].upper == "SET" and i + 2 < len(tokens):
                target = tokens[i + 1].upper
                set_count += 1
                end = i + 2
                while end < len(tokens) and tokens[end].value != ";":
                    end += 1
                expression_tokens = (
                    tokens[i + 3 : end]
                    if i + 2 < len(tokens) and tokens[i + 2].value in {"=", ":="}
                    else tokens[i + 2 : end]
                )
                normalized = " ".join(
                    token.upper if token.kind == TokenKind.WORD else token.value
                    for token in expression_tokens
                ).strip()
                if target in out_names:
                    out_count += 1
                    if self._is_computed_expression(expression_tokens):
                        computed_count += 1
                        derivations[target].add(normalized or "<EMPTY>")
                    effect_lines.append(tokens[i].line)
                i = max(i + 1, end)
                continue
            i += 1

        def statement_starts(keyword: str) -> list[list[Token]]:
            return [statement for statement in statements if statement and statement[0].upper == keyword]

        signal = len(statement_starts("SIGNAL"))
        resignal = len(statement_starts("RESIGNAL"))
        dml = sum(len(statement_starts(keyword)) for keyword in ("INSERT", "UPDATE", "DELETE", "MERGE"))
        commit = len(statement_starts("COMMIT"))
        rollback = len(statement_starts("ROLLBACK"))
        for keyword in ("SIGNAL", "RESIGNAL", "INSERT", "UPDATE", "DELETE", "MERGE", "COMMIT", "ROLLBACK"):
            effect_lines.extend(statement[0].line for statement in statement_starts(keyword))

        direct = out_count + signal + resignal + dml
        first_line = min(effect_lines) if effect_lines else None
        return EffectInventory(
            set_assignment_count=set_count,
            out_assignment_count=out_count,
            computed_out_assignment_count=computed_count,
            signal_count=signal,
            resignal_count=resignal,
            call_count=uppers.count("CALL"),
            prepare_count=uppers.count("PREPARE"),
            execute_count=uppers.count("EXECUTE"),
            execute_immediate_count=self._count_sequence(tokens, ("EXECUTE", "IMMEDIATE")),
            commit_count=commit,
            rollback_count=rollback,
            dml_effect_count=dml,
            direct_effect_site_count=direct,
            first_effect_line=first_line,
            shared_prologue_code_lines=(max(0, first_line - 1) if first_line else code_line_count),
            computed_output_derivations={name: tuple(sorted(values)) for name, values in derivations.items()},
        )

    @staticmethod
    def _is_computed_expression(tokens: list[Token]) -> bool:
        significant = [t for t in tokens if t.value not in {"(", ")"}]
        if not significant:
            return False
        if len(significant) == 1:
            token = significant[0]
            if token.kind in {TokenKind.STRING, TokenKind.NUMBER} or token.upper in LITERAL_WORDS:
                return False
        return True

    def _eligibility(
        self,
        header: ProcedureHeader,
        code_lines: int,
        query: QueryComplexityProfile,
        control: ControlComplexityProfile,
        effects: EffectInventory,
        findings: list[Finding],
    ) -> tuple[Eligibility, list[str]]:
        reasons: list[str] = []
        if header.name is None or any(f.severity == Severity.ERROR for f in findings):
            return Eligibility.POC_INELIGIBLE, ["A procedure declaration or lexically valid source is required."]
        if code_lines > self.budgets.max_source_lines:
            reasons.append(f"Code lines {code_lines} exceed Phase 1 limit {self.budgets.max_source_lines}.")
        if effects.prepare_count or effects.execute_immediate_count:
            reasons.append("Dynamic SQL is outside Phase 1 slicing scope.")
        if query.recursive_cte_count:
            reasons.append("Recursive CTE is outside Phase 1 slicing scope.")
        if reasons:
            return Eligibility.POC_PARSE_ONLY, reasons
        if control.handler_count or control.loop_count or control.cursor_declaration_count:
            if control.handler_count:
                reasons.append("Handler regions require later semantic analysis.")
            if control.loop_count:
                reasons.append("Loop regions require later summary contracts.")
            if control.cursor_declaration_count:
                reasons.append("Cursor behavior requires later CFG/summary analysis.")
            return Eligibility.POC_PARTIAL_SLICE_EXPECTED, reasons
        return Eligibility.POC_FULLY_ELIGIBLE, ["Within the bounded Phase 1 lexical eligibility profile."]

    @staticmethod
    def _count_join(tokens: list[Token], kind: str) -> int:
        return sum(1 for i in range(len(tokens) - 1) if tokens[i].upper == kind and tokens[i + 1].upper in {"OUTER", "JOIN"})

    @staticmethod
    def _find_sequence(tokens: list[Token], sequence: tuple[str, ...]) -> int | None:
        for i in range(len(tokens) - len(sequence) + 1):
            if tuple(token.upper for token in tokens[i : i + len(sequence)]) == sequence:
                return i
        return None

    @classmethod
    def _contains_sequence(cls, tokens: list[Token], sequence: tuple[str, ...]) -> bool:
        return cls._find_sequence(tokens, sequence) is not None

    @classmethod
    def _count_sequence(cls, tokens: list[Token], sequence: tuple[str, ...]) -> int:
        count = 0
        start = 0
        while start < len(tokens):
            found = cls._find_sequence(tokens[start:], sequence)
            if found is None:
                break
            count += 1
            start += found + len(sequence)
        return count

    @staticmethod
    def _value_after_keyword(tokens: list[Token], keyword: str) -> str | None:
        for i, token in enumerate(tokens[:-1]):
            if token.upper == keyword:
                return tokens[i + 1].value.strip('"')
        return None

    @staticmethod
    def _value_after_sequence(tokens: list[Token], sequence: tuple[str, ...]) -> str | None:
        idx = InventoryAnalyzer._find_sequence(tokens, sequence)
        if idx is not None and idx + len(sequence) < len(tokens):
            return tokens[idx + len(sequence)].value.strip('"')
        return None


def write_report(report: ProcedureInventory | Db2ScriptInventoryReport | EstateInventoryReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report.model_dump_json(indent=2), encoding="utf-8", newline="\n")


def write_markdown(report: ProcedureInventory, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Gate 0 Inventory — {report.source.filename}",
        "",
        f"- **Digest:** `{report.source.content_digest}`",
        f"- **Procedure:** `{report.procedure.schema_name or '<unqualified>'}.{report.procedure.name or '<unknown>'}`",
        f"- **Code lines:** {report.source.code_line_count}",
        f"- **Statements:** {report.statement_count}",
        f"- **Eligibility:** `{report.eligibility}`",
        f"- **Routine version:** `{report.procedure.routine_version_id or '<not declared>'}`",
        f"- **COMMIT ON RETURN:** `{report.procedure.commit_on_return or '<not declared>'}`",
        "",
        "## Complexity",
        "",
        f"- Queries: {report.query_complexity.query_count}",
        f"- Joins: {report.query_complexity.join_count}",
        f"- Subqueries: {report.query_complexity.subquery_count}",
        f"- Weighted query score: {report.query_complexity.weighted_score}",
        f"- Branches: IF={report.control_complexity.if_count}, ELSEIF={report.control_complexity.elseif_count}, CASE arms={report.control_complexity.case_when_arm_count}, MERGE WHEN arms={report.control_complexity.merge_when_arm_count}",
        f"- Handlers: {report.control_complexity.handler_count}",
        f"- Loops: {report.control_complexity.loop_count}",
        f"- Calls: {report.effects.call_count}",
        f"- Dynamic SQL: {'yes' if report.dynamic_sql_present else 'no'}",
        f"- Direct effect sites: {report.effects.direct_effect_site_count}",
        f"- Computed OUT assignments: {report.effects.computed_out_assignment_count}",
        "",
        "## Eligibility Reasons",
        "",
    ]
    lines.extend(f"- {reason}" for reason in report.eligibility_reasons)
    lines.extend(["", "## Findings", ""])
    if report.findings:
        lines.extend(f"- **{finding.severity} `{finding.code}`:** {finding.message}" for finding in report.findings)
    else:
        lines.append("- None")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
