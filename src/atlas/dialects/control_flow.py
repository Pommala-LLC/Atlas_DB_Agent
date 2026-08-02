from __future__ import annotations

from collections import defaultdict, deque
import re

from atlas.core.models import (
    EdgeKind,
    EffectModality,
    SemanticEdge,
    SemanticFinding,
    SemanticNode,
    SemanticNodeKind,
)


_TERMINAL_KINDS = {SemanticNodeKind.RETURN, SemanticNodeKind.ERROR_RAISE, SemanticNodeKind.GOTO}
_POTENTIALLY_FAILING = {
    SemanticNodeKind.QUERY,
    SemanticNodeKind.SELECT_INTO,
    SemanticNodeKind.RESULT_SET,
    SemanticNodeKind.INSERT,
    SemanticNodeKind.UPDATE,
    SemanticNodeKind.DELETE,
    SemanticNodeKind.MERGE,
    SemanticNodeKind.UPSERT,
    SemanticNodeKind.CALL,
    SemanticNodeKind.DYNAMIC_SQL,
    SemanticNodeKind.CURSOR_OPEN,
    SemanticNodeKind.CURSOR_FETCH,
    SemanticNodeKind.CURSOR_CLOSE,
    SemanticNodeKind.ERROR_RAISE,
    SemanticNodeKind.DDL,
    SemanticNodeKind.TRUNCATE,
    SemanticNodeKind.LOCK,
    SemanticNodeKind.BULK_OPERATION,
}


def refine_control_flow(
    nodes: list[SemanticNode],
    edges: list[SemanticEdge],
    findings: list[SemanticFinding],
    *,
    entry_id: str,
    exit_id: str,
) -> tuple[list[SemanticNode], list[SemanticEdge], list[SemanticFinding]]:
    """Refine parser-order edges into a deterministic bounded CFG.

    The parser still preserves every source statement. This pass removes false
    fall-through from transfers, adds joins, loop exits, handler causality,
    call-target and data-dependency evidence, and marks unreachable statements.
    """

    source_nodes = [node for node in nodes if node.kind is not SemanticNodeKind.CALL_TARGET]
    by_id = {node.node_id: node for node in source_nodes}
    position = {node.node_id: index for index, node in enumerate(source_nodes)}

    def ancestors(node: SemanticNode) -> tuple[str, ...]:
        result: list[str] = []
        current = node.parent_ref
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            result.append(current)
            parent = by_id.get(current)
            current = parent.parent_ref if parent else None
        return tuple(result)

    ancestry = {node.node_id: ancestors(node) for node in source_nodes}

    def is_descendant(node_id: str, ancestor_id: str) -> bool:
        return ancestor_id in ancestry.get(node_id, ())

    control_edges: list[SemanticEdge] = []
    for edge in edges:
        source = by_id.get(edge.source_ref)
        target = by_id.get(edge.target_ref)
        if source is None:
            continue
        if source.kind in _TERMINAL_KINDS:
            continue
        if source.kind is SemanticNodeKind.LOOP_CONTROL:
            continue
        if target and target.kind is SemanticNodeKind.ERROR_HANDLER:
            target_upper = target.text.strip().upper()
            if edge.kind is EdgeKind.NEXT and target_upper.startswith(("BEGIN CATCH", "EXCEPTION", "WHEN ")):
                continue
        control_edges.append(edge)

    def add_edge(source: str, target: str, kind: EdgeKind, condition: str | None = None) -> None:
        if source == target and kind is not EdgeKind.LOOP_BACK:
            return
        key = (source, target, kind, condition)
        if any((e.source_ref, e.target_ref, e.kind, e.condition_text) == key for e in control_edges):
            return
        control_edges.append(
            SemanticEdge(
                edge_id="pending",
                source_ref=source,
                target_ref=target,
                kind=kind,
                condition_text=condition,
            )
        )

    labels: dict[str, str] = {}
    for node in source_nodes:
        if node.kind is SemanticNodeKind.LABEL:
            name = node.attributes.get("label_name")
            if isinstance(name, str):
                labels[name.upper()] = node.node_id

    def first_after(index: int) -> str:
        return source_nodes[index + 1].node_id if index + 1 < len(source_nodes) else exit_id

    def enclosing_loop(node: SemanticNode) -> SemanticNode | None:
        for ref in ancestry.get(node.node_id, ()):
            candidate = by_id.get(ref)
            if candidate and candidate.kind is SemanticNodeKind.LOOP:
                return candidate
        return None

    def loop_end(loop: SemanticNode) -> SemanticNode | None:
        """Return the structural terminus of a loop body.

        Db2/Oracle/PostgreSQL/MySQL normally use explicit END LOOP/WHILE/REPEAT.
        T-SQL closes the BEGIN owned by WHILE with a generic END.  The last
        descendant block before control leaves the loop region is therefore the
        dialect-neutral boundary.
        """
        start = position[loop.node_id]
        for candidate in source_nodes[start + 1 :]:
            if candidate.kind is not SemanticNodeKind.BLOCK:
                continue
            upper = candidate.text.strip().upper()
            if not upper.startswith("END"):
                continue
            if candidate.parent_ref != loop.node_id and not is_descendant(candidate.node_id, loop.node_id):
                continue
            candidate_index = position[candidate.node_id]
            following = source_nodes[candidate_index + 1] if candidate_index + 1 < len(source_nodes) else None
            explicit = upper.startswith(("END LOOP", "END WHILE", "END REPEAT"))
            leaves_region = following is None or not is_descendant(following.node_id, loop.node_id)
            if explicit or leaves_region:
                return candidate
        return None

    # Explicit transfers and loop exits.
    handlers = [node for node in source_nodes if node.kind is SemanticNodeKind.ERROR_HANDLER]

    def handler_scope(handler: SemanticNode) -> str | None:
        for ref in ancestry.get(handler.node_id, ()):
            candidate = by_id.get(ref)
            if candidate and candidate.kind is SemanticNodeKind.BLOCK and candidate.text.strip().upper().startswith("BEGIN"):
                return candidate.node_id
        return handler.parent_ref

    handler_scopes = [(handler, handler_scope(handler)) for handler in handlers]

    def exception_keys(node: SemanticNode) -> set[str]:
        keys: set[str] = set()
        upper = node.text.strip().upper()
        if node.error_code:
            keys.add(node.error_code.upper())
        named_raise = re.match(r"^RAISE\s+([A-Z_$#][A-Z0-9_$#]*)\s*;?$", upper)
        if named_raise:
            keys.add(named_raise.group(1))
        if node.kind is SemanticNodeKind.SELECT_INTO:
            keys.update({"NO_DATA_FOUND", "NOT FOUND"})
            if "STRICT" in upper or "SELECT" in upper:
                keys.add("TOO_MANY_ROWS")
        if node.kind is SemanticNodeKind.CURSOR_FETCH:
            keys.update({"NO_DATA_FOUND", "NOT FOUND"})
        return keys

    def handler_candidates(node: SemanticNode, *, conservative: bool) -> list[tuple[int, int, SemanticNode]]:
        node_ancestors = set(ancestry.get(node.node_id, ()))
        if any(by_id.get(ref) and by_id[ref].kind is SemanticNodeKind.ERROR_HANDLER for ref in node_ancestors):
            return []
        keys = exception_keys(node)
        candidates: list[tuple[int, int, SemanticNode]] = []
        for handler, scope in handler_scopes:
            if scope is None:
                continue
            if scope != node.parent_ref and scope not in node_ancestors:
                continue
            if handler.node_id in node_ancestors or node.node_id == handler.node_id:
                continue
            upper = handler.text.strip().upper()
            condition = (handler.condition_text or upper).upper()
            specificity = 0
            if keys and any(key in condition for key in keys):
                specificity = 6
            elif "NOT FOUND" in upper or "NO_DATA_FOUND" in upper:
                if node.kind not in {SemanticNodeKind.CURSOR_FETCH, SemanticNodeKind.SELECT_INTO, SemanticNodeKind.QUERY}:
                    continue
                specificity = 5
            elif any(marker in upper for marker in ("SQLEXCEPTION", "OTHERS", "BEGIN CATCH")):
                specificity = 2
            elif upper == "EXCEPTION" or upper.startswith("EXCEPTION "):
                # Structural exception-section roots are not executable arms.
                continue
            elif upper.startswith("WHEN "):
                if not conservative:
                    continue
                # Static analysis cannot prove which vendor exception a DML,
                # dynamic SQL, or bulk operation may raise. Retain every named
                # arm in the nearest exception section as a MAY path.
                specificity = 3
            else:
                specificity = 1
            depth = len(ancestry.get(handler.node_id, ()))
            candidates.append((depth, specificity, handler))
        if not candidates:
            return []
        nearest_depth = max(item[0] for item in candidates)
        return [item for item in candidates if item[0] == nearest_depth]

    def applicable_handler(node: SemanticNode) -> SemanticNode | None:
        candidates = handler_candidates(node, conservative=False)
        return max(candidates, default=(0, 0, None), key=lambda item: item[1])[2]

    # Handler bodies are entered only on exceptional paths; normal control skips them.
    for handler in handlers:
        upper = handler.text.strip().upper()
        handler_index = position[handler.node_id]
        if upper.startswith("DECLARE ") and handler_index + 1 < len(source_nodes):
            begin = source_nodes[handler_index + 1]
            if begin.kind is SemanticNodeKind.BLOCK and begin.text.strip().upper().startswith("BEGIN") and begin.parent_ref == handler.node_id:
                end = next(
                    (
                        candidate
                        for candidate in source_nodes[handler_index + 2 :]
                        if candidate.kind is SemanticNodeKind.BLOCK
                        and candidate.text.strip().upper().startswith("END")
                        and (candidate.parent_ref == begin.node_id or begin.node_id in ancestry.get(candidate.node_id, ()))
                    ),
                    None,
                )
                if end:
                    add_edge(handler.node_id, first_after(position[end.node_id]), EdgeKind.NEXT, "HANDLER_DECLARATION")
        elif upper.startswith("BEGIN TRY"):
            end_try = next((candidate for candidate in source_nodes[handler_index + 1 :] if candidate.kind is SemanticNodeKind.BLOCK and candidate.text.strip().upper().startswith("END TRY")), None)
            begin_catch = next((candidate for candidate in source_nodes[handler_index + 1 :] if candidate.kind is SemanticNodeKind.ERROR_HANDLER and candidate.text.strip().upper().startswith("BEGIN CATCH")), None)
            if end_try and begin_catch:
                end_catch = next((candidate for candidate in source_nodes[position[begin_catch.node_id] + 1 :] if candidate.kind is SemanticNodeKind.BLOCK and candidate.text.strip().upper().startswith("END CATCH")), None)
                if end_catch:
                    add_edge(end_try.node_id, first_after(position[end_catch.node_id]), EdgeKind.NEXT, "TRY_SUCCESS")
        elif upper.startswith("EXCEPTION"):
            previous = source_nodes[handler_index - 1] if handler_index > 0 else None
            end = next(
                (
                    candidate
                    for candidate in source_nodes[handler_index + 1 :]
                    if candidate.kind is SemanticNodeKind.BLOCK
                    and candidate.text.strip().upper().startswith("END")
                    and handler.parent_ref in ({candidate.parent_ref} | set(ancestry.get(candidate.node_id, ())))
                ),
                None,
            )
            if previous and end and previous.kind not in _TERMINAL_KINDS:
                add_edge(previous.node_id, end.node_id, EdgeKind.NEXT, "NO_EXCEPTION")

    for node in source_nodes:
        if node.kind is SemanticNodeKind.RETURN:
            add_edge(node.node_id, exit_id, EdgeKind.BRANCH, "RETURN")
        elif node.kind is SemanticNodeKind.ERROR_RAISE:
            handler = applicable_handler(node)
            add_edge(node.node_id, handler.node_id if handler else exit_id, EdgeKind.EXCEPTION, node.error_code or "RAISE")
        elif node.kind is SemanticNodeKind.GOTO:
            label = node.attributes.get("label_name")
            target = labels.get(str(label).upper()) if label else None
            if target:
                add_edge(node.node_id, target, EdgeKind.BRANCH, f"GOTO {label}")
            else:
                findings.append(
                    SemanticFinding(
                        code="UNRESOLVED_GOTO_LABEL",
                        severity="ERROR",
                        message=f"GOTO target {label!r} did not resolve to a local label.",
                        source_span=node.source_span,
                        consequence="Control-flow completeness is partial.",
                    )
                )
        elif node.kind is SemanticNodeKind.LOOP_CONTROL:
            control = str(node.attributes.get("control_kind", "")).upper().rstrip(";")
            target_label = node.attributes.get("target_label")
            if isinstance(target_label, str) and target_label:
                label_ref = labels.get(target_label.upper())
                if label_ref:
                    label_node = by_id[label_ref]
                    if control == "ITERATE":
                        labelled_loop = next(
                            (
                                candidate
                                for candidate in source_nodes[position[label_ref] + 1 :]
                                if candidate.kind is SemanticNodeKind.LOOP
                                and (candidate.parent_ref == label_ref or label_ref in ancestry.get(candidate.node_id, ()))
                            ),
                            None,
                        )
                        if labelled_loop:
                            add_edge(node.node_id, labelled_loop.node_id, EdgeKind.LOOP_BACK, f"ITERATE {target_label}")
                            continue
                    end_label = next(
                        (
                            candidate
                            for candidate in source_nodes[position[label_ref] + 1 :]
                            if candidate.kind is SemanticNodeKind.BLOCK
                            and candidate.text.strip().upper().rstrip(";$").startswith(f"END {target_label.upper()}")
                        ),
                        None,
                    )
                    if end_label:
                        add_edge(node.node_id, first_after(position[end_label.node_id]), EdgeKind.BRANCH, f"{control} {target_label}")
                        continue
            loop = enclosing_loop(node)
            if loop is None:
                findings.append(
                    SemanticFinding(
                        code="LOOP_CONTROL_TARGET_UNRESOLVED",
                        severity="ERROR",
                        message=f"{control or 'Loop control'} target could not be resolved.",
                        source_span=node.source_span,
                        consequence="The transfer target is unresolved.",
                    )
                )
                continue
            if control in {"CONTINUE", "ITERATE"}:
                add_edge(node.node_id, loop.node_id, EdgeKind.LOOP_BACK, control)
            else:
                end = loop_end(loop)
                target = first_after(position[end.node_id]) if end else exit_id
                add_edge(node.node_id, target, EdgeKind.BRANCH, control or "LOOP_EXIT")

    # Loop false exits.
    for loop in [node for node in source_nodes if node.kind is SemanticNodeKind.LOOP]:
        end = loop_end(loop)
        target = first_after(position[end.node_id]) if end else exit_id
        add_edge(loop.node_id, target, EdgeKind.FALSE, loop.condition_text or "LOOP_EXIT")

    # IF/CASE branch joins.  Region ancestry is the source of truth, so this
    # also handles T-SQL BEGIN/END and single-statement IF forms.
    for root in [node for node in source_nodes if node.kind in {SemanticNodeKind.CONDITION, SemanticNodeKind.CASE}]:
        if root.kind is SemanticNodeKind.CONDITION and str(root.attributes.get("branch_kind", "")) in {"ELSE", "ELSIF", "ELSEIF", "WHEN"}:
            continue
        start = position[root.node_id]
        subtree = [
            node
            for node in source_nodes[start + 1 :]
            if is_descendant(node.node_id, root.node_id)
        ]
        if not subtree:
            continue
        last_subtree_index = max(position[node.node_id] for node in subtree)
        join_target = first_after(last_subtree_index)
        branch_nodes = [root]
        branch_nodes.extend(
            node
            for node in source_nodes[start + 1 : last_subtree_index + 1]
            if node.kind is SemanticNodeKind.CONDITION
            and node.parent_ref == root.node_id
            and str(node.attributes.get("branch_kind", "")) in {"ELSE", "ELSIF", "ELSEIF", "WHEN"}
        )
        for branch_index, branch in enumerate(branch_nodes):
            begin = position[branch.node_id] + 1
            stop = position[branch_nodes[branch_index + 1].node_id] if branch_index + 1 < len(branch_nodes) else last_subtree_index + 1
            body = [
                node
                for node in source_nodes[begin:stop]
                if is_descendant(node.node_id, branch.node_id)
                and node.kind is not SemanticNodeKind.BLOCK
            ]
            if body:
                last = body[-1]
                if last.kind not in _TERMINAL_KINDS and last.kind is not SemanticNodeKind.LOOP_CONTROL:
                    add_edge(last.node_id, join_target, EdgeKind.BRANCH, "JOIN")
        has_else = any(str(branch.attributes.get("branch_kind", "")) == "ELSE" for branch in branch_nodes)
        if root.kind is SemanticNodeKind.CONDITION and not has_else:
            add_edge(root.node_id, join_target, EdgeKind.FALSE, root.condition_text)
        if root.kind is SemanticNodeKind.CASE:
            add_edge(root.node_id, join_target, EdgeKind.BRANCH, "NO_MATCH")

    # Exception causality from statements in the declaring scope to the nearest handler.
    for node in source_nodes:
        if node.kind not in _POTENTIALLY_FAILING or node.kind in {SemanticNodeKind.ERROR_HANDLER, SemanticNodeKind.ERROR_RAISE}:
            continue
        for _depth, _specificity, handler in handler_candidates(node, conservative=True):
            add_edge(node.node_id, handler.node_id, EdgeKind.EXCEPTION, handler.condition_text or handler.text.strip())

    # External call targets remain explicit local graph nodes.
    all_nodes = list(source_nodes)
    target_nodes: dict[str, str] = {}
    for node in source_nodes:
        if node.kind is not SemanticNodeKind.CALL or not node.call_target:
            continue
        target_id = target_nodes.get(node.call_target)
        if target_id is None:
            target_id = f"call-target-{len(target_nodes) + 1:04d}"
            target_nodes[node.call_target] = target_id
            all_nodes.append(
                SemanticNode(
                    node_id=target_id,
                    kind=SemanticNodeKind.CALL_TARGET,
                    text=f"EXTERNAL ROUTINE {node.call_target}",
                    source_span=node.source_span,
                    target_name=node.call_target,
                    modality=EffectModality.MAY,
                    attributes={"external": True},
                )
            )
        add_edge(node.node_id, target_id, EdgeKind.CALLS, node.call_target)

    # Intra-routine last-writer dependencies.
    last_writer: dict[str, str] = {}
    for node in source_nodes:
        for variable in node.variable_reads:
            writer = last_writer.get(variable)
            if writer and writer != node.node_id:
                add_edge(writer, node.node_id, EdgeKind.DATA_DEPENDENCY, variable)
        for variable in node.variable_writes:
            last_writer[variable] = node.node_id

    # Renumber and deduplicate all edge classes.
    unique: list[SemanticEdge] = []
    seen_edges: set[tuple[str, str, EdgeKind, str | None]] = set()
    for edge in control_edges:
        key = (edge.source_ref, edge.target_ref, edge.kind, edge.condition_text)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique.append(
            edge.model_copy(update={"edge_id": f"edge-{len(unique) + 1:04d}"})
        )

    # Reachability ignores evidence-only CALLS and DATA_DEPENDENCY edges.
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in unique:
        if edge.kind not in {EdgeKind.CALLS, EdgeKind.DATA_DEPENDENCY}:
            adjacency[edge.source_ref].append(edge.target_ref)
    reachable = {entry_id}
    queue: deque[str] = deque([entry_id])
    while queue:
        source = queue.popleft()
        for target in adjacency.get(source, ()):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)

    # EXCEPTION is a structural root whose WHEN child receives the actual
    # exceptional edge.  Treat the root as reachable whenever one of its
    # descendants is reachable, without inventing an executable edge.
    for node in source_nodes:
        if node.kind is SemanticNodeKind.ERROR_HANDLER and any(
            candidate.node_id in reachable and is_descendant(candidate.node_id, node.node_id)
            for candidate in source_nodes
        ):
            reachable.add(node.node_id)

    adjusted: list[SemanticNode] = []
    existing_unreachable = {finding.source_span.start_offset for finding in findings if finding.code == "UNREACHABLE_STATEMENT" and finding.source_span}
    for node in all_nodes:
        if node.kind in {SemanticNodeKind.ENTRY, SemanticNodeKind.EXIT, SemanticNodeKind.CALL_TARGET} or node.node_id in reachable:
            adjusted.append(node)
            continue
        adjusted.append(node.model_copy(update={"modality": EffectModality.UNKNOWN}))
        if node.kind in {SemanticNodeKind.BLOCK, SemanticNodeKind.ERROR_HANDLER}:
            continue
        if node.source_span.start_offset not in existing_unreachable:
            findings.append(
                SemanticFinding(
                    code="UNREACHABLE_STATEMENT",
                    severity="WARNING",
                    message="A statement has no reachable control-flow predecessor.",
                    source_span=node.source_span,
                    consequence="Its effects are retained as evidence but cannot be classified as executed on a reachable path.",
                )
            )

    return adjusted, unique, findings
