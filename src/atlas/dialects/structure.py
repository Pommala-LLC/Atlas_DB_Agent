from __future__ import annotations

from dataclasses import dataclass

from atlas.core.models import DialectId, EdgeKind, SemanticNodeKind


@dataclass(slots=True)
class RegionFrame:
    kind: str
    root_ref: str
    active_ref: str
    condition_text: str | None = None
    owner_kind: str | None = None
    owner_ref: str | None = None
    single_statement: bool = False
    statements_seen: int = 0


class StructuredRegionTracker:
    """Tracks procedural nesting without embedding dialect semantics in the application layer."""

    def __init__(self, dialect: DialectId) -> None:
        self.dialect = dialect
        self.frames: list[RegionFrame] = []

    def current_parent(self) -> str | None:
        return self.frames[-1].active_ref if self.frames else None

    def nearest(self, *kinds: str) -> RegionFrame | None:
        for frame in reversed(self.frames):
            if frame.kind in kinds:
                return frame
        return None

    def parent_for(self, kind: SemanticNodeKind, attrs: dict[str, object], upper: str) -> str | None:
        branch = str(attrs.get("branch_kind", ""))
        if kind is SemanticNodeKind.CONDITION and branch in {"ELSE", "ELSIF", "ELSEIF"}:
            frame = self.nearest("IF", "CASE") if branch == "ELSE" else self.nearest("IF")
            return frame.root_ref if frame else self.current_parent()
        if kind is SemanticNodeKind.CONDITION and branch == "WHEN":
            frame = self.nearest("CASE", "HANDLER")
            return frame.root_ref if frame else self.current_parent()
        if kind is SemanticNodeKind.ERROR_HANDLER and upper.startswith("BEGIN CATCH"):
            frame = self.nearest("TRY_CATCH")
            return frame.root_ref if frame else self.current_parent()
        if kind is SemanticNodeKind.ERROR_HANDLER and upper.startswith("WHEN "):
            frame = self.nearest("HANDLER")
            return frame.root_ref if frame else self.current_parent()
        return self.current_parent()

    def branch_edge(self, kind: SemanticNodeKind, attrs: dict[str, object], upper: str) -> tuple[str | None, EdgeKind, str | None]:
        branch = str(attrs.get("branch_kind", ""))
        condition = attrs.get("condition_text") if isinstance(attrs.get("condition_text"), str) else None
        if kind is SemanticNodeKind.CONDITION and branch in {"ELSE", "ELSIF", "ELSEIF"}:
            frame = self.nearest("IF", "CASE") if branch == "ELSE" else self.nearest("IF")
            if frame:
                # ELSE/ELSIF is reached from the immediately preceding branch,
                # not always from the original IF root.
                edge_kind = EdgeKind.BRANCH if frame.kind == "CASE" else EdgeKind.FALSE
                return frame.active_ref, edge_kind, frame.condition_text
        if kind is SemanticNodeKind.CONDITION and branch == "WHEN":
            frame = self.nearest("CASE", "HANDLER")
            if frame:
                return frame.root_ref, EdgeKind.BRANCH if frame.kind == "CASE" else EdgeKind.EXCEPTION, condition
        if kind is SemanticNodeKind.ERROR_HANDLER and upper.startswith("BEGIN CATCH"):
            frame = self.nearest("TRY_CATCH")
            if frame:
                return frame.root_ref, EdgeKind.EXCEPTION, "CATCH"
        if kind is SemanticNodeKind.ERROR_HANDLER and upper.startswith("WHEN "):
            frame = self.nearest("HANDLER")
            if frame:
                condition = attrs.get("condition_text") if isinstance(attrs.get("condition_text"), str) else upper
                return frame.root_ref, EdgeKind.EXCEPTION, condition
        return None, EdgeKind.NEXT, None

    def after_node(
        self,
        *,
        node_id: str,
        kind: SemanticNodeKind,
        attrs: dict[str, object],
        upper: str,
        next_upper: str | None,
    ) -> tuple[EdgeKind, str | None, list[RegionFrame]]:
        """Update region state and return edge kind/condition for the next ordinary node."""
        closed: list[RegionFrame] = []
        branch = str(attrs.get("branch_kind", ""))
        condition = attrs.get("condition_text") if isinstance(attrs.get("condition_text"), str) else None

        if kind is SemanticNodeKind.CONDITION:
            if branch in {"ELSIF", "ELSEIF", "ELSE"}:
                frame = self.nearest("IF", "CASE") if branch == "ELSE" else self.nearest("IF")
                if frame:
                    frame.active_ref = node_id
                    frame.condition_text = condition or frame.condition_text
                    frame.statements_seen = 0
                    if frame.kind == "CASE":
                        return EdgeKind.BRANCH, condition, closed
                    return EdgeKind.TRUE if branch != "ELSE" else EdgeKind.NEXT, condition, closed
            elif branch == "WHEN":
                frame = self.nearest("CASE", "HANDLER")
                if frame:
                    frame.active_ref = node_id
                    frame.condition_text = condition
                    frame.statements_seen = 0
                    return EdgeKind.BRANCH if frame.kind == "CASE" else EdgeKind.EXCEPTION, condition, closed
            else:
                expects_block = bool(next_upper and next_upper.startswith("BEGIN"))
                frame = RegionFrame(
                    kind="IF",
                    root_ref=node_id,
                    active_ref=node_id,
                    condition_text=condition,
                    single_statement=self.dialect is DialectId.SQLSERVER_TSQL and not expects_block,
                )
                self.frames.append(frame)
                return EdgeKind.TRUE, condition, closed

        if kind is SemanticNodeKind.CASE:
            self.frames.append(RegionFrame(kind="CASE", root_ref=node_id, active_ref=node_id, condition_text=condition))
            return EdgeKind.BRANCH, condition, closed

        if kind is SemanticNodeKind.LOOP:
            expects_block = bool(next_upper and next_upper.startswith("BEGIN"))
            self.frames.append(RegionFrame(
                kind="LOOP",
                root_ref=node_id,
                active_ref=node_id,
                condition_text=condition or upper,
                single_statement=self.dialect is DialectId.SQLSERVER_TSQL and not expects_block,
            ))
            return EdgeKind.LOOP_BODY, condition, closed

        if kind is SemanticNodeKind.ERROR_HANDLER:
            inline_declared_handler = (
                self.dialect in {DialectId.MYSQL_STORED_PROGRAM, DialectId.DB2_SQL_PL}
                and upper.startswith("DECLARE ")
                and " HANDLER " in f" {upper} "
                and not (next_upper and next_upper.startswith("BEGIN"))
            )
            if inline_declared_handler:
                return EdgeKind.NEXT, None, closed
            if upper.startswith("BEGIN TRY"):
                self.frames.append(RegionFrame(kind="TRY_CATCH", root_ref=node_id, active_ref=node_id, condition_text="TRY"))
                return EdgeKind.NEXT, None, closed
            if upper.startswith("BEGIN CATCH"):
                frame = self.nearest("TRY_CATCH")
                if frame:
                    frame.active_ref = node_id
                    frame.condition_text = "CATCH"
                    frame.statements_seen = 0
                    return EdgeKind.EXCEPTION, "CATCH", closed
            if upper.startswith("WHEN "):
                frame = self.nearest("HANDLER")
                if frame:
                    frame.active_ref = node_id
                    frame.condition_text = condition
                    frame.statements_seen = 0
                    return EdgeKind.EXCEPTION, condition, closed
            self.frames.append(RegionFrame(kind="HANDLER", root_ref=node_id, active_ref=node_id, condition_text=upper))
            return EdgeKind.EXCEPTION, upper, closed

        if kind is SemanticNodeKind.BLOCK:
            if upper.startswith("BEGIN") and not upper.startswith(("BEGIN TRY", "BEGIN CATCH", "BEGIN TRAN")):
                owner = self.frames[-1] if self.frames else None
                self.frames.append(RegionFrame(
                    kind="BLOCK",
                    root_ref=node_id,
                    active_ref=node_id,
                    owner_kind=owner.kind if owner else None,
                    owner_ref=owner.root_ref if owner else None,
                ))
                return EdgeKind.NEXT, None, closed
            if upper.startswith("END"):
                closed.extend(self._close_for_end(upper, next_upper))
                return EdgeKind.NEXT, None, closed

        # Close T-SQL single-statement IF/WHILE after its one body statement.
        if self.dialect is DialectId.SQLSERVER_TSQL and self.frames:
            frame = self.frames[-1]
            if frame.single_statement and kind not in {SemanticNodeKind.BLOCK, SemanticNodeKind.CONDITION}:
                frame.statements_seen += 1
                if frame.statements_seen >= 1:
                    closed.append(self.frames.pop())

        return EdgeKind.NEXT, None, closed

    def _close_for_end(self, upper: str, next_upper: str | None) -> list[RegionFrame]:
        closed: list[RegionFrame] = []
        normalized = upper.rstrip(";$").strip()
        explicit = None
        if normalized.startswith("END IF"):
            explicit = "IF"
        elif normalized.startswith(("END LOOP", "END WHILE", "END REPEAT")):
            explicit = "LOOP"
        elif normalized.startswith("END CASE"):
            explicit = "CASE"
        elif normalized.startswith("END CATCH"):
            explicit = "TRY_CATCH"
        elif normalized.startswith("END TRY"):
            # TRY stays open until BEGIN CATCH/END CATCH.
            return closed

        if explicit:
            while self.frames:
                frame = self.frames.pop()
                closed.append(frame)
                if frame.kind == explicit:
                    break
            return closed

        if self.frames and self.frames[-1].kind == "BLOCK":
            block = self.frames.pop()
            closed.append(block)
            if block.owner_kind == "HANDLER":
                owner = self.nearest("HANDLER")
                if owner and owner.root_ref == block.owner_ref:
                    closed.append(self.frames.pop())
            elif self.dialect is DialectId.SQLSERVER_TSQL and block.owner_kind:
                owner = self.nearest(block.owner_kind)
                if owner and owner.root_ref == block.owner_ref:
                    if block.owner_kind == "IF" and next_upper and next_upper.startswith("ELSE"):
                        return closed
                    closed.append(self.frames.pop())
            return closed

        if self.frames:
            top = self.frames.pop()
            closed.append(top)
            # Oracle/PLpgSQL EXCEPTION sections close together with their declaring block.
            if top.kind == "HANDLER" and self.frames and self.frames[-1].kind == "BLOCK":
                closed.append(self.frames.pop())
        return closed

    def drain(self) -> list[RegionFrame]:
        remaining = list(self.frames)
        self.frames.clear()
        return remaining
