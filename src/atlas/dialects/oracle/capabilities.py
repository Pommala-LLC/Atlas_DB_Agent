from atlas.core.models import DialectId, RoutineKind
from ..base import DialectCapabilities

CAPABILITIES = DialectCapabilities(
    dialect=DialectId.ORACLE_PLSQL,
    routine_kinds=(RoutineKind.PROCEDURE, RoutineKind.FUNCTION, RoutineKind.TRIGGER, RoutineKind.PACKAGE_ROUTINE),
    statement_families=(
        "blocks_and_declarations", "exception_sections", "cursors", "static_and_dynamic_sql", "bulk_sql",
        "transaction_control", "routine_calls", "control_flow", "result_and_ref_cursor_semantics",
    ),
    vendor_constructs=(
        "authid", "pragmas", "raise_application_error", "forall", "bulk_collect", "save_exceptions",
        "cursor_attributes", "returning_into", "pipelined_functions", "package_routines", "open_for",
    ),
    explicit_boundaries=(
        "package_state_requires_runtime_or_catalog_evidence", "dynamic_identifier_values_are_not_guessed",
        "sql_engine_context_restrictions_are_reported_when_statically_determinable", "unclassified_extensions_are_opaque",
    ),
)
