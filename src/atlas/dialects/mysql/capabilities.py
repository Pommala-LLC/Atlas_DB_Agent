from atlas.core.models import DialectId, RoutineKind
from ..base import DialectCapabilities

CAPABILITIES = DialectCapabilities(
    dialect=DialectId.MYSQL_STORED_PROGRAM,
    routine_kinds=(RoutineKind.PROCEDURE, RoutineKind.FUNCTION, RoutineKind.TRIGGER),
    statement_families=("compound_statements", "declarations", "condition_handlers", "cursors", "prepared_statements", "transactions", "static_sql", "control_flow", "diagnostics"),
    vendor_constructs=("declaration_ordering", "continue_and_exit_handlers", "named_conditions", "asensitive_read_only_nonscrollable_cursors", "get_diagnostics", "prepare_execute_deallocate", "on_duplicate_key_update", "sql_security"),
    explicit_boundaries=("prepared_statement_text_values_are_runtime_evidence", "definer_privilege_resolution_requires_catalog_context", "function_and_trigger_restrictions_are_reported_when_statically_determinable", "unclassified_extensions_are_opaque"),
)
