from atlas.core.models import DialectId, RoutineKind
from ..base import DialectCapabilities

CAPABILITIES = DialectCapabilities(
    dialect=DialectId.DB2_SQL_PL,
    routine_kinds=(RoutineKind.PROCEDURE, RoutineKind.FUNCTION, RoutineKind.TRIGGER),
    statement_families=(
        "compound_statements", "condition_handlers", "condition_signaling", "cursors", "dynamic_sql",
        "transactions_and_savepoints", "static_sql", "result_sets", "routine_calls", "control_flow",
    ),
    vendor_constructs=(
        "atomic_and_not_atomic_blocks", "continue_exit_undo_handlers", "values_into", "with_return_cursors",
        "associate_result_set_locators", "allocate_cursor", "special_registers", "sequence_references",
    ),
    explicit_boundaries=(
        "catalog_dependent_overload_resolution", "runtime_dynamic_identifier_values", "external_routine_bodies",
        "unclassified_extensions_are_opaque",
    ),
)
