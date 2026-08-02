from atlas.core.models import DialectId, RoutineKind
from ..base import DialectCapabilities

CAPABILITIES = DialectCapabilities(
    dialect=DialectId.POSTGRESQL_PLPGSQL,
    routine_kinds=(RoutineKind.PROCEDURE, RoutineKind.FUNCTION, RoutineKind.TRIGGER),
    statement_families=("blocks_and_declarations", "exception_subtransactions", "static_and_dynamic_sql", "cursors_and_refcursors", "transaction_control", "control_flow", "return_sets", "diagnostics"),
    vendor_constructs=("found_register", "select_into_strict", "return_query", "return_next", "return_query_execute", "get_stacked_diagnostics", "assert", "perform", "security_definer", "volatility_and_parallel_safety"),
    explicit_boundaries=("transaction_control_requires_top_level_call_context", "dynamic_identifier_values_are_not_guessed", "trigger_event_context_requires_catalog_or_runtime_evidence", "unclassified_extensions_are_opaque"),
)
