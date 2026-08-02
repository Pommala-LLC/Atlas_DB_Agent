from atlas.core.models import DialectId, RoutineKind
from ..base import DialectCapabilities

CAPABILITIES = DialectCapabilities(
    dialect=DialectId.SQLSERVER_TSQL,
    routine_kinds=(RoutineKind.PROCEDURE, RoutineKind.FUNCTION, RoutineKind.TRIGGER),
    statement_families=("batches_and_blocks", "try_catch", "transactions", "static_and_dynamic_sql", "temporary_objects", "control_flow", "routine_calls", "result_sets"),
    vendor_constructs=("sp_executesql", "throw_and_raiserror", "xact_state", "xact_abort", "output_clause", "table_variables", "local_and_global_temp_tables", "goto", "execute_as"),
    explicit_boundaries=("dynamic_batch_identifiers_are_not_guessed", "metadata_dependent_name_resolution_requires_catalog_evidence", "udf_restrictions_are_reported_when_statically_determinable", "unclassified_extensions_are_opaque"),
)
