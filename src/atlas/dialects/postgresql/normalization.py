from atlas.core.models import DialectId
from ..normalization import DialectNormalizer

NORMALIZER = DialectNormalizer(
    dialect=DialectId.POSTGRESQL_PLPGSQL,
    quote_pairs=(("\"", "\""),),
    unquoted_server_case="LOWER",
    type_aliases={"INT": "INTEGER", "INT4": "INTEGER", "INT8": "BIGINT", "BOOL": "BOOLEAN", "DEC": "DECIMAL"},
)
