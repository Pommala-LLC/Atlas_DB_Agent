from atlas.core.models import DialectId
from ..normalization import DialectNormalizer

NORMALIZER = DialectNormalizer(
    dialect=DialectId.DB2_SQL_PL,
    quote_pairs=(("\"", "\""),),
    unquoted_server_case="UPPER",
    type_aliases={"INT": "INTEGER", "DEC": "DECIMAL", "CHARACTER VARYING": "VARCHAR"},
)
