from atlas.core.models import DialectId
from ..normalization import DialectNormalizer

NORMALIZER = DialectNormalizer(
    dialect=DialectId.SQLSERVER_TSQL,
    quote_pairs=(("[", "]"), ("\"", "\"")),
    unquoted_server_case="COLLATION_DEPENDENT",
    type_aliases={"INT": "INTEGER", "DEC": "DECIMAL", "CHARACTER VARYING": "VARCHAR"},
)
