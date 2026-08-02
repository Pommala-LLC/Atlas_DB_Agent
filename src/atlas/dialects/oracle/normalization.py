from atlas.core.models import DialectId
from ..normalization import DialectNormalizer

NORMALIZER = DialectNormalizer(
    dialect=DialectId.ORACLE_PLSQL,
    quote_pairs=(("\"", "\""),),
    unquoted_server_case="UPPER",
    type_aliases={"INT": "NUMBER", "INTEGER": "NUMBER", "DEC": "DECIMAL", "VARCHAR": "VARCHAR2"},
)
