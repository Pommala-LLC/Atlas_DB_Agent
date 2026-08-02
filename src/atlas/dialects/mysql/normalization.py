from atlas.core.models import DialectId
from ..normalization import DialectNormalizer

NORMALIZER = DialectNormalizer(
    dialect=DialectId.MYSQL_STORED_PROGRAM,
    quote_pairs=(("`", "`"), ("\"", "\"")),
    unquoted_server_case="FILESYSTEM_AND_SERVER_SETTING_DEPENDENT",
    type_aliases={"INT": "INTEGER", "DEC": "DECIMAL", "BOOL": "BOOLEAN"},
)
