# `CLAIMS.ADJUDICATE_CLAIM` acceptance gate

The parser capability required by the target is implemented:

- nested compound statements;
- local declarations inside a compound block;
- named SQLSTATE conditions;
- handlers referring to named conditions;
- nearest lexical-scope resolution;
- no opaque region for the constructed nested-condition fixture.

The complete `CLAIMS.ADJUDICATE_CLAIM` source was not supplied in the available artifacts, so the target-specific assertion remains pending input.

Run when the source is available:

```bat
python scripts\check_phase1_target.py path\ADJUDICATE_CLAIM.sql --require-unreachable-branch --expected-unreachable-line 167
```

Expected result:

```text
PARSES_COMPLETE
no OPAQUE nodes
UNREACHABLE_BRANCH near the expected Step 8 ELSE source line
```
