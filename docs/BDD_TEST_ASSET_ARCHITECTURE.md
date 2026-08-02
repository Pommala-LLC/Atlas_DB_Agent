# BDD Test Asset Architecture

## Ownership boundary

The application owns reusable tools only:

- generated-Gherkin subset parser and validator;
- canonical test case, dataset, observation, and result models;
- deterministic typed boundary generation;
- external adapter loading;
- assertion execution and result reconciliation;
- property-gated live execution adapters.

A procedure-specific test-assets package owns:

- the source procedure under test;
- `.feature` files;
- TestCaseSpec batches;
- catalog and relational datasets;
- procedure-specific scripted or external harness adapters;
- execution properties;
- test results and reports.

The application never imports a generated test-assets package during normal
startup, static extraction, ScenarioSpec compilation, or BDD compilation. The
adapter is imported only when `run-bdd-test-package` selects that package.

## Status meaning

`SCRIPTED_MODEL` verifies the consistency of generated BDD, test cases, test data,
and a source-faithful model. It does not prove that Db2 compiled or executed the
procedure. `DB2_LUW` and `DB2_ZOS_EXTERNAL` remain explicit separate execution
modes and require their configured environments.
