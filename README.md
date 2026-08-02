# Atlas Procedure Intelligence

Atlas Procedure Intelligence is an evidence-first static-analysis platform for
stored procedures.

It analyzes explicitly selected database dialects and produces source-bound:

- procedural decisions and ordered decision tables;
- non-authoritative candidate BDD scenarios;
- control-flow and exception-path evidence;
- output and data lineage;
- observable side effects;
- unresolved call and composition boundaries;
- complete source-to-artifact audit trails.

Supported dialects:

- IBM Db2 SQL PL
- Oracle PL/SQL
- Microsoft SQL Server T-SQL
- PostgreSQL PL/pgSQL
- MySQL stored programs

Atlas does not infer or silently switch database dialects. It does not require
database connections, execute stored procedures, or claim business authority
for generated BDD candidates.
