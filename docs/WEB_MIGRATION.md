# Atlas web namespace migration

The canonical console entry points are now `atlas.web.app:create_app` and
`atlas.web.runner:main`.

The stored-procedure intake, source-unit orchestration, result assembly and
persistence feature lives under `atlas.web.procedure`. The historical
`ojas_reconciler.db2_behavior.commercial_ui.procedure_analysis` module is a
compatibility re-export only.

The broader commercial console host remains a temporary implementation bridge
while its unrelated commercial routes are separated. New procedure-analysis
code must not be added to the legacy namespace.

## Dependency direction

```text
atlas.web.runner
  -> atlas.web.app
  -> atlas.web.procedure
  -> atlas.application

legacy commercial_ui.runner
  -> atlas.web.runner

legacy commercial_ui.procedure_analysis
  -> atlas.web.procedure
```

## Source-unit invariant

For identical source bytes, declared dialect and Atlas version, the UI, CLI and
end-to-end command must emit the same source-unit digest, routine set and
routine-IR digests.
