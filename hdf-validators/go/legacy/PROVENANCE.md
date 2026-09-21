# Legacy HDF v2 schema — provenance

`exec-json.schema.json` is the pinned schema for **HDF v2** — the legacy
Heimdall/InSpec exec-json shape (`profiles[] + platform`) that SAF `*2hdf`
converters emit and that the userbase already holds. It is used only by the
validators (`ValidateLegacyV2` in Go, the `v2` path in the TS validator) and for
dev reference. It is **not** part of `hdf-schema/src/schemas/` and is **not**
published on the docs site.

- **Source:** `libs/inspecjs/schemas/exec-json.json` in mitre/heimdall2.
- **Version:** heimdall2 **v2.14.0** (commit `d717efe8`, 2026-09-12).
- **Why Heimdall, not upstream InSpec:** the maintainer's team controls Heimdall;
  the exec-json schema there is the authoritative definition of a valid HDF v2
  document for this project. Do not re-source it from `inspec schema exec-json`.
- **Copied from Heimdall, then relaxed in four documented spots.** The base is
  permissive (`additionalProperties: true`), so extra top-level fields such as
  `target` and `passthrough` already validate. Heimdall's published schema is,
  however, stricter than what real InSpec emits (and than what Heimdall's own
  tooling tolerates), so four `type`/`required` rules were widened to accept real
  Heimdall converter output that would otherwise fail. Each is marked with a
  `$comment` beginning "Local deviation":
  1. `Control_Result.resource_id` — also accepts `object` (GitHub #328).
  2. `Exec_JSON_Control.source_location` — also accepts a bare `string`.
  3. `Reference` — also accepts an empty `{}`.
  4. `Exec_JSON_Control` — `impact` is no longer required.
  Verified against 157 real Heimdall-sourced v2 docs: all 157 validate. These are
  a temporary local fork; the correct long-term fix is to update Heimdall's
  inspecjs schema upstream and drop the deviations (follow-up card). Do not add
  further deviations without the same real-data justification and a `$comment`.

`testdata/inspec-exec-json-valid.json` is a real HDF v2 document:
`libs/hdf-converters/sample_jsons/hadolint/hadolint-hdf.json` from the same
heimdall2 v2.14.0 checkout — real converter output, not fabricated.
