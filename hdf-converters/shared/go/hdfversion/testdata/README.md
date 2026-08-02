# hdfversion testdata

- `modern_with_amendments.json` — a synthetic modern (v3) HDF document exercising the
  amendment-flatten and vulnerability-field paths of the v3→v2 downgrade. Shared by the
  Go (`hdf_version_test.go`) and TS (`legacyhdf-to-hdf` parity) downgrade tests.
- `exec-json.schema.json` — the InSpec exec-json JSON Schema, vendored verbatim from
  MITRE heimdall2 (`libs/inspecjs/schemas/exec-json.json`, Apache-2.0). Used to assert
  that the v3→v2 downgrade emits documents Heimdall's InSpec parser accepts. Refresh from
  upstream if the legacy schema changes.
