# CycloneDX schema — provenance

Used to validate `hdf-to-cyclonedx-vex` output (specVersion 1.4) in its tests.

| file | source | $id | draft |
|---|---|---|---|
| `bom-1.4.schema.json` | CycloneDX/specification @1.6 `schema/bom-1.4.schema.json` | http://cyclonedx.org/schema/bom-1.4.schema.json | draft-07 |
| `spdx.schema.json` | CycloneDX/specification @1.6 `schema/spdx.schema.json` | http://cyclonedx.org/schema/spdx.schema.json | draft-07 |
| `jsf-0.82.schema.json` | CycloneDX/specification @1.6 `schema/jsf-0.82.schema.json` | http://cyclonedx.org/schema/jsf-0.82.schema.json | draft-07 |

Source: https://github.com/CycloneDX/specification/tree/1.6/schema — retrieved
2026-07-30, byte-identical. `bom-1.4` `$ref`s `spdx.schema.json` and
`jsf-0.82.schema.json` by relative name; both are registered as companions under
their `$id`s so the schema compiles offline.
