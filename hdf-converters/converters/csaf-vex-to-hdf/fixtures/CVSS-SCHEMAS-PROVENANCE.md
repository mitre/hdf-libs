# CVSS companion schemas — provenance

The OASIS CSAF v2.0 schema (`csaf_json_schema.json`) `$ref`s the FIRST.org CVSS
schemas by URL. They are vendored here so the CSAF schema compiles offline in the
`hdf-to-csaf-vex` output-validation test.

| file | source | $schema draft |
|---|---|---|
| `cvss-v2.0.json` | https://www.first.org/cvss/cvss-v2.0.json | draft-04 |
| `cvss-v3.0.json` | https://www.first.org/cvss/cvss-v3.0.json | draft-04 |
| `cvss-v3.1.json` | https://www.first.org/cvss/cvss-v3.1.json | draft-07 |

Retrieved 2026-07-30, byte-identical to source.

Note: the draft-04 CVSS schemas mean CSAF output is schema-validated on the Go
side only (santhosh-tekuri compiles mixed drafts; ajv 8 dropped draft-04). The
TypeScript output is covered transitively: the Go↔TS golden-parity test proves
the two emit byte-identical output.
