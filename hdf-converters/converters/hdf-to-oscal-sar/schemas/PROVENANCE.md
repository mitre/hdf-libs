# OSCAL Assessment Results schema — provenance

`oscal_assessment-results_schema-v1.1.2.json` is the official NIST OSCAL
**v1.1.2** Assessment Results (AR) JSON Schema, used to validate this converter's
output in its tests. The `hdf-to-oscal-sar` converter self-declares
`"oscal-version": "1.1.2"`, so its output is validated against exactly that
schema version.

- **Source:** https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_assessment-results_schema.json
- **Release:** usnistgov/OSCAL `v1.1.2`
- **`$id`:** `http://csrc.nist.gov/ns/oscal/1.1.2/oscal-ar-schema.json`
- **JSON Schema draft:** draft-07
- **Self-contained:** yes — no external `$ref`s; validates a full
  `{ "assessment-results": { … } }` document at the root.
- **SHA-256:** `d033da70154cf6625ae46a746199e88e58f2928b1387dfac051d381b92f41b0d`
- **Retrieved:** 2026-07-27

Byte-identical to the upstream release asset. Do not edit; re-fetch from the
pinned release URL to update.
