# OSCAL Plan of Action & Milestones schema — provenance

`oscal_poam_schema-v1.1.2.json` is the official NIST OSCAL **v1.1.2** POA&M JSON
Schema, used to validate this converter's output in its tests. The converter
emits `"oscal-version": "1.1.2"`, so its output is validated against exactly that
schema version.

- **Source:** https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/oscal_poam_schema.json
- **Release:** usnistgov/OSCAL `v1.1.2`
- **`$id`:** `http://csrc.nist.gov/ns/oscal/1.1.2/oscal-poam-schema.json`
- **JSON Schema draft:** draft-07
- **Self-contained:** yes — no external `$ref`s; validates a full
  `{ "plan-of-action-and-milestones": { … } }` document at the root.
- **SHA-256:** `906725163d767036c6189aec51252109b203214e121fc1acaff494b4d2dfbc04`
- **Retrieved:** 2026-07-28

Byte-identical to the upstream release asset. Do not edit; re-fetch from the
pinned release URL to update.
