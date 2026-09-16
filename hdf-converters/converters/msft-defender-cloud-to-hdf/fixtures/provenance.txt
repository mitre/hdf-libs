# Microsoft Defender for Cloud fixtures — provenance

**Schema-validated synthetic** (fixture-integrity option 3: no real tool output
available, so constructed and validated against the official schema). Each fixture
carries an inline `_provenance` field stating this; the summary is surfaced here
at the directory level.

- `sample.json` / `minimal.json` — constructed from the Microsoft Azure REST API
  documentation (`Microsoft.Security/assessments`, api-version 2021-06-01) and
  validated against the official Swagger spec at
  `github.com/Azure/azure-rest-api-specs`. Placeholder subscription/tenant GUIDs
  (`a1b2c3d4-…`) are intentional. **Not real tool output.**
- `empty.json` — zero-assessments document.

**Refreshing:** requires an Azure tenant with Defender for Cloud (licensed). To
replace with a real export, pull `Microsoft.Security/assessments`, scrub tenant/
subscription/resource IDs, and drop the `_provenance` marker.
