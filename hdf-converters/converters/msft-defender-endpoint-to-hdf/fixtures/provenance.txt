# Microsoft Defender for Endpoint fixtures — provenance

**Schema-validated synthetic** (fixture-integrity option 3: no real tool output
available, so constructed and validated against the official schema). Each fixture
carries an inline `_provenance` field stating this; the summary is surfaced here
at the directory level.

- `sample.json` / `minimal.json` — constructed from the Microsoft Graph Security
  API v2 documentation (`security/alerts_v2`); alert structure and evidence types
  match the official docs at
  `learn.microsoft.com/en-us/graph/api/resources/security-alert`. Uses Microsoft's
  standard `contoso` example tenant and placeholder machine IDs. **Not real tool
  output.**
- `empty.json` — zero-alerts document.

**Refreshing:** requires an M365 tenant with Defender for Endpoint (licensed). To
replace with a real export, pull `security/alerts_v2` via MS Graph, scrub tenant/
device/user identifiers, and drop the `_provenance` marker.
