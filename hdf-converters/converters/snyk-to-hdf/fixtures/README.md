# snyk-to-hdf fixtures — provenance

Source tool: **Snyk CLI** (`snyk test --json`).

| Fixture | Generated | How |
|---|---|---|
| `nodejs-goof-local.json` | 2026-08 | `snyk test --json` on a local clone of public `snyk-labs/nodejs-goof`, run in the `snyk/snyk:node` container; trimmed to a representative stratified subset (all severities). |
| `nodejs-goof-remote.json` | 2026-08 | `snyk test https://github.com/snyk-labs/nodejs-goof --json` (containerized); trimmed to a small structural subset. |
| `minimal.json` | 2026-08 | The eight long-lived nodejs-goof vulns (by ID) extracted from the local scan; the primary value-pin fixture. |
| `empty.json` | — | Synthetic no-findings shape. |

Sanitization: the `org` field is set to `demo-org` (the live scan's org is a real Snyk org). Scans run in a container so paths are neutral (`/project`, the public git URL). No credentials, tokens, or machine identifiers are present.

Refresh: `snyk auth <token>` then re-run the commands above against the current `snyk-labs/nodejs-goof`, re-trim, set `org` to `demo-org`, and regenerate goldens with `go test ./converters/snyk-to-hdf/go/... -run TestSnapshots -update`.
