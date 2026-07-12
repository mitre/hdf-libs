# SonarQube Severity Mapping

SonarQube carries two independent severity axes. This page states which one drives HDF
`severity` and `impact`, so downstream severity gates can be pinned to a known meaning.

## The two axes

| Axis | API field | Values | Status |
|---|---|---|---|
| Legacy | `severity` | `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, `INFO` | Deprecated once a project is in MQR mode |
| Multi-Quality-Rule (MQR) | `impacts[].severity` | `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | What the SonarQube / SonarCloud UI displays by default |

MQR (the Clean Code taxonomy) rates an issue independently per software quality —
`SECURITY`, `RELIABILITY`, `MAINTAINABILITY` — and is the default on SonarCloud and on
SonarQube 10.8+.

The two axes are **not** a relabelling of each other. The relationship is per-rule, so a
finding can be legacy `MAJOR` but MQR `LOW` (a style nit), or legacy `MAJOR` but MQR
`HIGH` (a genuine security finding). A legacy value therefore cannot be converted into an
MQR value after the fact.

## Which axis HDF emits

The converter uses `impacts[]` whenever the source data contains it, and falls back to the
legacy `severity` only when it does not (pre-MQR servers). Every requirement records which
axis was used in the `severitySource` tag:

| `tags.severitySource` | Meaning |
|---|---|
| `mqr` | `severity` and `impact` came from `impacts[].severity` — reconciles with the SonarQube UI |
| `legacy` | Source had no `impacts[]`; `severity` and `impact` came from the deprecated `severity` field |

When an issue is rated on more than one software quality, the **highest** severity governs,
matching how the SonarQube UI buckets it.

Releases up to and including v3.3.2 always emitted the legacy axis, which is why their
severity distribution does not reconcile with the SonarQube UI for a project in MQR mode.

## Tags

In MQR mode both axes are preserved so consumers can select:

| Tag | Example | Notes |
|---|---|---|
| `severity` | `high` | The authoritative axis; drives `impact` |
| `severitySource` | `mqr` | Which axis drove `severity` / `impact` |
| `legacySeverity` | `critical` | The deprecated axis, retained for comparison. MQR mode only |
| `impacts` | `[{"softwareQuality": "SECURITY", "severity": "HIGH"}]` | Full per-quality breakdown. MQR mode only |
| `cleanCodeAttribute` | `COMPLETE` | Clean Code attribute, when present |

In legacy mode `tags.severity` already is the legacy axis, so `legacySeverity` is omitted
rather than duplicated.

## Impact scores

Each axis maps to HDF `impact` on its own scale. The labels overlap (`BLOCKER`, `INFO`) but
do not carry the same meaning, so the scales are kept separate.

| MQR severity | Impact | | Legacy severity | Impact |
|---|---|---|---|---|
| `BLOCKER` | 1.0 | | `BLOCKER` | 1.0 |
| `HIGH` | 0.7 | | `CRITICAL` | 0.7 |
| `MEDIUM` | 0.5 | | `MAJOR` | 0.5 |
| `LOW` | 0.3 | | `MINOR` | 0.3 |
| `INFO` | 0.0 | | `INFO` | 0.0 |

## Pinning a severity gate

Gate on `severity` and assert `severitySource` so a gate cannot silently change meaning if
the source server is not in the mode you expect:

```bash
hdf fetch sonarqube out.json --url "$URL" --project-key "$KEY" --format hdf

# Fail the build if anything is rated high or above on the MQR axis.
jq -e '
  [ .baselines[].requirements[]
    | select(.tags.severitySource == "mqr")
    | select(.tags.severity == "high" or .tags.severity == "blocker") ]
  | length == 0
' out.json
```
