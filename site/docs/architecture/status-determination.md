# HDF Status Determination

How hdf-libs determines the overall status of a control/requirement from its individual test results. This logic applies to all data sources (InSpec, SARIF, Nessus, XCCDF, etc.) — not just InSpec.

## Status Values

| Status | Meaning |
|---|---|
| `passed` | Control requirements are met |
| `failed` | One or more requirements are not met |
| `error` | A test execution error occurred |
| `notApplicable` | Control is not applicable (impact 0.0 or explicitly scoped out) |
| `notReviewed` | Control was not evaluated (skipped, no results) |

## Precedence Order

When a control has multiple test results with different statuses, the overall status is determined by precedence (highest wins):

```
1. error          — any result errored → control is error
2. failed         — any result failed  → control is failed
3. passed         — any result passed  → control is passed
4. notApplicable  — only if all results are notApplicable
5. notReviewed    — only if nothing else matches (all skipped/notReviewed)
```

### Key Rules

- **`failed` + `passed` → `failed`**: One failure means the control fails
- **`passed` + `notReviewed` → `passed`**: A passing test proves the control works; a skipped test alongside it doesn't negate that
- **`impact === 0` → `notApplicable`**: Overrides all result statuses. A control with impact 0.0 is always Not Applicable regardless of whether its tests passed, failed, or were skipped
- **No results → `notReviewed`**: Unless impact is 0.0 (then `notApplicable`)

### Examples

| Results | Impact | Overall Status |
|---|---|---|
| `[passed]` | 0.7 | `passed` |
| `[failed]` | 0.7 | `failed` |
| `[passed, failed]` | 0.5 | `failed` |
| `[passed, notReviewed]` | 0.7 | `passed` |
| `[notReviewed]` | 0.5 | `notReviewed` |
| `[notReviewed]` | 0.0 | `notApplicable` |
| `[passed, error]` | 0.5 | `error` |
| `[]` (empty)*  | 0.0 | `notApplicable` |
| `[]` (empty)*  | 0.5 | `notReviewed` |

\* The v3 HDF schema enforces `results.minItems=1`, so empty results arrays should not appear in schema-valid HDF documents — converters synthesize a `passed` placeholder for clean scans (see `../specification/hdf-specification.md` § "Clean-scan convention"). The empty-results rows above remain a safety net for legacy InSpec-ExecJSON-shaped input that did not enforce the invariant.

## Where Status Is Computed

### effectiveStatus Field

The `effectiveStatus` field on `EvaluatedRequirement` is the authoritative status. When present, consumers should use it directly. When absent, consumers derive status from results using the precedence above.

### In hdf-libs

- **hdf-converters** (`convertControl`): Sets `effectiveStatus` from the source data. For v1 InSpec data, also sets `effectiveStatus = notApplicable` when `impact === 0`.
- **hdf-cli** (`determineControlStatus` in `stats.go`): Checks `effectiveStatus` first (via `SchemaStatusToDisplay` mapping). Falls back to result-based derivation with correct precedence.

### Schema Note

The HDF schema uses **camelCase** for status enum values (`notApplicable`, `notReviewed`). The CLI uses **snake_case** for display (`not_applicable`, `not_reviewed`). The `SchemaStatusToDisplay` function in the CLI handles this translation.

## Reference

This logic matches [InSpec Enhanced Outcomes](https://github.com/inspec/inspec/blob/main/lib/inspec/enhanced_outcomes.rb) (`Inspec::EnhancedOutcomes.determine_status`), which is the industry standard for security control status determination.
