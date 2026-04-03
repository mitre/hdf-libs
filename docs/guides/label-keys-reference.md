# Well-Known Label Keys Reference

Labels are optional `Record<string, string>` metadata on **components** and **baselines** in HDF v2. They enable flexible grouping, filtering, and system-level organization without imposing a fixed hierarchy.

For full design rationale, see [hdf-v2-document-ecosystem.md](../architecture/hdf-v2-document-ecosystem.md), section "Labels -- Flexible Grouping Without Hierarchy."

## What Labels Are

Every component in `hdf-results` and every baseline can carry a `labels` object -- a flat map of string keys to string values:

```json
{
  "type": "host",
  "name": "web-server-01",
  "labels": {
    "system": "Enterprise Portal Production",
    "component": "WebTier",
    "environment": "production",
    "region": "us-gov-west-1",
    "team": "platform-eng"
  }
}
```

Labels are defined in `Base_Component` within `primitives/component.schema.json` and in `Baseline_Metadata` within `primitives/common.schema.json`. The schema accepts any string keys and string values -- it does not enforce specific keys.

## Well-Known Keys

Five keys have conventional meaning across the HDF ecosystem. Tools, converters, and Heimdall recognize these keys and use them for grouping and display.

### `system`

The authorization boundary or ATO system this component belongs to.

- **Expected values:** System name matching an hdf-system document's `name` field.
- **Example:** `"ACME-WebPortal"`, `"Enterprise Portal Production"`
- **Used by:** Heimdall system view, `hdf diff --group-by labels.system`

### `component`

The logical component within a system boundary (maps to hdf-system `Component.name`).

- **Expected values:** Component names from the hdf-system document.
- **Example:** `"WebTier"`, `"DatabaseTier"`, `"APIGateway"`
- **Used by:** `hdf diff --group-by labels.component`, system-level compliance aggregation

### `environment`

The deployment environment.

- **Expected values:** `"production"`, `"staging"`, `"development"`, `"test"`
- **Example:** `"production"`
- **Used by:** Cross-environment comparison (`hdf diff dev-results.json prod-results.json`)

### `region`

Geographic or cloud region where the component resides.

- **Expected values:** Cloud region identifiers or geographic labels.
- **Example:** `"us-east-1"`, `"us-gov-west-1"`, `"eu-west-1"`
- **Used by:** Regional compliance dashboards, `hdf diff --group-by labels.region`

### `team`

The team responsible for the component.

- **Expected values:** Team names from your organization.
- **Example:** `"platform-engineering"`, `"security-ops"`
- **Used by:** Ownership-based filtering and reporting

## Target Selectors in hdf-system

Components in an hdf-system document match assessed components by label values using `Target_Selector`. A `Target_Selector` is an object where all specified key-value pairs must match (AND logic):

```json
{
  "name": "WebTier",
  "type": "application",
  "targetSelector": { "labels.component": "WebTier" },
  "baselineRefs": ["RHEL9-STIG", "DISA-Container-STIG"]
}
```

This means any component with `labels.component = "WebTier"` is automatically included in the WebTier system component. Adding a new server with the right labels requires no system document update.

`Target_Selector` is defined in `primitives/system.schema.json` as an object with `additionalProperties: { type: "string" }`.

## How Converters Populate Labels

Several converters automatically extract labels from source tool metadata during conversion:

| Converter | Labels populated | Source of data |
|---|---|---|
| `aws-config` | `labels.account`, `labels.region` | AWS resource ARN |
| `nessus` | `labels.hostgroup`, `labels.network` | Nessus host properties |
| `grype` / `trivy` | `labels.image`, `labels.registry` | Container image reference |
| `oscal-sar` | Populates `systemRef` (not labels directly) | OSCAL `import-ap` href |
All other converters produce results without labels. Labels can be added after conversion using the CLI.

## Applying Labels via CLI

### During conversion

The `--labels` flag on `hdf convert` applies labels to all components in the output:

```bash
hdf convert --from nessus scan.nessus -o results.json \
  --labels system=Portal,environment=production,region=us-east-1
```

### After conversion

Use `hdf label set` to add or update labels on an existing file:

```bash
# Add labels (modifies file in-place)
hdf label set results.json system=Portal component=WebTier environment=production

# Write to a new file instead
hdf label set results.json system=Portal -o labeled-results.json
```

Use `hdf label show` to inspect labels:

```bash
hdf label show results.json
# Component: web-server-01 [host]
#   component = WebTier
#   environment = production
#   system = Portal
```

Use `hdf label remove` to delete label keys:

```bash
hdf label remove results.json team region
```

## Guidelines for Custom Labels

Custom labels beyond the five well-known keys are supported. Follow these conventions:

1. **Use lowercase keys.** Prefer `datacenter` over `DataCenter`.
2. **Use hyphens for multi-word keys.** Prefer `cost-center` over `costCenter` or `cost_center`.
3. **Avoid collisions with well-known keys.** Do not redefine `system`, `component`, `environment`, `region`, or `team` with non-standard semantics.
4. **Namespace vendor-specific labels.** If adding tool-specific labels, prefix with the tool name: `nessus-policy`, `prisma-rule-set`.
5. **Keep values short and categorical.** Labels are for grouping, not for storing arbitrary data. Use the `extensions` object for unstructured metadata.

## Example: Full Pipeline with Label Flow

This example shows labels flowing from scan through conversion, labeling, and system matching.

### 1. Convert a Nessus scan

```bash
hdf convert --from nessus scan.nessus -o results.json \
  --labels system="Enterprise Portal",environment=production,region=us-gov-west-1
```

The converter extracts `labels.account` and `labels.region` from the Nessus data. The `--labels` flag adds the system and environment labels on top.

### 2. Add component label

```bash
hdf label set results.json component=WebTier
```

### 3. Inspect labels

```bash
hdf label show results.json
# Component: 10.0.1.50 [host]
#   component = WebTier
#   environment = production
#   region = us-gov-west-1
#   system = Enterprise Portal
```

### 4. System matching

Given an hdf-system document with:

```json
{
  "components": [
    {
      "name": "WebTier",
      "type": "application",
      "targetSelector": { "labels.component": "WebTier" },
      "baselineRefs": ["RHEL9-STIG"]
    }
  ]
}
```

The component with `labels.component = "WebTier"` is automatically matched to the WebTier system component. The system-aware diff uses this to produce per-component compliance percentages:

```bash
hdf diff --system portal-prod.hdf-system.json feb-scan.json mar-scan.json
```
