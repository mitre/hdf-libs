# OSCAL CLI Examples

User stories and example commands for processing OSCAL documents with `hdf convert`.

## 1. FedRAMP SAR → HDF Results

"I have a FedRAMP SAR and want HDF results to load in Heimdall."

```bash
# Auto-detect (OSCAL SAR → HDF Results)
hdf convert sar-fedramp.json -o sar-results.json

# Explicit format
hdf convert --from oscal-sar --to hdf sar-fedramp.json -o sar-results.json
```

## 2. OSCAL Catalog → HDF Baseline

"I have an OSCAL catalog and want to see all controls as an HDF baseline."

```bash
hdf convert --from oscal-catalog catalog-800-53-rev5.json -o nist-baseline.json
```

## 3. OSCAL Profile → HDF Baseline (with catalog resolution)

"I have an OSCAL profile and need to resolve it against the catalog."

```bash
hdf convert --from oscal-profile --catalog catalog-800-53-rev5.json profile-moderate.json -o moderate-baseline.json
```

## 4. FedRAMP POA&M → HDF

"I have a FedRAMP POA&M and want HDF to track remediation."

```bash
hdf convert --from oscal-poam poam-fedramp.json -o poam.json
```

## 5. OSCAL SSP → HDF System

"I have an OSCAL SSP and want to extract the system architecture as an HDF system document."

```bash
hdf convert --from oscal-ssp ssp-fedramp.json -o ssp-system.json
```

## 6. OSCAL Component Definition → HDF Baseline

"I have an OSCAL component definition and want an HDF baseline."

```bash
hdf convert --from oscal-component-definition component-example.json -o component-baseline.json
```

## 7. Auto-Detect OSCAL Type

"I don't know what type of OSCAL file this is — just auto-detect it."

```bash
# The 'oscal' source format auto-detects the OSCAL document type
hdf convert --from oscal ssp-fedramp.json -o output.json
```

## 8. HDF Results → OSCAL SAR Export

"I have HDF results and need to export as OSCAL SAR for FedRAMP submission."

```bash
hdf convert --from hdf --to oscal-sar results.json -o sar-export.json
```

## 9. HDF Amendments → OSCAL POA&M Export

"I have HDF amendments and need an OSCAL POA&M."

```bash
hdf convert --from hdf-amendments --to oscal-poam amendments.json -o poam-export.json
```

## 10. Batch Convert Mixed OSCAL Files

"I want to batch-convert a directory of mixed OSCAL files."

```bash
hdf convert --from oscal *.json -o converted/
```

## 11. OSCAL SAR → Legacy HDF v1 (version specifier)

"I want legacy HDF v1 output from an OSCAL SAR."

```bash
hdf convert --from oscal-sar --to hdf@1 sar-fedramp.json -o legacy-sar.json
```

## Available OSCAL Conversions

| Source | Destination | Notes |
|--------|-------------|-------|
| `oscal` | `hdf` | Auto-detects OSCAL document type |
| `oscal-catalog` | `hdf` | Produces HDF Baseline |
| `oscal-profile` | `hdf` | Requires `--catalog` flag |
| `oscal-component-definition` | `hdf` | Produces HDF Baseline |
| `oscal-ssp` | `hdf` | Produces HDF System |
| `oscal-assessment-plan` | `hdf` | Produces HDF Plan |
| `oscal-assessment-results` / `oscal-sar` | `hdf` | Produces HDF Results |
| `oscal-poam` | `hdf` | Produces HDF Amendments |
| `hdf` | `oscal-sar` | Export HDF Results as OSCAL SAR |
| `hdf-amendments` | `oscal-poam` | Export amendments as OSCAL POA&M |
