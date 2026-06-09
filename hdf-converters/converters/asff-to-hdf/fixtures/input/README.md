# asff-to-hdf fixtures

All fixtures are derived from real Security Hub output captured in heimdall2's
sample corpus and conform to the published AWS Security Finding Format
(`AwsSecurityFinding` shape).

**Source:** `heimdall2/libs/hdf-converters/sample_jsons/asff_mapper/sample_input_report/asff_sample.json`

**Format spec:** https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html

| File | Purpose | Derivation |
|---|---|---|
| `minimal.json` | One canonical Security Hub finding; happy-path | First finding of the heimdall2 sample, in standard `{"Findings": [...]}` envelope |
| `securityhub.json` | Three findings exercising SecurityHub case-handler dispatch + consolidation | First 3 findings of the heimdall2 sample |
| `bare-array.json` | Input wrapper resilience — top-level array | Same first finding as `minimal.json`, top-level `[...]` |
| `single.json` | Input wrapper resilience — single bare object | Same first finding as `minimal.json`, top-level `{...}` |
| `empty.json` | Empty-findings synthesizer (Step 4e) | Hand-written `{"Findings": []}` |
| `suppressed.json` | `Workflow.Status=SUPPRESSED` forces impact 0.0 (heimdall2 parity) | First finding with `"Workflow": {"Status": "SUPPRESSED"}` injected |
| `multi-resource.json` | Consolidation — multiple findings sharing one GeneratorId | First finding cloned three times with distinct resource IDs and finding IDs |
| `config-rule.json` | SecurityHub case NIST-tag resolution via AWS Config rule lookup | First finding with `ProductFields.RelatedAWSResources:0/{type,name}` injected; rule name `s3-bucket-public-read-prohibited` exists in `hdf-mappings/go/awsconfig/awsconfig-mappings.json` and maps to `AC-3|AC-4|AC-6|AC-21(b)|SC-7|SC-7(3)` |

Every fixture is well under 5KB.
