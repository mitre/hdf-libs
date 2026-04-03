# HDF CLI User Story Examples

Each section walks through a real user workflow for one CLI command. Run these after building the CLI:

```bash
cd hdf-cli && go build -o hdf ./cmd/hdf && cd ..
```

Fixture files used throughout:
```bash
RESULTS=hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/dropwizard-vulns.json
SARIF=hdf-converters/converters/sarif-to-hdf/fixtures/input/minimal.json
NESSUS=hdf-converters/converters/nessus-to-hdf/fixtures/input/sample.nessus
BASELINE=hdf-schema/test/fixtures/minimal-baseline.json
```

---

## 1. Converting Security Tool Output to HDF

**Story**: A security engineer receives a CycloneDX vulnerability report and needs to convert it to HDF for their compliance dashboard.

```bash
# Auto-detect format and convert
hdf convert $RESULTS -o /tmp/example-hdf-results.json

# Validate the output
hdf validate /tmp/example-hdf-results.json

# Convert with explicit format
hdf convert --from cyclonedx $RESULTS -o /tmp/example-hdf-explicit.json

# Stamp a componentId during conversion
hdf convert $RESULTS -o /tmp/example-hdf-stamped.json --component-id "aaaaaaaa-1111-2222-3333-444444444444"

# Apply labels during conversion
hdf convert $RESULTS -o /tmp/example-hdf-labeled.json --labels "env=prod,system=Portal"

# Verify the output with hdf list
hdf list /tmp/example-hdf-labeled.json --detail components

# Convert Nessus (XML format)
hdf convert $NESSUS -o /tmp/example-hdf-nessus.json
hdf validate /tmp/example-hdf-nessus.json
```

**Expected**: Each conversion produces valid HDF with `components[]`, embedded SBOM for CycloneDX, and labels/componentId when flags are used.

---

## 2. Validating HDF Documents

**Story**: Before submitting an HDF document for compliance review, an engineer validates it against the schema.

```bash
# Validate results (auto-detect type)
hdf validate /tmp/example-hdf-results.json

# Validate with explicit type
hdf validate --type results /tmp/example-hdf-results.json

# Validate with wrong type — should fail with type-specific error
hdf validate --type system /tmp/example-hdf-results.json
# Expected: "Ensure the file conforms to the HDF system schema"

# Validate JSON output
hdf validate --json /tmp/example-hdf-results.json

# Validate invalid file — errors include line numbers for file input
echo '{
  "baselines": "not an array",
  "components": [],
  "statistics": {}
}' > /tmp/example-hdf-invalid.json
hdf validate /tmp/example-hdf-invalid.json
# Expected: "line 2: baselines: Invalid type..."

# Validate invalid file with JSON output — line numbers in error objects
hdf validate --json /tmp/example-hdf-invalid.json
```

**Expected**: Valid docs pass, wrong-type gives schema-specific error message, invalid JSON fails with clear errors including line numbers.

---

## 3. Listing HDF Document Contents

**Story**: An analyst wants to see what's in an HDF file without opening it in a JSON editor.

```bash
# Summary of results file
hdf list /tmp/example-hdf-results.json

# List requirements
hdf list /tmp/example-hdf-results.json --detail requirements

# List components
hdf list /tmp/example-hdf-results.json --detail components

# JSON output
hdf list /tmp/example-hdf-results.json --detail components --json
```

**Expected**: Results summary shows baselines/components/status counts. Detail sections list individual items.

---

## 4. Querying Requirements

**Story**: A security engineer wants to find all failing critical requirements.

```bash
# Query by status
hdf query /tmp/example-hdf-results.json --status failed

# Query by severity
hdf query /tmp/example-hdf-results.json --severity critical

# Query by NIST control
hdf query /tmp/example-hdf-results.json --nist AC-3

# Free text search
hdf query /tmp/example-hdf-results.json --search "injection"

# JSON output
hdf query /tmp/example-hdf-results.json --status failed --json

# Combined filters
hdf query /tmp/example-hdf-results.json --status failed --nist SI-10
```

**Expected**: Filters return matching requirements. JSON mode outputs structured data.

---

## 5. Comparing Scans Over Time

**Story**: A team wants to see what changed between two scans of the same system.

```bash
# Convert two different fixtures for comparison
hdf convert hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/minimal-vulns.json -o /tmp/example-hdf-diff-old.json
hdf convert $RESULTS -o /tmp/example-hdf-diff-new.json

# Temporal diff (results documents)
hdf diff /tmp/example-hdf-diff-old.json /tmp/example-hdf-diff-new.json

# JSON output
hdf diff /tmp/example-hdf-diff-old.json /tmp/example-hdf-diff-new.json --json

# System drift diff
echo '{"name":"Sys","components":[{"name":"App","type":"application","componentId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}' > /tmp/example-hdf-sys-v1.json
echo '{"name":"Sys","components":[{"name":"App","type":"application","componentId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","description":"added"},{"name":"Cache","type":"application","componentId":"11111111-2222-3333-4444-555555555555"}],"dataFlows":[{"from":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","to":"11111111-2222-3333-4444-555555555555","protocol":"TCP","port":6379}]}' > /tmp/example-hdf-sys-v2.json
hdf diff /tmp/example-hdf-sys-v1.json /tmp/example-hdf-sys-v2.json

# Summary only
hdf diff /tmp/example-hdf-sys-v1.json /tmp/example-hdf-sys-v2.json --stat
```

**Expected**: Temporal diff shows requirement-level changes (fixed, regressed). System diff shows component and data flow changes.

---

## 6. Managing System Documents

**Story**: A system owner bootstraps a system document from scan results, then updates it.

```bash
# Create system from results
hdf system create --from /tmp/example-hdf-results.json --name "Dropwizard Prod" \
  --owner "platform-team@agency.gov" --description "Production Dropwizard" \
  -o /tmp/example-hdf-system.json

# View system info (shows auto-generated systemId, owner, components)
hdf system info /tmp/example-hdf-system.json

# Update owner
hdf system set /tmp/example-hdf-system.json --owner "new-team@agency.gov"

# Unset optional field
hdf system set /tmp/example-hdf-system.json --unset description

# Try to unset required field — should fail
hdf system set /tmp/example-hdf-system.json --unset name
```

**Expected**: System documents have auto-generated systemId, owner, components. Set/unset work. Required fields are protected.

---

## 7. Labels and Component IDs

**Story**: A DevSecOps pipeline stamps labels and component IDs onto HDF output.

```bash
# Set labels
cp /tmp/example-hdf-results.json /tmp/example-hdf-label-test.json
hdf label set /tmp/example-hdf-label-test.json env=production system=Portal
hdf label show /tmp/example-hdf-label-test.json

# Remove a label
hdf label remove /tmp/example-hdf-label-test.json env

# Stamp componentId
hdf label set /tmp/example-hdf-label-test.json --component-id "deadbeef-1234-5678-9abc-def012345678"

# Generate unique componentIds
hdf label set /tmp/example-hdf-label-test.json --generate-component-id
```

**Expected**: Labels are applied/removed on components[]. componentId is stamped correctly.

---

## 8. Applying Amendments (Waivers)

**Story**: An ISSM applies a waiver to a failing requirement.

```bash
# Create a minimal amendments doc
cat > /tmp/example-hdf-amendments.json << 'EOF'
{
  "name": "Q1 Waivers",
  "overrides": [
    {
      "type": "waiver",
      "requirementId": "GHSA-5p34-5m6p-p58g",
      "status": "passed",
      "reason": "Compensating control in place",
      "appliedBy": {"type": "email", "identifier": "issm@agency.gov"},
      "appliedAt": "2026-03-27T00:00:00Z",
      "expiresAt": "2026-09-27T00:00:00Z"
    }
  ]
}
EOF

hdf validate --type amendments /tmp/example-hdf-amendments.json

# Apply amendments to results
hdf amend apply --results /tmp/example-hdf-results.json \
  --amendments /tmp/example-hdf-amendments.json \
  -o /tmp/example-hdf-amended.json

# Update amendments metadata
hdf amend set /tmp/example-hdf-amendments.json --amendment-id "550e8400-e29b-41d4-a716-446655440000"
```

**Expected**: Amendments validate. Apply modifies effectiveStatus on matching requirements.

---

## 9. Generating InSpec Profiles

**Story**: A developer generates an InSpec profile stub from a DISA STIG.

```bash
# Generate from XCCDF benchmark XML (auto-detected)
hdf generate inspec-profile hdf-generators/test/fixtures/stig-rhel9-benchmark.xml /tmp/example-hdf-profile/
ls /tmp/example-hdf-profile/controls/ | head -5

# Verify with cinc-auditor
cinc-auditor check /tmp/example-hdf-profile/

# Generate from HDF Baseline JSON
# hdf generate inspec-profile $BASELINE /tmp/example-hdf-profile-json/

# Generate with explicit source type
# hdf generate inspec-profile benchmark.xml /tmp/example-hdf-profile/ -s xccdf

# Override metadata
# hdf generate inspec-profile benchmark.xml /tmp/example-hdf-profile/ --maintainer "MITRE SAF" --license Apache-2.0
```

**Expected**: Profile directory with controls/ (named SV-xxx.rb) and inspec.yml. cinc-auditor reports Valid: true. (Note that cinc-auditor will print warnings for each requirement in the baseline, since the InSpec testfiles it generates only contain baseline metadata, and no actual executable test code.)

---

## 10. Assessment Plans

**Story**: A security engineer creates and manages assessment plans.

```bash
# Create a plan from a system document
hdf plan create /tmp/example-hdf-system.json -o /tmp/example-hdf-plan.json
hdf validate --type plan /tmp/example-hdf-plan.json

# Create a standalone plan (no system document required)
hdf plan create --name "RHEL9 Assessment" --baseline RHEL9-STIG -o /tmp/example-hdf-standalone-plan.json

# View plan info
hdf plan info /tmp/example-hdf-plan.json

# Update plan metadata
hdf plan set /tmp/example-hdf-plan.json --description "Monthly compliance scan"
hdf plan set /tmp/example-hdf-plan.json --system-ref portal-prod.hdf-system.json
hdf plan set /tmp/example-hdf-plan.json --version "1.0.0"
```

**Expected**: Plans have auto-generated planId UUID. Create works from system file or standalone with --name/--baseline. Set updates fields in place.

---

## 11. Evidence Packages (Full Document Chain)

**Story**: A compliance officer builds the full document chain (system → plan → results → evidence) and verifies completeness.

```bash
# --- Step 1: Create a system document ---
cat > /tmp/example-hdf-system.json << 'EOF'
{
  "systemId": "aaaaaaaa-1111-2222-3333-444444444444",
  "name": "Portal Prod",
  "components": [
    {"name": "WebTier", "type": "application", "baselineRefs": ["RHEL9-STIG"]},
    {"name": "DatabaseTier", "type": "application", "baselineRefs": ["PostgreSQL-STIG"]}
  ]
}
EOF
hdf validate --type system /tmp/example-hdf-system.json

# --- Step 2: Create an assessment plan from the system ---
hdf plan create /tmp/example-hdf-system.json -o /tmp/example-hdf-plan.json
hdf validate --type plan /tmp/example-hdf-plan.json
# Plan should have 2 assessments: RHEL9-STIG, PostgreSQL-STIG

# --- Step 3: Create results for each baseline ---
cat > /tmp/example-hdf-rhel9-results.json << 'EOF'
{
  "baselines": [{"name": "RHEL9-STIG", "requirements": [
    {"id": "SV-257777", "title": "Vendor support", "descriptions": [{"label": "default", "data": "check"}],
     "impact": 0.7, "tags": {}, "results": [{"status": "passed", "codeDesc": "check", "startTime": "2026-03-30T00:00:00Z"}]}
  ], "supports": [], "groups": []}],
  "platform": {"name": "rhel9", "release": "9.2"},
  "statistics": {"duration": 12.5}, "version": "2.0.0"
}
EOF
hdf validate --type results /tmp/example-hdf-rhel9-results.json

cat > /tmp/example-hdf-postgres-results.json << 'EOF'
{
  "baselines": [{"name": "PostgreSQL-STIG", "requirements": [
    {"id": "SV-233512", "title": "Access control", "descriptions": [{"label": "default", "data": "check"}],
     "impact": 0.5, "tags": {}, "results": [{"status": "passed", "codeDesc": "check", "startTime": "2026-03-30T00:00:00Z"}]}
  ], "supports": [], "groups": []}],
  "platform": {"name": "postgresql", "release": "15.4"},
  "statistics": {"duration": 8.2}, "version": "2.0.0"
}
EOF
hdf validate --type results /tmp/example-hdf-postgres-results.json

# --- Step 4: Build the evidence package ---
# --results is repeatable and supports globs
hdf evidence build \
  --system /tmp/example-hdf-system.json \
  --results /tmp/example-hdf-rhel9-results.json \
  --results /tmp/example-hdf-postgres-results.json \
  -o /tmp/example-hdf-evidence.json
# Or with a glob:
# hdf evidence build --system /tmp/example-hdf-system.json --results "/tmp/example-hdf-*-results.json" -o /tmp/example-hdf-evidence.json
# Or with positional args (shell-expanded):
# hdf evidence build --system /tmp/example-hdf-system.json /tmp/scans/*.json -o /tmp/example-hdf-evidence.json

# Link the evidence package to the plan
hdf evidence set /tmp/example-hdf-evidence.json --plan-ref example-hdf-plan.json

# --- Step 5: Verify checksums ---
hdf evidence verify /tmp/example-hdf-evidence.json --checksums-only

# --- Step 6: Verify completeness against the plan ---
hdf evidence verify /tmp/example-hdf-evidence.json
# Checks that every baseline in the plan has a corresponding results document.

# --- Other evidence commands ---
hdf evidence info /tmp/example-hdf-evidence.json
hdf evidence set /tmp/example-hdf-evidence.json --package-id "550e8400-e29b-41d4-a716-446655440000"
hdf evidence set /tmp/example-hdf-evidence.json --description "Quarterly ATO evidence bundle"
hdf validate --type evidence-package /tmp/example-hdf-evidence.json
```

**Expected**:
- Each document validates against its schema at creation time.
- Plan has 2 assessments derived from system components.
- Evidence build accepts multiple `--results` flags, globs, and positional args.
- `evidence verify --checksums-only`: all SHA-256 checksums match.
- `evidence verify` (default): completeness check reports missing baselines.
- `evidence set --plan-ref`: links evidence to the assessment plan.
- `evidence info`: displays package name, planRef, systemRef, contents list.

---

## 12. Compliance Thresholds (CI/CD Gates)

**Story**: A CI pipeline enforces compliance regression detection.

```bash
# Generate a threshold from HDF results
hdf generate threshold hdf-schema/test/fixtures/minimal-v2.json -o /tmp/example-hdf-threshold.yaml

# View the generated threshold
cat /tmp/example-hdf-threshold.yaml

# Validate the same results against the threshold (should pass)
hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -T /tmp/example-hdf-threshold.yaml

# Generate with control IDs included
hdf generate threshold hdf-schema/test/fixtures/minimal-v2.json --include-controls

# Inline threshold validation (CI one-liner)
hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -I "{compliance.min: 40}"

# Inline threshold that should fail (compliance too high)
hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -I "{compliance.min: 90}" || echo "Expected failure"
```

**Expected**:
- Generate produces YAML with compliance, passed, failed sections.
- Validate with -T: exit 0 when results meet threshold.
- --include-controls: adds control ID lists under each status/severity.
- Inline -I: parses `{key: value}` format, exit 0 on pass, exit 1 on fail.
- Round-trip: generate → validate against same file always passes.

---

## 13. Fetching Results from APIs

**Story**: A security engineer pulls findings from an API.

```bash
# Check fetch help
hdf fetch --help
```

**Expected**: Help text shows available API sources. (Actual API calls require credentials/endpoints.)
