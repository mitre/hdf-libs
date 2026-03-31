# HDF CLI Smoke Tests — User Story Walkthrough

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

## 1. hdf convert (bead lgd2)

**Story**: A security engineer receives a CycloneDX vulnerability report and needs to convert it to HDF for their compliance dashboard.

```bash
# Auto-detect format and convert
hdf-cli/hdf convert $RESULTS -o /tmp/smoke-results.json

# Verify output has components (not targets)
python3 -c "import json; d=json.load(open('/tmp/smoke-results.json')); print('components:', len(d.get('components', []))); print('baselines:', len(d.get('baselines', [])))"

# Convert with explicit format
hdf-cli/hdf convert --from cyclonedx $RESULTS -o /tmp/smoke-explicit.json

# Stamp a componentId during conversion
hdf-cli/hdf convert $RESULTS -o /tmp/smoke-stamped.json --component-id "aaaaaaaa-1111-2222-3333-444444444444"
python3 -c "import json; d=json.load(open('/tmp/smoke-stamped.json')); print('componentId:', d['components'][0].get('componentId'))"

# Apply labels during conversion
hdf-cli/hdf convert $RESULTS -o /tmp/smoke-labeled.json --labels "env=prod,system=Portal"
python3 -c "import json; d=json.load(open('/tmp/smoke-labeled.json')); print('labels:', d['components'][0].get('labels'))"

# Verify embedded SBOM in CycloneDX output
python3 -c "
import json; d=json.load(open('/tmp/smoke-results.json'))
c = d['components'][0]
print('name:', c.get('name'))
print('version:', c.get('version'))
print('sbomFormat:', c.get('sbomFormat'))
sbom = c.get('sbom', {})
print('sbom packages:', len(sbom.get('components', [])) if sbom else 0)
"

# Convert Nessus (XML format)
hdf-cli/hdf convert $NESSUS -o /tmp/smoke-nessus.json
python3 -c "import json; d=json.load(open('/tmp/smoke-nessus.json')); print('components:', len(d.get('components', [])))"
```

**Expected**: Each conversion produces valid HDF with `components[]` (not `targets[]`), embedded SBOM for CycloneDX, and labels/componentId when flags are used.

---

## 2. hdf validate (bead txhl)

**Story**: Before submitting an HDF document for compliance review, an engineer validates it against the schema.

```bash
# Validate results (auto-detect type)
hdf-cli/hdf validate /tmp/smoke-results.json

# Validate with explicit type
hdf-cli/hdf validate --type results /tmp/smoke-results.json

# Validate with wrong type — should fail with type-specific error
hdf-cli/hdf validate --type system /tmp/smoke-results.json
# Expected: "Ensure the file conforms to the HDF system schema"

# Validate a system document
hdf-cli/hdf system create --from /tmp/smoke-results.json --name "Test" -o /tmp/smoke-system.json
hdf-cli/hdf validate /tmp/smoke-system.json

# Validate JSON output
hdf-cli/hdf validate --json /tmp/smoke-results.json

# Validate invalid file — errors now include line numbers for file input
echo '{
  "baselines": "not an array",
  "components": [],
  "statistics": {}
}' > /tmp/smoke-invalid.json
hdf-cli/hdf validate /tmp/smoke-invalid.json
# Expected: "line 2: baselines: Invalid type..."

# Validate invalid file with JSON output — line numbers in error objects
hdf-cli/hdf validate --json /tmp/smoke-invalid.json
# Expected: each error has "line": N field
```

**Expected**: Valid docs pass, wrong-type gives schema-specific error message, invalid JSON fails with clear errors including line numbers (file input only, not stdin).

---

## 3. hdf list (bead 7n2s)

**Story**: An analyst wants to see what's in an HDF file without opening it in a JSON editor.

```bash
# Summary of results file
hdf-cli/hdf list /tmp/smoke-results.json

# List requirements
hdf-cli/hdf list /tmp/smoke-results.json --detail requirements

# List components
hdf-cli/hdf list /tmp/smoke-results.json --detail components

# Using short alias
hdf-cli/hdf list /tmp/smoke-results.json --detail t

# Backward compat: "targets" alias
hdf-cli/hdf list /tmp/smoke-results.json --detail targets

# JSON output
hdf-cli/hdf list /tmp/smoke-results.json --detail components --json

# List a system document
hdf-cli/hdf list /tmp/smoke-system.json

# List system components
hdf-cli/hdf list /tmp/smoke-system.json --detail components

# List system data flows
hdf-cli/hdf list /tmp/smoke-system.json --detail dataFlows

# Short alias for data flows
hdf-cli/hdf list /tmp/smoke-system.json --detail d
```

**Expected**: Results summary shows baselines/components/status counts. System summary shows component count and data flow count. Detail sections work for both doc types.

---

## 4. hdf query (bead e4xp)

**Story**: A security engineer wants to find all failing critical requirements.

```bash
# Query by status
hdf-cli/hdf query /tmp/smoke-results.json --status failed

# Query by severity (if available)
hdf-cli/hdf query /tmp/smoke-results.json --severity critical

# Query by NIST control
hdf-cli/hdf query /tmp/smoke-results.json --nist AC-3

# Free text search
hdf-cli/hdf query /tmp/smoke-results.json --search "injection"

# JSON output
hdf-cli/hdf query /tmp/smoke-results.json --status failed --json

# Combined filters
hdf-cli/hdf query /tmp/smoke-results.json --status failed --nist SI-10
```

**Expected**: Filters return matching requirements. JSON mode outputs structured data.

---

## 5. hdf diff (bead 2no6)

**Story**: A team wants to see what changed between two scans of the same system, and also compare system documents over time.

```bash
# Convert two different fixtures for comparison
hdf-cli/hdf convert hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/minimal-vulns.json -o /tmp/smoke-diff-old.json
hdf-cli/hdf convert $RESULTS -o /tmp/smoke-diff-new.json

# Temporal diff (results documents)
hdf-cli/hdf diff /tmp/smoke-diff-old.json /tmp/smoke-diff-new.json

# JSON output
hdf-cli/hdf diff /tmp/smoke-diff-old.json /tmp/smoke-diff-new.json --json

# System drift diff — create two system document versions
echo '{"name":"Sys","components":[{"name":"App","type":"application","componentId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}' > /tmp/smoke-sys-v1.json
echo '{"name":"Sys","components":[{"name":"App","type":"application","componentId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","description":"added"},{"name":"Cache","type":"application","componentId":"11111111-2222-3333-4444-555555555555"}],"dataFlows":[{"from":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","to":"11111111-2222-3333-4444-555555555555","protocol":"TCP","port":6379}]}' > /tmp/smoke-sys-v2.json
hdf-cli/hdf diff /tmp/smoke-sys-v1.json /tmp/smoke-sys-v2.json

# System diff JSON — verify componentDiffs and dataFlowChanges
hdf-cli/hdf diff /tmp/smoke-sys-v1.json /tmp/smoke-sys-v2.json --json

# System diff summary only
hdf-cli/hdf diff /tmp/smoke-sys-v1.json /tmp/smoke-sys-v2.json --stat

# Error case: mismatched types should give a clear error
hdf-cli/hdf diff /tmp/smoke-diff-old.json /tmp/smoke-sys-v1.json 2>&1 || echo "(expected: cannot diff results against system)"
```

**Expected**: Temporal diff shows requirement-level changes (fixed, regressed, etc.). System drift diff shows component-level changes (new, absent, updated) with data flow diffs. Mismatched document types produce a clear error message.

---

## 6. hdf system (bead bepb)

**Story**: A system owner bootstraps a system document from scan results, then updates it over time.

```bash
# Create system from results
hdf-cli/hdf system create --from /tmp/smoke-results.json --name "Dropwizard Prod" \
  --owner "platform-team@agency.gov" --description "Production Dropwizard" \
  -o /tmp/smoke-sys-created.json

# Verify systemId was auto-generated
python3 -c "import json; d=json.load(open('/tmp/smoke-sys-created.json')); print('systemId:', d.get('systemId')); print('owner:', d.get('owner')); print('components:', len(d.get('components', [])))"

# View system info
hdf-cli/hdf system info /tmp/smoke-sys-created.json

# Update owner
hdf-cli/hdf system set /tmp/smoke-sys-created.json --owner "new-team@agency.gov"
hdf-cli/hdf system info /tmp/smoke-sys-created.json

# Set plain text owner
hdf-cli/hdf system set /tmp/smoke-sys-created.json --owner "Platform Engineering Team"
hdf-cli/hdf system info /tmp/smoke-sys-created.json

# Unset description
hdf-cli/hdf system set /tmp/smoke-sys-created.json --unset description
python3 -c "import json; d=json.load(open('/tmp/smoke-sys-created.json')); print('description:', d.get('description', '(not set)'))"

# Try to unset required field
hdf-cli/hdf system set /tmp/smoke-sys-created.json --unset name
# Expected: error about required field

# Create system from CycloneDX SBOM (not a vuln report)
hdf-cli/hdf system create --from hdf-converters/converters/cyclonedx-to-hdf/fixtures/input/dropwizard-vulns.json --name "From SBOM" --component-name "Dropwizard" -o /tmp/smoke-sys-sbom.json
python3 -c "import json; d=json.load(open('/tmp/smoke-sys-sbom.json')); print('components:', len(d.get('components', [])))"

# Add a component from another SBOM
# (if juice-shop-sbom.json is available and has metadata)
```

**Expected**: System documents have systemId, owner, components with SBOMs. Set/unset work. Required fields are protected.

---

## 7. hdf label (bead o7gs)

**Story**: A DevSecOps pipeline stamps labels and component IDs onto HDF output.

```bash
# Show current labels
hdf-cli/hdf label show /tmp/smoke-results.json

# Set labels
cp /tmp/smoke-results.json /tmp/smoke-label-test.json
hdf-cli/hdf label set /tmp/smoke-label-test.json env=production system=Portal
hdf-cli/hdf label show /tmp/smoke-label-test.json

# Remove a label
hdf-cli/hdf label remove /tmp/smoke-label-test.json env
hdf-cli/hdf label show /tmp/smoke-label-test.json

# Stamp componentId
hdf-cli/hdf label set /tmp/smoke-label-test.json --component-id "deadbeef-1234-5678-9abc-def012345678"
python3 -c "import json; d=json.load(open('/tmp/smoke-label-test.json')); print('componentId:', d['components'][0].get('componentId'))"

# Generate unique componentIds
hdf-cli/hdf label set /tmp/smoke-label-test.json --generate-component-id
python3 -c "import json; d=json.load(open('/tmp/smoke-label-test.json')); [print(f'  {c[\"name\"]}: {c.get(\"componentId\")}') for c in d['components']]"

# Write to different file
hdf-cli/hdf label set /tmp/smoke-results.json env=staging -o /tmp/smoke-label-copy.json
```

**Expected**: Labels are applied/removed on components[]. componentId is stamped correctly. generate-component-id produces unique UUIDs.

---

## 8. hdf amend (bead hurj)

**Story**: An ISSM applies a waiver to a failing requirement.

```bash
# List current amendments (if any)
hdf-cli/hdf amend list /tmp/smoke-results.json 2>&1 || echo "(no amendments in results)"

# Apply a waiver (needs an amendments file)
# Create a minimal amendments doc
cat > /tmp/smoke-amendments.json << 'EOF'
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

hdf-cli/hdf validate --type amendments /tmp/smoke-amendments.json

# Apply amendments to results
hdf-cli/hdf amend apply --results /tmp/smoke-results.json --amendments /tmp/smoke-amendments.json -o /tmp/smoke-amended.json
```

**Expected**: Amendments validate. Apply workflow modifies effectiveStatus on matching requirements.

---

## 9. hdf generate (bead tnkj)

**Story**: A developer generates an InSpec profile stub from a baseline or XCCDF benchmark.

```bash
# Check if baseline fixture exists
ls hdf-schema/test/fixtures/minimal-baseline.json 2>/dev/null || echo "Need baseline fixture"

# Generate InSpec profile from HDF Baseline JSON
# hdf-cli/hdf generate inspec-profile $BASELINE /tmp/smoke-profile/
# ls /tmp/smoke-profile/

# Generate InSpec profile directly from XCCDF benchmark XML (auto-detected)
# hdf-cli/hdf generate inspec-profile hdf-generators/test/fixtures/stig-rhel9-benchmark.xml /tmp/smoke-xccdf-profile/
# ls /tmp/smoke-xccdf-profile/controls/

# Generate with explicit --source-type
# hdf-cli/hdf generate inspec-profile benchmark.xml /tmp/smoke-profile/ -s xccdf

# Check help
hdf-cli/hdf generate --help
hdf-cli/hdf generate inspec-profile --help
```

**Expected**: Profile directory with controls/ and inspec.yml. XCCDF input produces controls named after STIG rule versions (e.g., WN22-00-000010.rb).

---

## 10. hdf plan (bead 9g3z)

**Story**: A system owner creates and views an assessment plan.

```bash
# Check plan help
hdf-cli/hdf plan --help

# Create a minimal plan document manually
cat > /tmp/smoke-plan.json << 'EOF'
{
  "name": "Monthly STIG Scan",
  "type": "automated",
  "systemRef": "portal-prod.hdf-system.json",
  "assessments": [
    {
      "baselineRef": "RHEL9-STIG",
      "componentRef": "aaaaaaaa-1111-2222-3333-444444444444",
      "runner": {"name": "cinc-auditor", "version": "6.8.1"}
    }
  ]
}
EOF

hdf-cli/hdf validate --type plan /tmp/smoke-plan.json
```

**Expected**: Plan document validates with componentRef field.

---

## 11. hdf evidence (bead 5fhb)

**Story**: A compliance officer builds the full document chain (system → plan → results → evidence) and verifies completeness.

```bash
# --- Step 1: Create a system document ---
cat > /tmp/smoke-system.json << 'EOF'
{
  "systemId": "aaaaaaaa-1111-2222-3333-444444444444",
  "name": "Portal Prod",
  "components": [
    {"name": "WebTier", "type": "application", "baselineRefs": ["RHEL9-STIG"]},
    {"name": "DatabaseTier", "type": "application", "baselineRefs": ["PostgreSQL-STIG"]}
  ]
}
EOF
hdf-cli/hdf validate --type system /tmp/smoke-system.json

# --- Step 2: Create an assessment plan from the system ---
hdf-cli/hdf plan create /tmp/smoke-system.json -o /tmp/smoke-plan.json
hdf-cli/hdf validate --type plan /tmp/smoke-plan.json
# Plan should have 2 assessments: RHEL9-STIG, PostgreSQL-STIG

# --- Step 3: Create results for each baseline ---
cat > /tmp/smoke-rhel9-results.json << 'EOF'
{
  "baselines": [{"name": "RHEL9-STIG", "requirements": [
    {"id": "SV-257777", "title": "Vendor support", "descriptions": [{"label": "default", "data": "check"}],
     "impact": 0.7, "tags": {}, "results": [{"status": "passed", "codeDesc": "check", "startTime": "2026-03-30T00:00:00Z"}]}
  ], "supports": [], "groups": []}],
  "platform": {"name": "rhel9", "release": "9.2"},
  "statistics": {"duration": 12.5}, "version": "2.0.0"
}
EOF
hdf-cli/hdf validate --type results /tmp/smoke-rhel9-results.json

cat > /tmp/smoke-postgres-results.json << 'EOF'
{
  "baselines": [{"name": "PostgreSQL-STIG", "requirements": [
    {"id": "SV-233512", "title": "Access control", "descriptions": [{"label": "default", "data": "check"}],
     "impact": 0.5, "tags": {}, "results": [{"status": "passed", "codeDesc": "check", "startTime": "2026-03-30T00:00:00Z"}]}
  ], "supports": [], "groups": []}],
  "platform": {"name": "postgresql", "release": "15.4"},
  "statistics": {"duration": 8.2}, "version": "2.0.0"
}
EOF
hdf-cli/hdf validate --type results /tmp/smoke-postgres-results.json

# --- Step 4: Build the evidence package (auto-computes checksums) ---
hdf-cli/hdf evidence build \
  --system /tmp/smoke-system.json \
  --results /tmp/smoke-rhel9-results.json \
  -o /tmp/smoke-evidence.json
# Note: evidence build currently accepts one --results flag.
# For multiple results, add the second manually or use evidence set.

# Add the second results file and the plan reference
# (or build the evidence package manually with all files)

# --- Step 5: Verify checksums only ---
hdf-cli/hdf evidence verify /tmp/smoke-evidence.json --checksums-only
# Expected: all checksums match

# --- Step 6: Verify completeness against the plan ---
# First, set the planRef so verify can check completeness
hdf-cli/hdf evidence set /tmp/smoke-evidence.json --plan-ref smoke-plan.json

hdf-cli/hdf evidence verify /tmp/smoke-evidence.json
# Default mode: checks that every baseline in the plan (RHEL9-STIG,
# PostgreSQL-STIG) has a corresponding results document in the package.
# Will report missing baselines if any are absent.

# --- Other evidence commands ---
hdf-cli/hdf evidence info /tmp/smoke-evidence.json
hdf-cli/hdf evidence set /tmp/smoke-evidence.json --package-id "550e8400-e29b-41d4-a716-446655440000"
hdf-cli/hdf evidence set /tmp/smoke-evidence.json --description "Quarterly ATO evidence bundle"
hdf-cli/hdf validate --type evidence-package /tmp/smoke-evidence.json
```

**Expected**:
- Each document validates against its schema at creation time.
- Plan has 2 assessments derived from system components.
- Evidence build computes real SHA-256 checksums for referenced files.
- `evidence verify --checksums-only`: all checksums match.
- `evidence verify` (default): completeness check — reports if any planned baselines lack results.
- `evidence set --plan-ref`: links the evidence package to the assessment plan.
- `evidence info`: displays package name, planRef, systemRef, contents list.

---

## 11a. hdf plan

**Story**: A security engineer creates and manages assessment plans.

```bash
# Create a plan from a system document
# hdf-cli/hdf plan create portal-prod.hdf-system.json -o plan.json

# Create a standalone plan (no system document required)
hdf-cli/hdf plan create --name "RHEL9 Assessment" --baseline RHEL9-STIG -o /tmp/smoke-plan.json

# View plan info
hdf-cli/hdf plan info /tmp/smoke-plan.json

# Update plan metadata
hdf-cli/hdf plan set /tmp/smoke-plan.json --description "Monthly compliance scan"
hdf-cli/hdf plan set /tmp/smoke-plan.json --system-ref portal-prod.hdf-system.json
hdf-cli/hdf plan set /tmp/smoke-plan.json --version "1.0.0"

# Verify plan validates
hdf-cli/hdf validate --type plan /tmp/smoke-plan.json
```

**Expected**:
- Create: generates plan with auto-generated planId UUID, one assessment entry.
- Info: displays plan name, planId, assessments.
- Set: updates fields in place.
- Validate: plan passes schema validation.

---

## 11b. hdf generate/validate threshold

**Story**: A CI pipeline enforces compliance regression detection.

```bash
# Generate a threshold from HDF results
hdf-cli/hdf generate threshold hdf-schema/test/fixtures/minimal-v2.json -o /tmp/smoke-threshold.yaml

# View the generated threshold
cat /tmp/smoke-threshold.yaml

# Validate the same results against the threshold (should pass)
hdf-cli/hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -T /tmp/smoke-threshold.yaml

# Generate with control IDs included
hdf-cli/hdf generate threshold hdf-schema/test/fixtures/minimal-v2.json --include-controls

# Inline threshold validation (CI one-liner)
hdf-cli/hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -I "{compliance.min: 40}"

# Inline threshold that should fail (compliance too high)
hdf-cli/hdf validate threshold hdf-schema/test/fixtures/minimal-v2.json -I "{compliance.min: 90}" || echo "Expected failure"
```

**Expected**:
- Generate: produces YAML with compliance, passed, failed sections.
- Validate with -T: exit 0 when results meet threshold.
- --include-controls: adds control ID lists under each status/severity.
- Inline -I: parses `{key: value}` format, exit 0 on pass, exit 1 on fail.
- Round-trip: generate → validate against same file always passes.

---

## 12. hdf fetch (bead vj0i)

**Story**: A security engineer pulls findings from an API.

```bash
# Check fetch help
hdf-cli/hdf fetch --help

# List available fetch sources
hdf-cli/hdf fetch --help 2>&1 | head -20
```

**Expected**: Help text shows available API sources. (Actual API calls require credentials/endpoints.)
