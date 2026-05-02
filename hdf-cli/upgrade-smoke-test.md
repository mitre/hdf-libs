# `hdf generate upgrade` — Smoke Test Guide

## Prerequisites

```bash
cd /Users/wdower/repos/mitre/hdf-libs/hdf-cli
go build -o ../hdf ./cmd/hdf/
cd ..
```

## Fixture Paths

All fixtures are in the repo under `hdf-converters/converters/xccdf-results-to-hdf/fixtures/`.

```bash
XCCDF_12=hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/benchmark-minimal-1.2.xml
XCCDF_11=hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/benchmark-minimal-1.1.xml
RHEL7_XCCDF=hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/stig-rhel7.xml
RHEL7_HDF=hdf-converters/converters/xccdf-results-to-hdf/fixtures/expected/stig-rhel7.xml.hdf.json
```

---

## Test 1: Baseline → Baseline (identity upgrade)

Same file as both current and upstream — verify no-op merge.

```bash
./hdf generate upgrade $XCCDF_12 $XCCDF_12 /tmp/upgrade-identity/
```

**Expected**:
- `/tmp/upgrade-identity/baseline.json` exists with 3 requirements
- `delta.json` shows 3 matched, 0 no-match
- All controls are identical (no field changes in merge)

```bash
python3 -m json.tool /tmp/upgrade-identity/baseline.json | grep '"id"'
cat /tmp/upgrade-identity/delta.md
```

## Test 2: XCCDF 1.1 → 1.2 (cross-version)

```bash
./hdf generate upgrade $XCCDF_11 $XCCDF_12 /tmp/upgrade-xccdf-versions/
```

**Expected**: 3 requirements matched. Baseline.json has upstream (1.2) metadata.

## Test 3: HDF Results as current baseline

Uses RHEL7 STIG HDF Results (with code in baselines) as the current profile.

```bash
./hdf generate upgrade $RHEL7_HDF $RHEL7_XCCDF /tmp/upgrade-rhel7/
```

**Expected**: Requirements matched. Code from HDF Results preserved in baseline.json.

```bash
python3 -c "
import json
with open('/tmp/upgrade-rhel7/baseline.json') as f:
    bl = json.load(f)
for r in bl['requirements'][:3]:
    print(r['id'], 'has code' if r.get('code') else 'no code')
"
```

## Test 4: Smart merge verification

Craft a test where current has custom tags/descriptions, upstream has updated scalars.

```bash
# Create a current baseline with custom tags
python3 -c "
import json
with open('$RHEL7_HDF') as f:
    results = json.load(f)
reqs = results['baselines'][0]['requirements']
# Add custom tags and descriptions to first req
if reqs:
    reqs[0]['tags']['custom_tag'] = 'my-custom-value'
    reqs[0]['descriptions'].append({'label': 'custom', 'data': 'My custom description'})
bl = {'name': 'custom-rhel7', 'requirements': [
    {'id': r['id'], 'impact': r['impact'], 'title': r.get('title'),
     'tags': r.get('tags', {}), 'descriptions': r.get('descriptions', []),
     'code': r.get('code')} for r in reqs
], 'groups': [], 'supports': []}
with open('/tmp/custom-current.json', 'w') as f:
    json.dump(bl, f, indent=2)
" 2>/dev/null

./hdf generate upgrade /tmp/custom-current.json $RHEL7_XCCDF /tmp/upgrade-smart-merge/
```

**Expected**: `baseline.json` first requirement has:
- Upstream scalars (title, impact from XCCDF)
- Union of tags including `custom_tag: my-custom-value`
- Union of descriptions including label `custom`

```bash
python3 -c "
import json
with open('/tmp/upgrade-smart-merge/baseline.json') as f:
    bl = json.load(f)
r = bl['requirements'][0]
print('custom_tag:', r['tags'].get('custom_tag'))
print('custom desc:', any(d['label'] == 'custom' for d in r['descriptions']))
"
```

## Test 5: --prefer current

```bash
./hdf generate upgrade /tmp/custom-current.json $RHEL7_XCCDF /tmp/upgrade-prefer-current/ --prefer current
```

**Expected**: Current values win on scalar conflicts. Custom tags/descriptions still preserved.

## Test 6: --prefer upstream

```bash
./hdf generate upgrade /tmp/custom-current.json $RHEL7_XCCDF /tmp/upgrade-prefer-upstream/ --prefer upstream
```

**Expected**: Upstream replaces everything. `custom_tag` should NOT be present.

```bash
python3 -c "
import json
with open('/tmp/upgrade-prefer-upstream/baseline.json') as f:
    bl = json.load(f)
r = bl['requirements'][0]
print('custom_tag present:', 'custom_tag' in r.get('tags', {}))
"
```

## Test 7: --output-format inspec

```bash
./hdf generate upgrade $XCCDF_12 $XCCDF_12 /tmp/upgrade-inspec/ -f inspec
```

**Expected**: `inspec.yml` and `controls/*.rb` exist. No `baseline.json`.

```bash
ls /tmp/upgrade-inspec/
ls /tmp/upgrade-inspec/controls/
```

## Test 8: --output-format both

```bash
./hdf generate upgrade $XCCDF_12 $XCCDF_12 /tmp/upgrade-both/ -f both
```

**Expected**: Both `baseline.json` AND `inspec.yml` + `controls/*.rb`.

```bash
ls /tmp/upgrade-both/
```

## Test 9: -c controls/ (code enrichment)

```bash
# Create a minimal controls directory
mkdir -p /tmp/test-controls
cat > /tmp/test-controls/SV-12345.rb << 'RUBY'
control 'SV-12345' do
  describe file('/etc/passwd') do
    it { should exist }
  end
end
RUBY

# Create a minimal current baseline referencing SV-12345
python3 -c "
import json
bl = {'name': 'test', 'requirements': [
    {'id': 'SV-12345', 'impact': 0.5, 'tags': {}, 'descriptions': [{'label': 'default', 'data': 'test'}]}
], 'groups': [], 'supports': []}
with open('/tmp/test-current.json', 'w') as f:
    json.dump(bl, f)
"

./hdf generate upgrade /tmp/test-current.json $XCCDF_12 /tmp/upgrade-controls/ -c /tmp/test-controls/
```

**Expected**: Output includes InSpec profile. The `SV-12345` requirement preserves the `.rb` code from the controls directory.

## Test 10: Cross-vendor (RHEL → minimal benchmark)

Deliberate mismatch — different benchmarks with no SRG overlap.

```bash
./hdf generate upgrade $RHEL7_XCCDF $XCCDF_12 /tmp/upgrade-cross/
```

**Expected**: Most/all upstream reqs are no-match. Unmatched current reqs included as-is. `delta.md` shows matching strategies attempted.

## Test 11: `hdf generate delta` alias

```bash
./hdf generate delta $XCCDF_12 $XCCDF_12 /tmp/upgrade-alias/
```

**Expected**: Same output as Test 1. The `delta` alias works identically to `upgrade`.

## What to check in each test

| Check | Command |
|-------|---------|
| Stderr statistics | Printed during run |
| baseline.json valid | `python3 -m json.tool /tmp/upgrade-*/baseline.json > /dev/null` |
| Requirement count | `python3 -c "import json; print(len(json.load(open('/tmp/upgrade-*/baseline.json'))['requirements']))"` |
| inspec.yml valid | `cat /tmp/upgrade-*/inspec.yml` (when -f inspec/both) |
| Mapping report | `cat /tmp/upgrade-*/delta.md` |
| JSON report parseable | `python3 -m json.tool /tmp/upgrade-*/delta.json > /dev/null` |
| Stats invariant | In `delta.md`: matched + related + noMatch = totalNew |

## Cleanup

```bash
rm -rf /tmp/upgrade-identity /tmp/upgrade-xccdf-versions /tmp/upgrade-rhel7 \
       /tmp/upgrade-smart-merge /tmp/upgrade-prefer-current /tmp/upgrade-prefer-upstream \
       /tmp/upgrade-inspec /tmp/upgrade-both /tmp/upgrade-controls \
       /tmp/upgrade-cross /tmp/upgrade-alias \
       /tmp/custom-current.json /tmp/test-current.json /tmp/test-controls
```

## Notes

- All XCCDF fixtures are in the repo. No external downloads needed.
- XCCDF-sourced fixtures don't carry Ruby code, so code preservation tests require
  either HDF Results JSON (which carries code) or the -c flag with a controls directory.
- InSpec JSON input (`inspec json <profile>` output) is auto-detected when the
  file has `profiles[].controls[]` structure.
