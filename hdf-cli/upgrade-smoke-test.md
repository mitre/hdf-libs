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
INSPEC_HDF=hdf-converters/converters/legacyhdf-to-hdf/fixtures/expected/ubi9-scan.json
```

> Note: real-world STIG SCAP files (e.g. `stig-rhel7.xml`) often bundle a `<Benchmark>`
> together with an embedded `<TestResult>`. The XCCDF→Baseline converter currently
> rejects such inputs as "not a benchmark." The fixtures above are clean inputs
> suitable for `upgrade`. To use a SCAP-bundled file, strip the `<TestResult>`
> first.

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

Verifies HDF Results JSON auto-detects as the current side and that the
`code` field from `baselines[].requirements[]` is preserved into the
upgraded baseline.

```bash
./hdf generate upgrade $INSPEC_HDF $XCCDF_12 /tmp/upgrade-rhel7/
```

**Expected**: 452 current reqs (from UBI 9 InSpec scan) carry through with
`code` populated; 3 upstream reqs (Windows minimal benchmark) added.

```bash
python3 -c "
import json
bl = json.load(open('/tmp/upgrade-rhel7/baseline.json'))
with_code = [r for r in bl['requirements'] if r.get('code')]
print('total reqs:', len(bl['requirements']))
print('reqs with code:', len(with_code))
"
```

## Test 4: Smart merge verification

Build a customized current baseline by converting the upstream XCCDF and
injecting custom tags/descriptions. Then upgrade against the same XCCDF —
upstream scalars should adopt; current's customizations should survive.

```bash
# Seed a known-valid baseline from the upstream, then customize first req.
./hdf convert --from xccdf-benchmark $XCCDF_12 -o /tmp/seed-baseline.json
python3 -c "
import json
bl = json.load(open('/tmp/seed-baseline.json'))
bl['requirements'][0]['tags']['custom_tag'] = 'my-custom-value'
bl['requirements'][0]['descriptions'].append({'label': 'custom', 'data': 'My custom note'})
with open('/tmp/custom-current.json', 'w') as f:
    json.dump(bl, f, indent=2)
"

./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 /tmp/upgrade-smart-merge/
```

**Expected**: first requirement in output has both upstream's title/impact
*and* current's `custom_tag` and `custom` description label.

```bash
python3 -c "
import json
r = json.load(open('/tmp/upgrade-smart-merge/baseline.json'))['requirements'][0]
print('custom_tag:', r['tags'].get('custom_tag'))
print('custom desc:', any(d['label'] == 'custom' for d in r['descriptions']))
"
```

## Test 5: --prefer current

Same input as Test 4. `--prefer current` should keep current's scalars
on conflicts (no observable difference in this fixture pair, since
current and upstream scalars are already identical — but the flag should
not error and should still preserve the customizations).

```bash
./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 /tmp/upgrade-prefer-current/ --prefer current
python3 -c "
import json
r = json.load(open('/tmp/upgrade-prefer-current/baseline.json'))['requirements'][0]
print('custom_tag:', r['tags'].get('custom_tag'))
"
```

## Test 6: --prefer upstream

Same input as Test 4. `--prefer upstream` should replace tags/descriptions
entirely with upstream's — `custom_tag` should NOT be present.

```bash
./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 /tmp/upgrade-prefer-upstream/ --prefer upstream
python3 -c "
import json
r = json.load(open('/tmp/upgrade-prefer-upstream/baseline.json'))['requirements'][0]
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

## Test 10: Cross-document — large current, small upstream

A 452-req RHEL UBI 9 InSpec profile as current, the 3-req Windows
minimal benchmark as upstream. The two share the SRG-OS taxonomy so
some matches are expected; the bulk of current reqs carry through
unmatched.

```bash
./hdf generate upgrade $INSPEC_HDF $XCCDF_12 /tmp/upgrade-cross/
```

**Expected**: output baseline retains all 452 current reqs (matched ones
take upstream metadata + current code; unmatched ones pass through unchanged).
`delta.md` shows the matching tier each upstream req hit.

```bash
python3 -c "
import json
bl = json.load(open('/tmp/upgrade-cross/baseline.json'))
print('total reqs:', len(bl['requirements']))
"
grep -A 5 "Match Statistics" /tmp/upgrade-cross/delta.md | head -7
```

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
| Match-tier breakdown | `delta.md`'s "Match Statistics" section. Note: `related` can overlap with `match` (secondary strategy hits an already-matched upstream), so the four counts are not a strict partition of `totalNew`. |

## Cleanup

```bash
rm -rf /tmp/upgrade-identity /tmp/upgrade-xccdf-versions /tmp/upgrade-rhel7 \
       /tmp/upgrade-smart-merge /tmp/upgrade-prefer-current /tmp/upgrade-prefer-upstream \
       /tmp/upgrade-inspec /tmp/upgrade-both /tmp/upgrade-controls \
       /tmp/upgrade-cross /tmp/upgrade-alias \
       /tmp/seed-baseline.json /tmp/custom-current.json \
       /tmp/test-current.json /tmp/test-controls
```

## Notes

- All XCCDF fixtures are in the repo. No external downloads needed.
- XCCDF-sourced fixtures don't carry Ruby code, so code preservation tests require
  either HDF Results JSON (which carries code) or the -c flag with a controls directory.
- InSpec JSON input (`inspec json <profile>` output) is auto-detected when the
  file has `profiles[].controls[]` structure.
