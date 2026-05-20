# `hdf generate upgrade` — Smoke Test Guide

Validates `hdf generate upgrade` end-to-end. The primary workflow is
**in-place update of an existing InSpec profile** to track a newer
XCCDF release — equivalent to SAF CLI's `update_controls4delta` +
`delta` collapsed into one command. Most of this guide exercises that
path. A file-input mode (for direct baseline-to-baseline upgrades
without a profile dir) is covered toward the end.

## Prerequisites

Build the `hdf` binary. Run from the repo root:

```bash
(cd hdf-cli && go build -o ../hdf ./cmd/hdf/)
```

All commands below assume the repo root as the working directory, with
the freshly built `./hdf` binary there.

For the in-place tests:
- [cinc-auditor](https://cinc.sh/start/auditor/) or
  [inspec](https://docs.chef.io/inspec/install/) on PATH — upgrade
  shells out to one of them to extract control metadata from a profile
  directory.
- For SAF parity (Test 4 below): SAF CLI on PATH (`saf --version`).

## Shared setup for in-place tests

The headline workflow uses the publicly available redhat baseline
profile, upgrading from its v1.14.1 release to RHEL 8 V2R1 (the next
major DISA STIG version).

```bash
# Clone the source profile at v1.14.1
git clone https://github.com/mitre/redhat-enterprise-linux-8-stig-baseline /tmp/redhat-baseline
git -C /tmp/redhat-baseline switch --detach v1.14.1

# Download the target XCCDF (V2R1) from cyber.trackr.live
curl -sL "https://cyber.trackr.live/stig/Red_Hat_Enterprise_Linux_8/2/1/download" \
  -o /tmp/RHEL8_V2R1.xml
```

The v1.14.1 → V2R1 jump has well-known characteristics:
- 366 controls keep their IDs (text/check/fix updates only)
- 1 control was renamed: **SV-244540 → SV-268322**
- 8 controls were retired (no replacement)
- Total: 375 in v1.14.1, 367 in V2R1

---

## Test 1: Default in-place upgrade

The headline workflow. Run upgrade against the profile directory with
no `-o` — outputs land back in the profile.

```bash
# Make a working copy so we don't have to reclone for subsequent tests
cp -r /tmp/redhat-baseline /tmp/redhat-inplace

./hdf generate upgrade /tmp/redhat-inplace /tmp/RHEL8_V2R1.xml
```

**Expected output**:
```
Updated 367 controls in /tmp/redhat-inplace/controls (9 stale .rb files pruned)
Upgrade: 367 match, 0 possible mismatch, 0 related, 0 no match (of 367 upstream from 375 current)
Updated profile in-place at /tmp/redhat-inplace; reports in /tmp/redhat-inplace/.upgrade
```

The "9 stale .rb files pruned" = 8 truly deprecated + 1 renamed source (SV-244540).

**Verifications**:

```bash
# Control count dropped from 375 to 367
ls /tmp/redhat-inplace/controls/*.rb | wc -l                       # 367

# Original inspec.yml preserved verbatim (not overwritten)
head -1 /tmp/redhat-inplace/inspec.yml                             # name: redhat-enterprise-linux-8-stig-baseline

# Profile structure intact (Gemfile, libraries/, etc. untouched)
ls /tmp/redhat-inplace/Gemfile /tmp/redhat-inplace/libraries

# Reports landed in .upgrade/
ls /tmp/redhat-inplace/.upgrade/                                   # baseline.json delta.json delta.md

# Stale rename source pruned, new ID written
ls /tmp/redhat-inplace/controls/SV-244540.rb 2>&1                  # No such file
ls /tmp/redhat-inplace/controls/SV-268322.rb                       # exists

# Profile passes cinc-auditor check cleanly
cinc-auditor check /tmp/redhat-inplace                             # Valid: true, 0 errors/warnings/offenses
```

**Rename rewrite — critical verification**:

The SV-244540 → SV-268322 rename should produce a clean `.rb` file
with a single control block and its inner control declaration renamed
to match. If it has two nested control blocks, the bug fix has
regressed.

```bash
test "$(grep -c "^control '" /tmp/redhat-inplace/controls/SV-268322.rb)" -eq 1 \
  && echo "✓ single control block"
grep -q "control 'SV-268322' do" /tmp/redhat-inplace/controls/SV-268322.rb \
  && echo "✓ wrapper renamed to SV-268322"
grep -q "control 'SV-244540' do" /tmp/redhat-inplace/controls/SV-268322.rb \
  && echo "✗ stale SV-244540 wrapper present (REGRESSION)"
ruby -c /tmp/redhat-inplace/controls/SV-268322.rb                  # Syntax OK
```

**All .rb files should be valid Ruby with single control declarations**:

```bash
for f in /tmp/redhat-inplace/controls/*.rb; do
  c=$(grep -c "^control '" "$f")
  [ "$c" -gt 1 ] && echo "NESTED: $f (count=$c)"
  ruby -c "$f" >/dev/null || echo "PARSE FAIL: $f"
done
echo "(no NESTED or PARSE FAIL lines above = clean)"
```

## Test 2: Fresh-copy mode (-o leaves original alone)

When `-o` is provided, the original profile dir is untouched and a
fresh copy is written to `-o`. Useful for reviewing the upgrade
before committing it back.

```bash
./hdf generate upgrade /tmp/redhat-baseline /tmp/RHEL8_V2R1.xml -o /tmp/redhat-fresh
```

**Verifications**:

```bash
# Original profile untouched
ls /tmp/redhat-baseline/controls/*.rb | wc -l                      # still 375

# Fresh copy has the upgraded state
ls /tmp/redhat-fresh/controls/*.rb | wc -l                         # 367
head -1 /tmp/redhat-fresh/inspec.yml                               # original inspec.yml preserved in copy
ls /tmp/redhat-fresh/.upgrade/                                     # baseline.json delta.json delta.md

# Full profile structure copied, not just controls/
ls /tmp/redhat-fresh/Gemfile /tmp/redhat-fresh/libraries

cinc-auditor check /tmp/redhat-fresh                               # Valid: true
```

## Test 3: `--keep-unmatched` preserves deprecated controls

By default, controls present in current but absent from upstream are
dropped (matching SAF CLI's "the new XCCDF is truth" semantics).
`--keep-unmatched` preserves them — useful when the profile has custom
controls outside the DISA STIG, or you want to see what would be
dropped before committing.

```bash
cp -r /tmp/redhat-baseline /tmp/redhat-keep
./hdf generate upgrade /tmp/redhat-keep /tmp/RHEL8_V2R1.xml --keep-unmatched
```

**Verifications**:

```bash
# Output: 367 matched (with the rename target SV-268322 replacing
# the renamed source SV-244540) + 8 unmatched-current preserved = 375.
# SV-244540 is still pruned — it was matched to SV-268322 and replaced,
# not unmatched.
ls /tmp/redhat-keep/controls/*.rb | wc -l                          # 375

# Confirm the 8 deprecated controls survive
for id in SV-230348 SV-230349 SV-230350 SV-230353 SV-230368 SV-244537 SV-245540 SV-251717; do
  test -f "/tmp/redhat-keep/controls/${id}.rb" && echo "✓ $id preserved"
done
```

## Test 4: SAF CLI parity comparison

The headline parity test. Run both tools on identical inputs and
verify HDF matches SAF's output count + catches an additional rename
SAF misses.

```bash
# SAF needs profile.json as input
cp -r /tmp/redhat-baseline /tmp/redhat-saf-source
cinc-auditor json /tmp/redhat-saf-source > /tmp/profile.json

# SAF run
saf generate delta -X /tmp/RHEL8_V2R1.xml -J /tmp/profile.json \
  -r /tmp/saf-out/report.md -o /tmp/saf-out/

# HDF run
cp -r /tmp/redhat-baseline /tmp/redhat-hdf-cmp
./hdf generate upgrade /tmp/redhat-hdf-cmp /tmp/RHEL8_V2R1.xml
```

**Count parity**:

```bash
ls /tmp/saf-out/controls/*.rb | wc -l                              # 367
ls /tmp/redhat-hdf-cmp/controls/*.rb | wc -l                       # 367
diff <(ls /tmp/saf-out/controls/ | sort) <(ls /tmp/redhat-hdf-cmp/controls/ | sort)
# (no diff output = identical filename sets)
```

**Rename catch — where HDF wins**:

SAF uses exact-ID matching and treats SV-268322 as net-new (it doesn't
exist in v1.14.1). HDF uses SRG+CCI matching and identifies it as a
rename of SV-244540, so SV-268322.rb inherits the current code body.

```bash
# SAF's SV-268322.rb is a fresh stub — no preserved code
head -15 /tmp/saf-out/controls/SV-268322.rb

# HDF's SV-268322.rb is the merged body (current code + upstream metadata)
head -15 /tmp/redhat-hdf-cmp/controls/SV-268322.rb

# Compare body lengths — HDF's should be larger (it has real test code)
wc -l /tmp/saf-out/controls/SV-268322.rb /tmp/redhat-hdf-cmp/controls/SV-268322.rb
```

**UX difference — profile-dir completeness**:

SAF emits ONLY `controls/`, `delta.json`, `report.md`. No `inspec.yml`,
so `cinc-auditor check /tmp/saf-out/` fails ("doesn't look like a
supported profile structure"). The user is expected to splice the
controls into an existing profile dir.

HDF updates in place (or copies the whole profile when `-o` is given),
so `cinc-auditor check` runs out of the box.

```bash
cinc-auditor check /tmp/saf-out 2>&1 | tail -3                     # fails: not a profile structure
cinc-auditor check /tmp/redhat-hdf-cmp 2>&1 | tail -3              # passes: Valid: true
```

---

## File-input mode

When `<current>` is a JSON or XML file (not a profile directory),
upgrade emits the upgraded `baseline.json`. With no `-o` it streams to
stdout (pipe-friendly); with `-o <dir>` it's written to disk. Delta
reports are written only when `--report-dir` is given. Each artifact
has exactly one flag: `-o` for the baseline, `--report-dir` for the
reports. To turn baseline.json into an InSpec profile, chain
`hdf generate inspec-profile`.

```bash
XCCDF_12=hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/benchmark-minimal-1.2.xml
XCCDF_11=hdf-converters/converters/xccdf-results-to-hdf/fixtures/input/benchmark-minimal-1.1.xml
INSPEC_HDF=hdf-converters/converters/legacyhdf-to-hdf/fixtures/expected/ubi9-scan.json
```

## Test 5: Baseline to stdout (no -o)

File input with no `-o` streams `baseline.json` to stdout. In this
mode upgrade acts as a filter — stderr stays empty (no stats, no
summary), so it composes cleanly in a pipe.

```bash
# Pipe straight into jq
./hdf generate upgrade $XCCDF_12 $XCCDF_12 | jq '.requirements | length'
# Expected: 3

# stdout is pure JSON; stderr is empty
./hdf generate upgrade $XCCDF_12 $XCCDF_12 > /tmp/up-stdout.json 2> /tmp/up-stderr.txt
python3 -m json.tool /tmp/up-stdout.json > /dev/null && echo "✓ stdout is valid JSON"
test ! -s /tmp/up-stderr.txt && echo "✓ stderr is empty (filter mode)"

# No delta reports written (no --report-dir); nothing hits disk
```

## Test 6: Baseline to stdout + reports via --report-dir

```bash
./hdf generate upgrade $XCCDF_12 $XCCDF_12 --report-dir /tmp/up-reports/ > /tmp/up-bl.json 2> /tmp/up-stderr.txt
ls /tmp/up-reports/                                                # delta.json delta.md
python3 -m json.tool /tmp/up-bl.json > /dev/null && echo "✓ baseline on stdout"
cat /tmp/up-stderr.txt   # only "Wrote delta reports to /tmp/up-reports/" — no match stats
```

## Test 7: Baseline to a file (-o)

```bash
./hdf generate upgrade $XCCDF_12 $XCCDF_12 -o /tmp/upgrade-identity/
ls /tmp/upgrade-identity/                                          # baseline.json only (no reports — no --report-dir)
python3 -c "import json; bl=json.load(open('/tmp/upgrade-identity/baseline.json')); print('reqs:', len(bl['requirements']))"
# Expected: 3 reqs
```

## Test 8: XCCDF 1.1 → 1.2 cross-version

```bash
./hdf generate upgrade $XCCDF_11 $XCCDF_12 -o /tmp/upgrade-xccdf-versions/
python3 -c "
import json
bl = json.load(open('/tmp/upgrade-xccdf-versions/baseline.json'))
print('first title:', (bl['requirements'][0].get('title') or '')[:60])
"
# Expected: 3 reqs, upstream metadata adopted
```

## Test 9: HDF Results as current (default drop, then --keep-unmatched)

```bash
# Default: drop unmatched-current
./hdf generate upgrade $INSPEC_HDF $XCCDF_12 -o /tmp/upgrade-rhel7-default/
python3 -c "
import json
bl = json.load(open('/tmp/upgrade-rhel7-default/baseline.json'))
print('default reqs:', len(bl['requirements']))
print('with code:', sum(1 for r in bl['requirements'] if r.get('code')))
"
# Expected: 3 reqs (only matched), code preserved on all 3

./hdf generate upgrade $INSPEC_HDF $XCCDF_12 -o /tmp/upgrade-rhel7-keep/ --keep-unmatched
python3 -c "
import json
bl = json.load(open('/tmp/upgrade-rhel7-keep/baseline.json'))
print('keep reqs:', len(bl['requirements']))
print('with code:', sum(1 for r in bl['requirements'] if r.get('code')))
"
# Expected: 452 reqs (everything preserved), code on all 452
```

## Test 10: Smart merge — custom tags and descriptions survive

```bash
# Seed a customized current baseline from the upstream
./hdf convert --from xccdf-benchmark $XCCDF_12 -o /tmp/seed-baseline.json
python3 -c "
import json
bl = json.load(open('/tmp/seed-baseline.json'))
bl['requirements'][0]['tags']['custom_tag'] = 'my-custom-value'
bl['requirements'][0]['descriptions'].append({'label': 'custom', 'data': 'My custom note'})
json.dump(bl, open('/tmp/custom-current.json', 'w'), indent=2)
"

./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 -o /tmp/upgrade-smart-merge/
python3 -c "
import json
r = json.load(open('/tmp/upgrade-smart-merge/baseline.json'))['requirements'][0]
print('custom_tag:', r['tags'].get('custom_tag'))
print('custom desc:', any(d['label'] == 'custom' for d in r['descriptions']))
"
# Expected: custom_tag=my-custom-value, custom desc=True
```

## Test 11: `--prefer current` and `--prefer upstream`

Same input as Test 10. Verify the conflict-resolution variants.

```bash
./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 -o /tmp/upgrade-prefer-current/ --prefer current
python3 -c "
import json
r = json.load(open('/tmp/upgrade-prefer-current/baseline.json'))['requirements'][0]
print('custom_tag:', r['tags'].get('custom_tag'))
"
# Expected: custom_tag preserved (current wins)

./hdf generate upgrade /tmp/custom-current.json $XCCDF_12 -o /tmp/upgrade-prefer-upstream/ --prefer upstream
python3 -c "
import json
r = json.load(open('/tmp/upgrade-prefer-upstream/baseline.json'))['requirements'][0]
print('custom_tag present:', 'custom_tag' in r.get('tags', {}))
"
# Expected: custom_tag absent (upstream replaces all)
```

## Test 12: `delta` alias

```bash
./hdf generate delta $XCCDF_12 $XCCDF_12 -o /tmp/upgrade-alias/
diff -q <(python3 -m json.tool /tmp/upgrade-identity/baseline.json) \
        <(python3 -m json.tool /tmp/upgrade-alias/baseline.json) \
  && echo "✓ alias output matches identity"
```

---

## Cross-cutting checks

| Check | Command template |
|---|---|
| `baseline.json` valid JSON | `python3 -m json.tool /tmp/<dir>/baseline.json > /dev/null` |
| `delta.json` parseable | `python3 -m json.tool /tmp/<dir>/delta.json > /dev/null` |
| Match-tier breakdown | `grep -A 5 "Match Statistics" /tmp/<dir>/delta.md` (note: `related` may overlap with `match` — not a strict partition) |
| Profile passes cinc check | `cinc-auditor check /tmp/<profile-dir>` |
| No nested control blocks | `for f in /tmp/<dir>/controls/*.rb; do c=$(grep -c "^control '" "$f"); [ "$c" -gt 1 ] && echo "NESTED: $f"; done` |
| All .rb files parse as Ruby | `for f in /tmp/<dir>/controls/*.rb; do ruby -c "$f" >/dev/null \|\| echo "FAIL: $f"; done` |

## Cleanup

```bash
# In-place test artifacts
rm -rf /tmp/redhat-baseline /tmp/redhat-inplace /tmp/redhat-fresh \
       /tmp/redhat-keep /tmp/redhat-saf-source /tmp/redhat-hdf-cmp \
       /tmp/saf-out

# File-input test artifacts
rm -rf /tmp/upgrade-identity /tmp/upgrade-xccdf-versions \
       /tmp/upgrade-rhel7-default /tmp/upgrade-rhel7-keep \
       /tmp/upgrade-smart-merge /tmp/upgrade-prefer-current \
       /tmp/upgrade-prefer-upstream /tmp/upgrade-alias /tmp/up-reports

# Intermediates
rm -f /tmp/profile.json /tmp/RHEL8_V2R1.xml \
      /tmp/seed-baseline.json /tmp/custom-current.json \
      /tmp/up-stdout.json /tmp/up-stderr.txt /tmp/up-bl.json
```

## Notes

- `cinc-auditor` / `inspec` are **external tools**, not bundled with
  HDF CLI. For profile-directory inputs, `hdf generate upgrade` shells
  out to whichever one it finds on `PATH` (probing `cinc-auditor`
  first, then `inspec`) to run `inspec json` and extract control
  metadata. If neither is installed, the command errors and tells you
  to install one or pre-generate `profile.json` yourself. Both tools
  produce equivalent `inspec json` output for this purpose.
- `--id-type` (rule | group | cis | version) is for XCCDF inputs and
  was not exercised here — only relevant when migrating between
  vendors with different ID conventions.
- `--strategy` overrides the matching chain (advanced; default order
  works for STIG → STIG upgrades).
- The `delta` alias exists for SAF CLI muscle memory; new code should
  use `upgrade`.
