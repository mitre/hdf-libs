# Thresholds End to End

A scanner tells you what it found. A threshold tells you whether that is acceptable.

Without one, a pipeline has two options, and neither is good. It can trust the scanner's exit code — a single bit, chosen by the scanner's author, that usually means "did I crash" rather than "is this release safe". Or it can parse the scanner's output itself, which means writing and maintaining a parser per tool, in the pipeline, forever.

A threshold is the third option: a committed, reviewable policy file, applied to a normalized HDF document, that decides pass or fail. Because it runs against HDF rather than a vendor format, the same policy shape works for every tool the converters support.

## What a threshold asserts

A threshold sets bounds on counts. Counts of what, sliced two ways:

- **by status** — `passed`, `failed`, `skipped`, `error`, `no_impact`
- **by severity within that status** — `critical`, `high`, `medium`, `low`, `informational`, and `total` for all severities at once

Each bound takes a `min`, a `max`, or both. There is also a top-level `compliance` bound on the overall percentage.

So `failed.critical.max: 0` reads as "no failed critical requirements", and `compliance.min: 80` as "at least 80% compliant". That is the whole model.

## Start from a real document

You rarely want to write the first one by hand. `hdf generate threshold` reads a document and writes the policy it satisfies right now:

```bash
hdf convert --from checkov scan.json -o results.json
hdf generate threshold results.json -o threshold.yaml
```

```yaml
compliance:
    min: 25
passed:
    medium:
        min: 1
    total:
        min: 1
failed:
    medium:
        max: 1
    total:
        max: 1
skipped:
    medium:
        max: 2
    total:
        max: 2
```

That is a description of today, not a policy you necessarily want — it locks in the one failure this scan happened to have. Treat it as a starting point to edit down, which is the point: you are editing a file rather than staring at a blank one.

## Check a document against it

```bash
hdf validate threshold results.json -T threshold.yaml
```

```
Agent-attributed overrides: 0
All thresholds passed
```

Exit code 0. When a bound is breached, the command names which one and exits 1:

```bash
hdf validate threshold results.json -I "{failed.total.max: 0}"
```

```
Agent-attributed overrides: 0
FAIL: failed.total: 1 exceeds maximum 0

1 threshold violation(s)
```

`-I` takes bounds inline instead of from a file. It is useful for a one-off check or for trying a bound before committing it; a real gate belongs in a file, under review, next to the code it governs.

A compliance floor reads the same way:

```bash
hdf validate threshold results.json -I "{compliance.min: 80}"
```

```
Agent-attributed overrides: 0
FAIL: compliance 25.00% is below minimum 80.00%

1 threshold violation(s)
```

## Examples

**No critical or high failures.** The most common gate. It says nothing about medium and low, so a finding at those severities does not block the build:

```yaml
failed:
    critical:
        max: 0
    high:
        max: 0
```

**A compliance floor with a severity ceiling.** Allows some failures, but not serious ones, and requires the overall score to hold:

```yaml
compliance:
    min: 25
failed:
    critical:
        max: 0
    high:
        max: 0
```

**Nothing regressed.** `max: 0` on total failures is the strictest useful form — any failure at any severity stops the pipeline:

```yaml
failed:
    total:
        max: 0
```

**A skip budget.** `skipped` maps to requirements that were not evaluated. A suite that quietly stops running checks is green everywhere else, so a ceiling here catches what no exit code can:

```yaml
skipped:
    total:
        max: 2
```

**Pin an exact control list.** `--include-controls` records which specific controls are in each bucket, not just how many:

```bash
hdf generate threshold results.json --include-controls -o threshold.yaml
```

```yaml
# abridged — the file also carries compliance, the total bounds, and skipped
passed:
    medium:
        min: 1
        controls:
            - CKV_TF_2
failed:
    medium:
        max: 1
        controls:
            - CKV_TF_1
```

Now the gate fails if `CKV_TF_1` starts passing, or if a different control fails in its place. That is stricter than a count and suits a baseline you expect to be stable; it is noisy for a scan whose findings move around.

## Gate a GitHub pipeline

Two steps. Convert, then check:

```yaml
- name: Convert the scan to HDF
  run: hdf convert --from checkov scan.json -o results.json

- name: Apply the threshold
  run: hdf validate threshold results.json -T .github/thresholds/checkov.yaml
```

That is the whole integration. `hdf validate threshold` exits non-zero on a violation, which fails the step, which fails the job — no wrapper script, no output parsing, no `jq`.

Keep the policy file in the repository next to the workflow that applies it. It is reviewed like code, and its history shows when a bound was loosened and by whom — which is usually the question being asked after an incident.

## Where to go next

- [Status determination](../architecture/status-determination.md) — how a requirement's status and severity are decided before a threshold ever counts them, including the effect of amendments
- [Amendments end to end](./amendments-workflow.md) — waiving or risk-adjusting a finding so it stops tripping a gate for a recorded reason, rather than loosening the gate for everyone
