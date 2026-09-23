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
✓ results.json passed all thresholds
```

Exit code 0. When a bound is breached, the command names which one and exits 1:

```bash
hdf validate threshold results.json -I "{failed.total.max: 0}"
```

```
Agent-attributed overrides: 0
✗ results.json — 1 threshold violation

  Violations:
    failed.total: 1 exceeds maximum 0
```

`-I` takes bounds inline instead of from a file. It is useful for a one-off check or for trying a bound before committing it; a real gate belongs in a file, under review, next to the code it governs.

A compliance floor reads the same way:

```bash
hdf validate threshold results.json -I "{compliance.min: 80}"
```

```
Agent-attributed overrides: 0
✗ results.json — 1 threshold violation

  Violations:
    compliance 25.00% is below minimum 80.00%
```

## Apply more than one threshold

`-T` and `-I` are repeatable, and they may be combined. Every spec is evaluated against the document and the run fails if any of them fails, so an org-wide baseline and a repo-specific overlay compose without anyone hand-merging YAML:

```bash
hdf validate threshold results.json -T baseline.yaml -T repo.yaml
```

```
Agent-attributed overrides: 0
✗ results.json — 1 threshold violation

  Violations:
    [baseline.yaml] failed.critical: 2 exceeds maximum 0
```

The specs are never merged into one policy. Each is evaluated on its own and the violations are pooled, so two specs bounding the same key need no precedence rule — the stricter one simply fails on its own terms. A violation names the spec it came from, and so does a pass:

```
✓ results.json passed all 2 thresholds
    baseline.yaml
    repo.yaml
```

A single file may also hold several policies, separated by `---`. Those are named by file and position, counting policies from 1 — `policy.yaml#1`, `policy.yaml#2` — so no threshold document is obliged to carry a name. A separator introducing no document, such as a trailing `---` or a comment, is not a policy and is ignored.

An inline spec names itself by its own text, because that is what you typed:

```
    [-I '{failed.total.max: 0}'] failed.total: 1 exceeds maximum 0
```

`-F` operates on files, not specs: every spec is always evaluated against a document, so one run shows every policy it broke, and `-F` decides only whether the next document is read.

## Rules: policies the grid cannot express

The bounds above are a fixed grid — five statuses by five severities, plus compliance. It can say "no failing criticals". It cannot say "nothing still failing without a remediation plan", because it has no way to talk about amendments.

A `rules:` section adds that. A rule is a filter predicate plus a bound:

```yaml
rules:
  - name: nothing fails without a plan
    where:
      status: [failed]
      poams: none-valid
    max: 0
```

```
✗ results.json — 1 threshold violation

  Violations:
    nothing fails without a plan: 1 matched, maximum 0
```

The predicate is the filter vocabulary `hdf query` already speaks, so a gate can be prototyped with a query and pasted into a spec. Values within a field OR together; different fields AND. Rules sit beside the grid rather than replacing it — both are bounds in one policy, and every one must hold.

`status` is the EFFECTIVE status, so amendments are already applied when a rule sees the document. That is what makes the example above express the whole posture in one line: a requirement suppressed by a waiver is no longer `failed`, so the rule asks only about findings nobody has adjudicated. Either something is suppressed by an override that records an owner and an expiry, or it carries a live POA&M, or it fails the gate.

`poams: none-valid` deliberately covers "no POA&M", "an empty list" and "only lapsed ones" as one condition, because a plan that has expired is not a plan.

A rule bounds a count, not a percentage — `compliance` remains the only percentage bound — and it evaluates over the whole document. To narrow it to one baseline, say so in the predicate with `baseline`.

### A predicate that can never match is refused

A value outside its vocabulary returns nothing for every document, so a rule built on one passes forever while looking like a gate:

```
$ hdf validate threshold results.json -I '{rules: [{name: r, where: {status: [faild]}, max: 0}]}'
Error: failed to parse inline threshold: -I: r: status "faild" is not a known value
(expected one of: passed, failed, notApplicable, notReviewed, error)
```

A predicate that merely matches nothing *today* is a healthy gate and is accepted — rejecting it would fail a working policy the day its findings are fixed. The distinction is whether the value names something, not whether anything currently has it.

### Inline and file are the same language

Anything expressible in a file is expressible with `-I`, because a structured inline spec goes through the same decoder a file does:

```bash
hdf validate threshold results.json -I '{rules: [{name: no failures, where: {status: [failed]}, max: 0}]}'
```

The dotted SAF form (`-I "{failed.total.max: 0}"`) still works and is told apart by its keys: a top-level key carrying a `.` is the dotted form, anything else is a structured spec.

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
