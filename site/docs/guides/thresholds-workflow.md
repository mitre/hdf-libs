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

Compliance is worth stating exactly, because the denominator surprises people:

```
compliance = passed / (passed + failed + skipped + error)
```

`not_applicable` is excluded entirely — a requirement that does not apply to the target is not held against it. **`not_reviewed` is not excluded**; it lands in `skipped` and counts against you. That is the intended reading, since a control nobody evaluated is not a control you satisfied, but it means a compliance floor is partly a measure of scan *coverage*: a suite that quietly stops evaluating controls drives the number down without a single new failure. Pair the floor with a `skipped` ceiling rather than relying on it alone.

It also means **a compliance bound is unreliable on a document built from an InSpec overlay chain**, and this is worth checking before you set a number. A wrapper or overlay layer carries requirement *definitions* and inherits execution, so its requirements are structurally `not_reviewed` — they were never going to run. They still land in `skipped` and still enter the denominator.

A real three-layer RHEL 9 scan shows the size of the effect. The whole document reports 134 passed, 271 failed, 233 not applicable and 965 not reviewed, for **9.78%**. But 913 of those 965 belong to two wrapper layers that execute nothing; the baseline that actually ran holds 133 passed, 258 failed and 21 not reviewed, which is **32.28%**. The first number describes the document's layering, the second describes the host's posture.

`compliance` evaluates over the whole document and cannot be narrowed — unlike a rule, which takes `baseline`. So on a layered document, prefer a rule over the baseline that really ran:

```yaml
rules:
  - name: no more than 11 failing highs on the baseline that ran
    where:
      baseline: redhat-enterprise-linux-9-stig-baseline
      status: failed
      severity: high
    max: 11
```

The scoping is doing real work there: this document has 15 failing `high` requirements overall but 11 in that baseline, the other 4 coming from the k8s-node layer.

A rule bounds a count rather than a percentage, so this is not a drop-in replacement for a floor. Until a percentage can be scoped, a compliance bound on a layered document is best set against the number that document actually reports, with a comment saying why it looks low.

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
      CKV_TF_1  Ensure Terraform module sources use a commit hash  [failed/medium]
```

Each violation lists the requirements that breached it; `--no-findings` suppresses that list. `-I` takes bounds inline instead of from a file. It is useful for a one-off check or for trying a bound before committing it; a real gate belongs in a file, under review, next to the code it governs.

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
✗ results.json — 2 threshold violations

  Violations:
    [baseline.yaml] failed.medium: 1 exceeds maximum 0
      CKV_TF_1  Ensure Terraform module sources use a commit hash  [failed/medium]
    [repo.yaml] compliance 25.00% is below minimum 50.00%
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
      CKV_TF_1  Ensure Terraform module sources use a commit hash  [failed/medium]
```

## Check several documents in one run

Pass as many documents as you like. Each is checked against every spec and reports its own verdict:

```bash
hdf validate threshold grype.json prisma.json zap.json -T policy.yaml
```

```
grype.json: ok
Agent-attributed overrides: 0
✗ prisma.json — 1 threshold violation

  Violations:
    failed.critical: 32 exceeds maximum 0
      46-CVE-2016-1583  my-fake-host-1.somewhere.cloud-redhat-RHEL7-image  [failed/critical]
      46-CVE-2016-1583  my-fake-host-2.somewhere.cloud-redhat-RHEL7-image  [failed/critical]
      ...
zap.json: ok

Results: 2/3 passed thresholds, 1 failed
Error: threshold validation
```

Exit code is 1 if any document failed, 0 only if all of them passed. A passing document gets one short line; a failing one gets the same verdict a single-file run would print, so the breached bound and the requirements under it are named without re-running anything. That matters in CI, where one pipeline step typically checks one document per tool — a red step that named neither the file nor the reason used to mean opening an artifact to find out which tool broke.

A document that fails *before* a verdict can exist — unreadable, or not valid HDF — says so on its own line and prints the reason at the end:

```
grype.json: ok
broken.json: error
zap.json: ok

Results: 2/3 passed thresholds, 1 failed

broken.json:
  failed to parse HDF results: schema validation failed: validation error: invalid character 'n' looking for beginning of object key string
Error: threshold validation
```

So the two failure modes stay distinguishable: a document that breached a policy, and a document that was never checked at all.

`-F` stops after the first file that fails rather than checking the rest. It operates on files, not specs: every spec is always evaluated against a document, so one run always shows every policy that document broke, and `-F` decides only whether the *next* document is read.

A single-file run keeps its original shape, with no per-file prefix line — so adding a second document changes the output format, which is worth knowing if anything downstream parses it.

### Naming a document that arrives on stdin

Passing file paths is what makes a bulk verdict attributable. A pipeline that *streams* documents instead has no filename to report, so every verdict reads the same placeholder:

```console
$ for tool in grype epss; do cat "$tool.json" | hdf validate threshold - -T policy.yaml; done
✗ <stdin> — 1 threshold violation
✗ <stdin> — 1 threshold violation
```

Two red checks and nothing to tell them apart. `--source-name` supplies the name:

```console
$ for tool in grype epss; do
    cat "$tool.json" | hdf validate threshold - -T policy.yaml --source-name "$tool.json"
  done
✗ grype.json — 1 threshold violation
✗ epss.json — 1 threshold violation
```

It applies to both verdicts, and without it `<stdin>` is unchanged — so nothing shifts for a pipeline already piping. `hdf validate` takes the same flag, since it names documents through the same code.

Passing it alongside a real file argument is **refused** rather than preferred or ignored:

```console
$ hdf validate threshold grype.json -T policy.yaml --source-name other.json
Error: --source-name names a document read from stdin; drop it, or pass - instead of grype.json
```

A name that overrode a real filename could misattribute a failure, which is the opposite of what the flag is for, and one name cannot label several documents.

A name must contain no control or line-separator characters. A verdict is one line, so a newline in the value would forge a second line that reads as a verdict — which matters precisely because the label often comes from a filename or matrix value the pipeline author did not choose:

```console
$ hdf validate threshold - -T policy.yaml --source-name $'clean.json\n✓ other.json passed all thresholds'
Error: --source-name must not contain control or line-separator characters; found '\n' at byte 10
```

Refused rather than quietly stripped: a trimmed label would name something that is not the document, which is the attribution failure the flag exists to prevent.

The rule covers ASCII control characters, DEL, C1 (so U+0085 NEL) and the Unicode line separators U+2028/U+2029. Bidi marks and zero-width joiners are *not* refused — a blanket rule there would reject legitimate Persian and Indic filenames.

## Rules: selecting by field rather than by id

Everything above selects in one of two ways: a count within a status-and-severity bucket, or a named control that must land in a given bucket. Between them they cover a lot — "no failing criticals" is a count, and "`CKV_TF_1` must keep failing" is an exact control list.

What neither can do is select by a requirement's *fields*. `controls` names a requirement by id; nothing can say "requirements **where** something is true of them". So "nothing still failing without a remediation plan" is inexpressible, not because the bounds are too coarse, but because no part of the file can talk about the amendments layer — or about CVSS, EPSS, KEV, tags or disposition.

That is what a rule adds. A rule is a filter predicate plus a bound:

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
      CKV_TF_1  Ensure Terraform module sources use a commit hash  [failed/medium]
```

The predicate is the filter vocabulary `hdf query` already speaks, so a gate can be prototyped with a query and pasted into a spec. Values within a field OR together; different fields AND. Rules sit beside the bounds and control lists rather than replacing them — all of them are assertions in one policy, and every one must hold.

`status` is the EFFECTIVE status, so amendments are already applied when a rule sees the document. That is what makes the example above express the whole posture in one line: a requirement suppressed by a waiver is no longer `failed`, so the rule asks only about findings nobody has adjudicated. Either something is suppressed by an override that records an owner and an expiry, or it carries a live POA&M, or it fails the gate.

`impact` in a predicate is the **effective** impact — the score after any governing impact override — for the same reason `status` is the effective status. An assessor who formally re-scores a finding has moved it, and a gate that kept reading the original number would be ignoring the adjudication it was told about. `rawImpact` reaches the requirement's own score, and the pair is what expresses a policy about the adjudication itself:

```yaml
rules:
  - name: no override may move a critical below 0.7
    where:
      rawImpact: ">=0.9"
      impact: "<0.7"
    max: 0
```

Severity follows the effective impact too, so a requirement risk-adjusted out of `critical` is counted in the band it was moved to rather than the one it left.

A rule can also select on the vulnerability fields, which is what makes the gates this feature was built for expressible:

```yaml
rules:
  - name: nothing CISA knows is exploited may fail
    where:
      status: [failed]
      kev: "true"
    max: 0
  - name: nothing failing above CVSS 7
    where:
      status: [failed]
      cvss: ">=7"
    max: 0
```

`cvss` compares the score a consumer should act on — `computedScore` where someone recomputed one (as `hdf enrich --recompute-cvss` does), else `baseScore` — and a requirement carrying several CVSS entries resolves to its **highest**, because a finding matching several CVEs is as dangerous as its worst. `epss` is the exploit **probability**, not the percentile rank; both are on a 0–1 scale and mean very different things. `kev` takes `true` or `false`, where `false` also covers a finding carrying no KEV data, since that is not known-exploited either. `cwe` matches numerically, so `CWE-79`, `"CWE 79"` and `cwe79` are one value.

`cwe` reads the first-class `cwe[]` field and never falls back to `tags.cwe`, so the filter means the same thing on every document. The cost of that is worth knowing: the SARIF converter currently records CWEs only in tags, so a SARIF-derived document matches no `cwe` predicate until that is fixed.

`poams: none-valid` deliberately covers "no POA&M", "an empty list" and "only lapsed ones" as one condition, because a plan that has expired is not a plan.

Note that it is intended behavior that a gate built on `disposition` or `poams` will produce a different verdict as of the expiration date of the POA&M, with no announcement. When the governing override or plan lapses, the finding it was covering becomes unadjudicated again, the document is still schema-valid, and no command says a word about why the gate went red. Run such a gate on a schedule as well as on commit, so a lapse surfaces as a newly red pipeline rather than at audit time, and read the dates directly with `hdf list <document> --detail amendments`, which prints an `Expires` column.

A rule bounds a count, not a percentage — `compliance` remains the only percentage bound — and it evaluates over the whole document. To narrow it to one baseline, say so in the predicate with `baseline`.

### Every field a rule can select on

The complete vocabulary. It is identical to `hdf query`'s filter flags — a rule's predicate passes straight through to the same engine filter, so anything you can explore with `hdf query` you can gate on, and the flag's `--help` is the same reference as this table.

The **Form** column says how a field accepts values. *List* fields take the three spellings described above (scalar, list, or `not:`); *comparison* fields take an operator and a number (`">=7"`, `">0.5"`, `"0.5"`); *exact* fields take one string.

| Field | Form | Accepts | Notes |
|---|---|---|---|
| `status` | list | `passed`, `failed`, `notApplicable`, `notReviewed`, `error` | The effective status, after any governing override. `not_applicable` and `not_reviewed` also accepted. |
| `severity` | list | `critical`, `high`, `medium`, `low`, `informational` | A label; bands differ between tools. Prefer `cvss` when the tool reports a score. |
| `impact` | comparison | `0.0`–`1.0` | Effective impact, after any governing impact override. |
| `rawImpact` | comparison | `0.0`–`1.0` | The requirement's own impact, ignoring overrides. |
| `cvss` | comparison | a score | `computedScore` when a consumer recomputed one, else `baseScore`; the highest entry wins. |
| `epss` | comparison | `0.0`–`1.0` | Exploit probability, **not** the percentile rank. |
| `kev` | exact | `true`, `false` | CISA Known Exploited Vulnerabilities membership. `false` includes findings with no KEV data. |
| `cwe` | list | a CWE id | `CWE-79`, `CWE 79` and `cwe79` are one value. Reads `cwe[]` only — see the caveat above. |
| `cci` | list | a CCI identifier | |
| `nist` | list | a NIST control | Globs allowed. |
| `id` | exact or glob | an identifier | Matches requirement ID, STIG ID, GID, or group title. Exact and case-sensitive by default; a `*` or `?` wildcard globs case-insensitively. See below for gating on a CVE. |
| `tag` | list | `key:value` | The colon is required. |
| `search` | exact | free text | Substring match over title and description. A short string matches longer ids, so confirm with `hdf query` before relying on it. |
| `baseline` | exact | a profile name | How a rule narrows to one baseline. |
| `baselineLabel` | list | `key:value` | The labels of the baseline a requirement sits in. Globs allowed on the value (`environment:prod*`). |
| `disposition` | list | `waiver`, `attestation`, `poam`, `inherited`, `falsePositive`, `riskAdjustment`, `operationalRequirement` | What governs the requirement: the most recently applied non-expired override **or** POA&M. `false_positive` also accepted. |
| `poamType` | list | `remediation`, `mitigation`, `riskAcceptance`, `vendorDependency` | Which *kind* of POA&M governs. `disposition` reports every governing plan flatly as `poam`; this names the kind. |
| `poams` | exact | `valid`, `none-valid` | Remediation-plan validity. `none-valid` covers no POA&M, an empty list, and only-lapsed ones. |

Predicates within one rule are **AND**ed — every field listed must hold. Values *within* one field are **OR**ed. So this means "failing, and critical or high, and unadjudicated":

```yaml
rules:
  - name: nothing serious left unadjudicated
    where:
      status: failed
      severity: [critical, high]
      disposition:
        not: [waiver, poam, riskAdjustment]
    max: 0
```

An empty `where` is **not** refused — it matches every requirement in the document, so `where: {}` with `max: 0` fails on any document that contains anything at all. What is refused is a value outside its field's vocabulary, which is the case covered below.

### Gating on a specific CVE

"Nothing failing for CVE-X" is the most-asked-for vulnerability gate, and the obvious spelling of it is a trap. `search` reads title, description and code, so it matches a CVE that another finding merely *mentions*:

```console
$ hdf query grype.json --search CVE-2018-12698
Found 1 matching requirement(s):
Grype/CVE-2018-20657  not_applicable  INFO  Grype found a vulnerability to CVE-2018-20657 in ten...
```

That is one false positive and **zero** true positives — `CVE-2018-12698` is not a requirement in this document at all; the string sits in another finding's prose. A gate written that way fires on an unrelated vulnerability.

Use a glob on `id` instead. Converters mint prefixed ids, so the CVE you know is not the id the document carries — a wildcard bridges that without reaching into prose:

```console
$ hdf query grype.json --id '*CVE-2018-12698'
No matching requirements found.

$ hdf query grype.json --id '*CVE-2022-27943'
Found 1 matching requirement(s):
Grype/CVE-2022-27943  failed  LOW  Grype found a vulnerability to CVE-2022-27943 in ten...
```

As a policy:

```yaml
rules:
  - name: CVE-2022-27943 must not be failing
    where:
      status: failed
      id: '*CVE-2022-27943'
    max: 0
```

```console
✗ grype.json — 1 threshold violation

  Violations:
    CVE-2022-27943 must not be failing: 1 matched, maximum 0
```

The glob is anchored, so `*CVE-2018-1269` does not match `CVE-2018-12698` — a trailing fragment is not a prefix match. `search` keeps its substring behaviour, which is the right tool for "mentions this anywhere"; it is just the wrong tool for a gate.

**Check where your converter puts the CVE before trusting the spelling above.** `*CVE-…` is anchored at the end, so it only matches when the CVE *ends* the id. Audited across the committed expected-output fixtures:

| Converter | Id shape | Spelling that works |
|---|---|---|
| `asff`, `cyclonedx`, `grype`, `prisma`, `twistlock`, `veracode` | the CVE ends the id (`Grype/CVE-2022-27943`, `46-CVE-2019-19927`) | `*CVE-2022-27943` |
| `neuvector` | the CVE *starts* the id (`CVE-2021-36159/apk-tools/2.10.5-r1`) | `*CVE-2021-36159*` |
| `sarif` | **both shapes occur** (`CVE-2026-2297-python-3.12` and plain) | `*CVE-2026-2297*` |

The trap is that the wrong spelling fails *silently*. On neuvector output, `--id '*CVE-2021-36159'` returns nothing at all, so `max: 0` passes and the gate is forever-green — the same false confidence `search` gives, arrived at from the other direction. Always confirm with `hdf query` before committing a policy:

```bash
hdf query results.json --id '*CVE-2021-36159*'
```

If you wrap the CVE in wildcards on both sides, write the **complete** CVE id. A trailing wildcard turns a truncated one into a prefix match, so `*CVE-2018-1269*` would match `CVE-2018-12698` — the very over-match the anchored form avoids.

Converters that record a CVE outside the id — in `tags` or `refs` — are not reachable this way at all; `tags.cve` reaches it where a converter populates that tag, and `grype` does not. The audit covers the paths those fixtures exercise, not every code path, so treat it as a floor rather than a closed list.

### Three ways to write a value

Every multi-value field in a predicate accepts the same three spellings, so a policy file reads consistently rather than one field at a time:

```yaml
rules:
  - name: mixed forms
    where:
      status: failed                  # a scalar is the one-element list
      severity: [critical, high]      # a list, as before
      disposition: {not: [waiver]}    # everything except these
    max: 0
```

The scalar is sugar and nothing more — `status: failed` and `status: [failed]` are the same predicate. Existing files are unaffected.

**`not` is a pure negation, and that matters most where a field is ABSENT.** `disposition: {not: [waiver]}` selects everything not governed by a waiver, *including* requirements nothing governs at all. That is deliberate. The gate this vocabulary exists for is "nothing fails unless somebody waived it", and the requirement it most needs to catch is the failure nobody has adjudicated:

```console
$ hdf query plans.json --disposition poam
Found 7 matching requirement(s):

$ hdf query plans.json
Found 18 matching requirement(s):
```

A rule bounding `{disposition: {not: [poam]}}` on that document matches **11** — the other side of the same 18. Had absence been excluded, those two would not sum, and a failure with no disposition would fall through every gate written this way.

The cost is worth stating: a narrow-looking predicate can select broadly. `poamType: {not: [remediation]}` matches every requirement with no governing plan at all, because having no plan is indeed not being governed by a remediation. When you mean "governed by a plan, but not that kind", say both:

```yaml
    where:
      disposition: [poam]
      poamType: {not: [remediation]}
```

**`not` is a policy-file form, not a flag form.** `hdf query`'s repeatable flags stay positive-only — there is no `--status '{not: [passed]}'`, and passing one is refused as an unrecognized value:

```console
$ hdf query labelled.json --status '{not: [passed]}'
Error: unknown --status value "{not: [passed]}" (expected one of: passed, failed, notApplicable, notReviewed, error)
```

That is deliberate rather than an oversight: a shell flag carrying YAML would need quoting rules of its own, and the query surface exists for exploration where re-running with a different value is cheap. Negation earns its place in a committed policy, where the alternative is enumerating a complement by hand and maintaining it. Express a negated query as a rule and run it through `hdf validate threshold`.

A value inside `not` is checked against the same closed vocabulary as one outside it — `{not: [waver]}` is refused, because unrefused it would exclude nothing and the predicate would quietly match everything. `{not: []}` is refused for the same reason it asserts nothing at all.

### Naming which kind of plan governs

`disposition` reports the type of whatever governs a requirement — the most recently applied non-expired override or POA&M. Because the field is typed as the schema's `Override_Type`, every governing plan reports the flat `poam`: a plan's own kind (`remediation`, `mitigation`, `riskAcceptance`, `vendorDependency`) is not a member of that enum. `poamType` recovers it:

```yaml
rules:
  - name: no bare risk acceptance
    where:
      poamType: [riskAcceptance]
    max: 0

  - name: a vendor dependency is tolerated, up to a point
    where:
      poamType: [vendorDependency]
    max: 5
```

It is a separate key rather than a spelling inside `disposition` — the four kinds are not override types, and joining them with `:` would borrow the `key:value` shape `tag` and `baselineLabel` use for something that is a closed enum rather than a free-form pair.

`poamType` reads the **governing** plan, not any plan a requirement carries. That distinction is the whole point:

```console
$ hdf query plans.json --poam-type remediation --id POAM-LAPSED-REMEDIATION-LIVE-MITIGATION
No matching requirements found.
```

That requirement carries a `remediation` — but it lapsed, and a newer `mitigation` is in force, so the mitigation governs. Matching it on `remediation` would let a dead plan answer for a live one. It matches `--poam-type mitigation`, and `--disposition poam` too, since the governing entry is still a plan.

`disposition: [poam]` remains the way to ask "is a plan governing this at all", whatever kind — a fifth kind added to the schema would still match it with no change here. An unrecognized kind is refused, as every closed vocabulary is.

### Selecting by the baseline's labels

A baseline carries `labels` — a free-form map whose well-known keys include `system`, `component` and `environment` — so a results document already records which environment or component a baseline covers. `baselineLabel` selects on them, as `key:value`, with the value globbable.

The checkov scan used above carries no labels, so this section runs against a different document: `labelled.json`, a two-baseline results file whose first baseline is labelled `environment: production` and whose second carries no labels at all.

```yaml
rules:
  - name: nothing fails in production
    where:
      status: [failed]
      baselineLabel: [environment:production]
    max: 0
```

```console
$ hdf validate threshold labelled.json -T production.yaml
Agent-attributed overrides: 0
✗ labelled.json — 1 threshold violation

  Violations:
    nothing fails in production: 1 matched, maximum 0
      SV-230221  Configure password complexity  [failed/critical]
```

The same key works on `hdf query`:

```console
$ hdf query labelled.json --baseline-label environment:production
Found 3 matching requirement(s):

ID         Status          Severity  Title
---------  --------------  --------  -----------------------------
SV-230221  failed          CRIT      Configure password complexity
SV-230222  passed          HIGH      Enable auditing
SV-230223  not_applicable  MED       Configure remote logging
```

Three things to know about it:

- **A label belongs to the baseline, not the requirement**, so the predicate is applied once per baseline and selects every requirement inside a matching one. There is no requirement-level label, which is why the key is named for the baseline.
- **A baseline carrying no labels matches nothing.** An absent label is not a wildcard — including against `*`, which asks about a label the baseline does not have. In the run above, the document's second baseline is unlabelled and its two requirements are excluded; without the predicate the same query returns 5.
- **A value carrying no colon is refused.** It names no key, so it could never match any document — and under a `max` bound, "matched nothing" and "was never applied" produce the identical clean run:

  ```console
  $ hdf query labelled.json --baseline-label production
  Error: unknown --baseline-label value "production" (expected a key:value expression, e.g. environment:production)
  ```

The same colon rule applies to `tag`, whose form this mirrors — `tag: [nist:AC-2]`, glob allowed on the value:

```console
$ hdf query labelled.json --tag production
Error: unknown --tag value "production" (expected a key:value expression, e.g. nist:AC-2)
```

A colonless `tag` was worse than a colonless `baselineLabel` before both were refused: a label predicate merely selected nothing, while a tag predicate was dropped from the filter entirely, so a rule made only of colonless tags bounded the **whole document** — a false green under any `min` and a failure against uninvolved requirements under any `max`. The two are now refused identically.

Label keys are open by schema, so a key nothing in the document carries simply selects nothing. That is correct rather than an error, and differs from the closed vocabularies — `status`, `severity`, `disposition` — where an unrecognized value is refused because it could only ever match nothing. The colon is not part of that distinction: a `key:value` expression missing its colon is malformed rather than unrecognized, and is refused on the separate grounds below.

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

A requirement id names the requirement, not one finding, so the same id legitimately appears more than once — one CVE reported against several packages emits one requirement per package, in one baseline or across several. A named control is checked against **every** entry carrying that id: the assertion holds only if all of them have the expected status and severity, and each entry that does not is reported with its position (`entry 2 of 3`). Counting bounds are unchanged — they count requirement entries, duplicates included.

This matters most on an overlay chain, where a layer restates the requirements it inherits. In the three-layer scan above, 534 ids appear more than once and 406 of those carry differing statuses between layers, so resolving an id to a single arbitrary entry would let one passing layer green a gate its siblings fail.

## A failure names what caused it

A breached bound lists the requirements underneath it, so a red check answers "which finding broke the build" without downloading an artifact:

```console
$ hdf validate threshold results.json -I "{failed.total.max: 0}"
Agent-attributed overrides: 0
✗ results.json — 1 threshold violation

  Violations:
    failed.total: 1 exceeds maximum 0
      CKV_TF_1  Ensure Terraform module sources use a commit hash  [failed/medium]
```

Rules and count bounds read alike, so a reader does not have to know which kind of bound produced a line. The status shown is the requirement's own — the vocabulary `hdf query --status` accepts — not the threshold bucket name, so a value read off a finding line can be pasted straight into a query. Two bounds deliberately list nothing:

- **`compliance`** — a percentage is a property of the whole document, so there is no offending requirement to name.
- **A `controls:` list** — the message already names the requirement it asserted, and repeating it underneath would say the same thing twice.

Every match is listed, not a sample: a gate over thousands of findings is what `--no-findings` is for, rather than a reason to truncate and leave the reader guessing.

```console
$ hdf validate threshold results.json -I "{failed.total.max: 0}" --no-findings
Agent-attributed overrides: 0
✗ results.json — 1 threshold violation

  Violations:
    failed.total: 1 exceeds maximum 0
```

The verdict and exit code are identical either way — the flag only changes what is printed.

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

## Running a SAF CLI threshold file

A pipeline moving from `saf validate threshold` can point `hdf validate threshold -T` at its existing file. The formats are the same shape — `compliance`, then `passed` / `failed` / `skipped` / `error` / `no_impact`, each with severity sub-keys and `min` / `max` — and both count bound shapes SAF accepts are honoured:

```yaml
failed:
  total:
    max: 0        # object form
passed:
  total: 19       # scalar form — means EXACTLY 19, as it does in SAF
```

A bare number is an exact bound, not a minimum. That is SAF's own rule — though SAF applies it only to the `<status>.total` keys, where this tool applies it to any bound — and a bare value that is not a whole count (`total: 1.5`) is refused rather than truncated.

### `none` is not a severity category

The five severity categories are `critical`, `high`, `medium`, `low` and `informational`. `none` is an accepted alias that resolves onto `informational`, so a bound written with it is honoured — but there is no `none` bucket in the output, and a run using the key says so:

```console
warning: 'none' is not a severity category; no_impact.none is read as no_impact.informational
```

That is about the spec, not the document, so it does not depend on what the file being checked contains. A bulk run marks the per-file line — `<file>: ok (1 non-category severity key)` — since it prints one short line per file.

### The severity bands differ at the bottom

SAF's severity bands and this tool's agree everywhere except the lowest one:

| impact | SAF CLI | hdf |
|---|---|---|
| `0` | `none` | `informational` |
| `0 < impact < 0.1` | `none` | **`low`** |
| `0.1` – `0.399` | `low` | `low` |
| `0.4` – `0.699` | `medium` | `medium` |
| `0.7` – `0.899` | `high` | `high` |
| `0.9` and above | `critical` | `critical` |

Two consequences worth knowing when a threshold moves across:

- A requirement at `0 < impact < 0.1` is `none` to SAF and `low` here, so an `informational` bound counts one fewer and a `low` bound one more.
- SAF's severity vocabulary is `none|low|medium|high|critical`, with no `informational`, so SAF ignores an explicit `severity: informational` tag and derives from impact; this tool honours it. At impact 0.5 that requirement is `medium` to SAF and `informational` here.

Neither is reported at runtime — the bands are a property of the two tools, not of any one file.

### Two differences that are not reconciled

Both are visible on SAF's own sample threshold files, and both would change results for every non-SAF user if matched, so they are documented rather than changed:

- **`no_impact.total.min` / `.max`** is enforced here and silently ignored by SAF, whose `min`/`max` total bounds cover `passed`, `failed`, `skipped` and `error` only. The *scalar* form (`no_impact:` / `total: 44`) SAF does enforce, and three of its seven sample files use exactly that — so it is the object form alone that asserts nothing there and something here. A fourth, `triple_overlay_profile_example.json.counts.totalMinMax.yml`, is the live example: it writes `no_impact:` / `total:` / `min: 44`, which SAF ignores and this tool enforces.
- **Compliance rounding.** SAF rounds the percentage to a whole number; this tool keeps two decimals. A document at 95.6% passes `compliance.min: 96` under SAF and fails here.

One more, in this tool's favour: SAF defines `none` only under `no_impact`, while it is accepted here under every status — so a key SAF would ignore is honoured.

## Where to go next

- [Status determination](../architecture/status-determination.md) — how a requirement's status and severity are decided before a threshold ever counts them, including the effect of amendments
- [Amendments end to end](./amendments-workflow.md) — waiving or risk-adjusting a finding so it stops tripping a gate for a recorded reason, rather than loosening the gate for everyone
