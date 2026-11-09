# HDF threshold policies

HDF CLI defines the concept of a [threshold file](../../site/docs/guides/thresholds-workflow.md), which can be used to put gates on a CI/CD pipeline that operate on normalized HDF data instead of just dealing with whatever return code a scanner provides, or having to implement a bespoke gate for every scan.

We define one threshold file per tool, applied by the `gate-hdf-scans` and `gate-hdf-tests` jobs in `ci.yml`, so that we can set different policies and expectations for different tools if we like.

Our threshold files declare that failures are only permitted if they have had some decision made about them by a developer -- that is, we only allow failures that have had an [HDF amendment of some kind](../../site/docs/guides/amendments-workflow.md) applied to them. We also declare that no errors are permitted, since an error in an HDF document means that the source scanner malfunctioned and we have no idea one way or the other if the tests passed.

```yaml
rules:
    - name: no requirement errored
      where:
          status: error
      max: 0
    - name: nothing failing is unadjudicated
      where:
          status: failed
          disposition:
              not: [waiver, attestation, poam, inherited, falsePositive, riskAdjustment, operationalRequirement]
      max: 0
```

The adjudications live in [`../hdf-amendments/`](../hdf-amendments), applied by the gate before it judges. Every override requires an `expiresAt`, so no decision is permanent — when one lapses the finding returns to the gate on its own.

You may note that most scans in most CI runs will not produce any failures at all, so the disposition clause does nothing on a clean run. That is not a reason to leave out the disposition check. When scans *do* find failures, we are forced to address them with a documented amendment (or otherwise fix them, e.g. by patching) before we can get a clean run.

The test gate is the one place a tool has more than one file. `tests.yaml` carries the shared rules and `tests-ubuntu.yaml` / `tests-windows.yaml` each carry that platform's skip budget; `gate-hdf-tests` applies them per platform as `-T tests.yaml -T tests-<os>.yaml` over that platform's documents. JUnit `skipped` normalizes to `notReviewed`, and some skips are by design (symlink and POSIX-mode-bit semantics on windows, case-folding and Unicode normalization on linux), so the bound is a count measured from the highest document of a green run on that platform. One shared number would be set by windows and hand every other platform that much invisible headroom. Re-measure from the `hdf-normalized-tests` artifact of a green run, never from the run being gated, and record the run id in the file. A count cannot tell one skip from another; a `skipped.<severity>.controls:` pin can, but it is per-document — applied through a platform glob it fails every other document on that leg with `expected control ... not found` — and it fires when a pinned test starts running, so the budget stays a count.

Some threshold files for particular tools may need additional clauses or modifications, such as `govulncheck.yaml`, which scopes its rule to `severity: [critical, high]`. That tool tiers by *reachability*: a vulnerable symbol actually called arrives as high, while a vulnerable package merely imported arrives as low or medium and is meant to stay visible — unadjudicated — until a dependency bump clears it. A plain rule would demand an amendment for each of those and contradict the tiering the file already documents.

## For devs - adding a threshold for a new tool in the pipeline

1. Write `<tool>.yaml` with the bounds, plus the `rules:` block above, and any additional rules you believe necessary to properly gate that tool, into your PR.
2. Add the tool to the loop in `ci.yml`.
3. Adjudicate findings in `../hdf-amendments/<tool>.json`, if necessary, with consultation from the maintainers.
