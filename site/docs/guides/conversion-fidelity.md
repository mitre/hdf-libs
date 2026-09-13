# Conversion Count Fidelity

A converter bug has a correlated failure mode: it breaks the product and hides that a gate built on the product is no longer judging anything. A conversion that silently drops findings produces a smaller, valid document that looks exactly like a clean scan. `hdf convert` guards against the count half of that with a check that runs on every conversion whose converter declares its input-to-requirement relation.

## What is checked

A converter may declare, from the input alone, how many primary items its output must carry: requirements for a results or baseline document, assessments for a plan, overrides for an amendments document. The declaration is computed by the converter's own grouping code, so it states the same relation the conversion implements, without converting.

After converting, `hdf convert` counts the document's primary items and compares. The two possible outcomes:

| Outcome | Behaviour |
|---|---|
| Counts match | The document is written. A line on stderr records the relation, for example `scan.sarif: 5 requirements, matching the input's distinct SARIF rules`; in bulk mode it rides on the per-file line as `scan.sarif: ok (5 requirements, matching the input's distinct SARIF rules)`. |
| Counts differ | Nothing is written for that file and the command exits non-zero: `scan.sarif: conversion lost findings: expected 5 requirements from the input's distinct SARIF rules, produced 3; no output written`. In bulk mode the other files still convert. |

There is no flag to enable or disable the check. A converter that declares a relation is always held to it; a converter that declares none is not checked. A converter may also state that it has no relation for a particular input, as the OSCAL auto-detect converter does for a system security plan, whose output is an inventory document with nothing to count; that file is converted unchecked and debug output says so. The check runs on the document the converter produced, before any output-version downgrade reshapes it.

## What the relation looks like

Every import converter in the catalogue declares a relation except `scoutsuite`, which is held back until a known grouping defect is fixed. The unit is the converter's, not a universal one. Three examples from the converters this repository's own CI pipeline gates on:

| Converter | Input unit | Relation |
|---|---|---|
| `sarif` | results in each run | one requirement per distinct rule id per run (message text stands in for a missing rule id); one no-findings requirement for a run with no results |
| `semgrep` | results | one requirement per distinct check id, plus one for scan errors when semgrep reported any, plus one scan-coverage requirement always; one no-findings requirement when nothing matched |
| `junit` | testcases | one requirement per testcase across every suite; one no-findings requirement when there are none |

A converter that groups many findings into one requirement, as `sarif` does with 72 eslint results under 5 rules, declares the grouped count. A count of raw findings would be wrong for it and right for a one-to-one converter such as `junit`; the declaration belongs to the converter for exactly that reason.

## The MCP tool enforces the same check

`hdf_convert` on the HDF MCP server runs the identical check through the same shared implementation, for a single file and for every member of a batch call. A conversion whose count disagrees with the converter's declaration is refused with a `SCHEMA_INVALID` error carrying the same message the CLI prints, and no document, handle or output file is produced for it; in a batch the other files still convert and the refused file's entry carries the error. A matching count is not reported on the MCP surface, since the response already states the requirement count.

## Where it runs in a pipeline

The check happens inside `hdf convert`, before anything else touches the document. In a pipeline that applies committed amendments after conversion, that ordering matters: a waived finding is still present in the document with its raw status, so it is never mistaken for a lost one. See the amendment step in this repository's `.github/workflows/ci.yml` for the shape.

## What it does not check

This is count fidelity only. A conversion that produces the right number of requirements with the wrong severities, the wrong statuses, or missing evidence passes this check. Content fidelity is a separate property, and a green count check is not proof of it. Converter goldens under `fixtures/expected/` and the TypeScript/Go parity snapshots are where content is held to account.
