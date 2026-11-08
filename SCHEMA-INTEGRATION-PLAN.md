# Schema integration plan

Status: composition, combined-consumer verification and aggregate sub-epic review independently passed. Beads sub-epic `hdf-libs-fdw4v.9` owns execution: `.9.1` composes the inputs and `.9.2` verifies consumers and reports merge readiness. Each card requires independent Crosscheck acceptance. This prerequisite blocks CLI delivery acceptance and final validator integration; it does not depend on either card closing first.

## Original experiment inputs and authority

- Original validator/source-preservation HEAD: `a9a5901d4cb3473dcdfc2a50efcdcecc098b7955`, plus the captured staged, unstaged and untracked source files. Content fingerprints and the complete path inventory are retained with the integration evidence.
- [Schema PR #518](https://github.com/mitre/hdf-libs/pull/518): `c6476e94d46bf42a884e366f83f9f7459ef8868a`. Retain the original commit identities and authorship when describing incorporated work.
- Upstream main is pinned independently when constructing the checkout. A later upstream change requires a new input fingerprint and affected verification.
- [ADR-0018](dev-docs/adr-0018-validator-dialect.md), [ADR-0019](dev-docs/adr-0019-siem-source-preservation.md) and [ADR-0020](dev-docs/adr-0020-siem-evidence-package-delivery.md) remain authoritative. The integration introduces no additional schema or input policy.

At the original experiment checkpoint, #518 still had merge conflicts. That historical state is superseded by the draft-publication update below; neither earlier nor current #518 CI establishes that the combined checkout works.

## Composition

Preserve both original worktrees, including the older integration checkout and the current index. Create a fresh detached integration worktree, combine the pinned upstream commits with current main without committing, and apply the captured local changes with three-way conflict information. Copy only inventoried untracked source files; exclude local credentials, runtime outputs and agent state.

For every conflict, read the base and both changes, record the resulting semantic decision, and preserve each valid implementation and test. Regenerate schemas, embedded validators, types and OpenAPI artifacts with the repository build commands. Never resolve generated schema conflicts by inventing a third hand-edited schema. Stop for genuinely incompatible product semantics or a repair beyond the recorded scope.

Before applying the schema changes, retain the strict comparison-validation failure from the captured source. Then run the comparison tests against the combined checkout. Imported work is attributed as imported work; only new behavioral repairs claim a local staged RED/GREEN cycle.

## Verification

Run schema generation and tests, affected TypeScript typechecks, Go comparison/CLI/MCP tests and vet before the composition card's independent review. The following card runs the full TypeScript build, typecheck, tests and lint; Go tests, vet and lint; and built-consumer checks on the final combined tree. Keep each command's actual exit status and preserve genuine failures.

Live checks must emit a comparison that strict validation accepts, reject malformed/unknown-field input, and export/recover all three SIEM formats with exact original source bytes. Missing or modified package artifacts must fail. Verify TypeScript consumption from packed artifacts. These checks do not substitute for the separate Elasticsearch/Splunk ingestion or hosted CI cards.

Evidence includes input revisions and fingerprints, exact conflict resolutions, generated-output changes, test/live results and complete independent review responses. No acceptance closes with an unresolved required check. Isolated success applies only to the fingerprinted combined tree, not to the untouched development branch or a future GitHub run.

## Delivery and merge order

Prepare a reviewable integration patch and recommend one of two orders: merge #518 first and rebase the validator PR, or include the agreed upstream changes in the validator PR and have #518 reconcile its remaining work afterward. The owner decides merge order and authorizes each commit and publication. This experiment does not modify or publish the upstream author's branch.

## Recorded experiment outcome (2026-11-08)

The pinned combination clears all 11 comparison-schema failures from the source checkout. The full workspace TypeScript suite passes 10,717 tests (six existing skips), and every Go package test suite passes. Workspace typechecking and lint pass; the three root Go lint targets and the changed validator module report zero issues. Vet passes all 13 Go modules. The generated bundles and embedded validators agree for all eight document types.

Twelve local npm tarballs install and import outside workspace resolution. A strict TypeScript consumer validates comparison output, rejects unknown fields, and exercises all three bundle APIs with exact source recovery and rejection of missing or altered source artifacts. The rebuilt Go CLI passes 17 corresponding live checks, including preserved trailing-data and required-property diagnostics. Validator statement coverage is 94.5%; the changed decoder and error adapter each reach 100%.

Integration exposed two diagnostic compatibility gaps beyond the comparison schema: malformed trailing bytes and missing required properties. Both are repaired at the shared Go validator boundary with recorded failing-then-passing tests; existing upstream parser/amendment tests pass unchanged. Three existing CLI assertions whose expected diagnostic text had been changed by the local validator migration were reconciled with that boundary. The generator also strips padding from generated lines, avoiding trailing whitespace without hand-editing generated output.

The CLI trailing-data wording changes from `unexpected data after end of object` at the pinned main revision to `unexpected trailing data after end of JSON value`. Rejection and exit status remain unchanged; callers must not assume the old diagnostic text is byte-for-byte preserved. The required-property wording is restored to its original form.

The documentation build exits successfully but emits the existing oversized local-search warning tracked by `hdf-libs-vz9z1`. Its unchanged-baseline reproduction and outside-scope search configuration are retained; independent review accepted its separate tracking for this full-build card because no HDF consumer depends on the search asset and the build succeeds. It has not been silently suppressed or declared repaired. Crosscheck's separate root-Go-filename parser defect is tracked by `hdf-libs-l8110`; the owner authorized a narrow manual-gate exception after the composition's actual independent PASS.

Preferred merge order: finish and merge #518 first, then rebase the validator/source-preservation work onto the merged schema. This keeps schema authorship and review ownership clear and reduces duplication. The isolated patch and conflict ledger demonstrate compatibility for these exact inputs; they do not promise a conflict-free future rebase. If the owner instead chooses to include #518 first in the validator PR, preserve its original commits/authorship and coordinate reconciliation of #518 afterward. No upstream branch was modified.

At the original experiment checkpoint, a `gh` check confirmed #518 remained open at the tested head with merge conflicts. Its build, tests, security and package checks pass, while Entire Gates fails. Main remains at the tested revision. Neither source branch has adopted this isolated result, and no hosted combined-tree CI or actual SIEM ingestion is claimed. Those remain separate acceptance steps.

The portable integration patch was also applied to a fresh extraction of the pinned main tree. All 236 changed/new paths reproduced byte-for-byte. This exposed one extra EOF blank line in an untracked source file; removing it leaves the built converter runtime and type-declaration artifacts byte-identical. The patch passes Git's strict whitespace check, including its untracked-file additions.

## Draft publication update (2026-11-08)

The owner authorized opening a draft for maintainer review while live SIEM acceptance remains open. The publication branch stacks on #518 at `cb2f738ae415302dde759951d076fb7ce6d11565`, preserving its original history. That head includes the reviewed main/lockfile reconciliation and passed hosted build/test/security checks. It supersedes the earlier conflict status above.

The publication checkout imports the fingerprinted experiment's validator/SIEM delta. Four three-way conflicts preserve the latest upstream build dependency versions, add the existing Testcontainers dependency, retain the single upstream generated-whitespace fix, and keep the Go validator diagnostic release notes. The frozen lockfile installation succeeds. Exact-snapshot checks and an independent publication review are required before opening the draft; their results belong in its description and the preparation card.

After #518 merges, retarget this draft to `main` and verify the resulting diff and any changed inputs. Opening the draft does not close the final consumer, live Elasticsearch/Splunk or hosted SIEM CI cards and does not authorize merging or releasing packages.

## Main rebase after #518 merged (2026-11-08)

Will squash-merged #518 as `734a44ca8821e24325f2aa7f30a7dea136f3bd1e`, after incorporating the lockfile repair from #526. The owner authorized rebasing draft #527 onto that main revision. Only the draft's own commit, originally `535a9ab294acf4b2da1eb1736aa3e972fd94afcf`, was replayed; the former #518 branch history was not replayed.

The rebase applied without conflicts. Relative to the published draft, the resulting product tree differs only by the upstream lockfile repair; validator, converter, CLI, fixtures and harness sources are unchanged. The updated draft targets `main` and retains one feature commit. Rebased-snapshot verification and independent review are recorded in the PR description and preparation card. The live SIEM and final feature acceptance limitations above still apply.
