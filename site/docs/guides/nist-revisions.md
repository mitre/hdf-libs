# NIST 800-53 Revision Handling

Every hdf-libs converter that emits NIST 800-53 control tags emits them against a single, explicitly selected catalog revision — Rev 4 or Rev 5 — with a defined outcome for every control at either revision. This page is the contract: how to select a revision, what the selection guarantees, and how the underlying mapping data behaves for consumers who read it directly.

The failure mode this design eliminates is *silent cross-revision contamination*: a results document that mixes Rev 4 and Rev 5 control IDs cannot be validated or rolled up against one baseline, and a "filter to one revision" view that quietly drops rules under-reports compliance without any visible error.

## Selecting a revision

The default revision is **Rev 5**. Rev 4 remains fully supported for organizations still authorized against it.

```bash
hdf convert --from aws-config input.json -o out.json               # Rev 5 (default)
hdf convert --from aws-config --nist-rev 4 input.json -o out.json  # Rev 4
hdf convert --from nessus --nist-rev 4 --nist-strict scan.nessus -o out.json
```

`--nist-strict` turns a revision mismatch (an input that references a rule mapped only at another revision, with no crosswalk equivalent) into a hard error instead of a warning.

Programmatically, the revision is a process-global default that every mapping lookup consults:

::: code-group

```go [Go]
import "github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"

nist.SetRevision(4)        // all mapping lookups now answer at Rev 4
defer nist.ResetRevision() // back to the default (Rev 5)
nist.SetStrict(true)       // mismatches become errors
```

```typescript [TypeScript]
import { setCurrentNistRevision, resetNistRevision, setNistStrict } from '@mitre/hdf-mappings';

setCurrentNistRevision(4);
resetNistRevision();
setNistStrict(true);
```

:::

For explicit, side-effect-free selection, the revision-aware tables (AWS Config, CWE) expose per-call variants — `NISTControlsForRevision(...)` in Go, an optional `rev` parameter in TypeScript. The single-revision tables translate through the crosswalk directly, which is likewise side-effect-free: `nist.AtRevision(controls, nativeRev, rev)` / `nist.TranslateControls(...)` in Go, `nistControlsAtRevision(controls, nativeRev, rev)` in TypeScript.

## What selection guarantees

**Every NIST-emitting converter honors the selected revision** — not just the converters backed by revision-aware data. Each mapping table in `@mitre/hdf-mappings` declares the revision it was authored against, and its lookups translate to the selected revision through NIST's own Rev 4 ↔ Rev 5 crosswalk:

| Table | Native revision | Behavior under selection |
|-------|-----------------|--------------------------|
| AWS Config | 4 + 5 (dual) | native rows per revision, crosswalk-backfilled to completeness (below) |
| CWE | 4 + 5 (dual) | control IDs byte-identical across revisions |
| Nessus | 4 | translated (e.g. AU-8(1) → SC-45(1) at Rev 5) |
| CCI (DISA) | 4 | translated, statement suffixes preserved on identity |
| Nikto, OWASP, ScoutSuite | 4 | content identical at both revisions; a test guards the invariant |
| Hipcheck | 5 | translated (SR-family controls drop at Rev 4 — no equivalent exists) |

**Translation is deterministic and never invents specificity.** The crosswalk is generated from NIST's published comparison workbooks (the SP 800-53 Rev 4→Rev 5 comparison workbook and the Appendix J privacy-control comparison), not curated by hand. Per control:

- A control present in both revisions under the same ID passes through (*identity*).
- A control NIST **moved** or **incorporated** follows NIST's named successor (`IR-10` → `IR-4(11)`).
- Rev 4 Appendix J privacy controls follow NIST's **pointers** (`TR-1` → `PT-5`, `PT-5(1)`). NIST labels these pointers, not equivalences.
- A control with **no equivalent** at the target revision is dropped, never mistranslated. Family-level incorporations ("SA-12 → SR family") stay markers and are never expanded into member controls.
- Statement-style suffixes (`AC-2(j)`, `AC-1 a`) survive identity translation and are dropped on redirects (statement lettering is not stable across revisions).
- Tokens outside both NIST catalogs (tool placeholders such as Nessus's `UM-1`) pass through unchanged.

The crosswalk and translation APIs are public — useful for pipelines that consume HDF output and need the same translation (for example, OSCAL SAR generation against a specific catalog):

::: code-group

```go [Go]
tr := nist.Translate("IR-10", 4, 5)
// Translation{Targets: ["IR-4(11)"], Relation: "moved", ...}

tags, unmapped := nist.TranslateControls(controls, 4, 5)
controls = nist.AtRevision(controls, 4, nist.Revision()) // bulk, suffix-aware
```

```typescript [TypeScript]
import { translateNistControl, translateNistControls, nistControlsAtRevision } from '@mitre/hdf-mappings';

translateNistControl('IR-10', 4, 5);
// { control: 'IR-10', targets: ['IR-4(11)'], relation: 'moved', ... }
```

:::

## The AWS Config data contract

`awsconfig-mappings.json` (shipped in both the Go embed and `src/data/`) is the AWS Config rule → NIST bridge. Its per-revision completeness contract:

**Every rule in the table has a defined outcome at both supported revisions** — one of:

1. **Native** — AWS published the mapping at that revision (`Source: "config-pack"`, `"security-hub"`, or `"derived-theme"`).
2. **Crosswalk-derived** — AWS published the mapping at only one revision; the row at the other revision carries the crosswalk-translated controls (`Source: "crosswalk"`).
3. **Explicitly unmapped** — the rule's entire control set has no equivalent at that revision; the row is present with an **empty `NIST-ID`** (`Source: "crosswalk"`). "No mapping exists at this revision" is recorded as an answer, not left as a silent gap.

Consequences for direct consumers of the JSON:

- Filtering the flat array by `Rev` yields a **complete** single-revision view — no rule silently disappears.
- Never treat an empty `NIST-ID` as a parse error; it is the explicit unmapped marker. The lookup APIs (`NISTControls*`, `awsConfigMappedRevisions`) already handle it: marker rows resolve to no controls, and `MappedRevisions` excludes them.
- The `Source` field is the provenance chain. Crosswalk rows inherit the confidence of the native row they were derived from; `derived-theme` rows are heuristic (see the coverage-tier documentation in the `hdf-mappings` README).
- Native rows are never modified by the backfill. A rule mapped by AWS at both revisions carries AWS's own mapping at each — which may differ by more than ID renaming (e.g. `access-keys-rotated`: Rev 4 `AC-2(1)`, Rev 5 `AC-3(15)`); that divergence is AWS's published judgment, preserved verbatim.

## Unmapped rules, floors, and strict mode

- An AWS Config rule with no explicit mapping at any revision receives the **CM-6** (Configuration Settings) floor at conversion time — every Config rule evaluates a configuration setting, so CM-6 is an honest baseline. The floor applies only when no explicit mapping (native or crosswalk-derived) exists at the requested revision.
- The aws-config converter warns when input references rules that are mapped only at a different revision than requested; with `--nist-strict` this becomes an error. After the crosswalk backfill this fires only for genuinely untranslatable rules.
- For the translated tables (Nessus, CCI, Hipcheck), controls with no equivalent at the requested revision drop deterministically — the same semantics as the empty-`NIST-ID` marker, applied at lookup time.

## Interpretation

NIST tags produced by these mappings are *candidate control associations for triage*, not evidence that a control is assessed or satisfied. A crosswalk edge means NIST relocated or absorbed requirement text — it does not make the target control's full scope equivalent to the source control. Do not roll "rule passed" up to "tagged controls satisfied" in SSP / eMASS / ATO exports.

## Regenerating the data

Both data sets are generated, drift-gated, and byte-identical across the Go and TypeScript copies:

```bash
cd hdf-mappings
pnpm mappings:crosswalk          # regenerate the r4<->r5 crosswalk from NIST's workbooks
pnpm mappings:crosswalk:check    # drift gate
pnpm mappings:awsconfig          # regenerate the AWS Config table (includes the crosswalk tier)
pnpm mappings:awsconfig:check    # drift gate
```

Provenance (source URLs, tier precedence, derivation rules) is documented in the generator headers and the `hdf-mappings` README.
