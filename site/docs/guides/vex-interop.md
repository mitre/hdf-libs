# VEX Interoperability

Vulnerability Exploitability eXchange (VEX) is a class of supplier-attached
statements about whether a specific CVE actually affects a specific product.
Three formats dominate the ecosystem: **OpenVEX** (the openvex/spec
JSON-LD format), **CSAF VEX** (the OASIS Common Security Advisory Framework
2.0 `csaf_vex` profile), and **CycloneDX VEX** (analysis blocks on
CycloneDX BOM vulnerabilities). HDF v3.3.x ships round-trippable
converters for all three.

This guide explains how the three formats map to HDF Amendments, the
real-system vs abstract-vuln invariant that shapes the design, and the
partial-fidelity contract each converter honors.

## Why amendments, not results?

VEX is consumer-attached context. The act of accepting (or asserting) a
VEX statement IS the amendment — there is no scan-finding behavior
underneath. That makes VEX a natural fit for the HDF Amendments document
type, not HDF Results.

`Standalone_Override` is the primitive on the receiving end. Each VEX
statement becomes exactly one override:

| VEX shape | Override type | Status after import |
|---|---|---|
| `not_affected` (any format) | `falsePositive` + `justification` | `passed` |
| `affected` / `known_affected` / `exploitable` | (no override) — informational only | — |
| `fixed` / `resolved` / `known_fixed` | `poam` with open milestone | `failed` (pinned) |
| `under_investigation` / `in_triage` | (no override) — informational only | — |

A `falsePositive` override with an HDF `Justification` value carries
exactly the same payload as a VEX `not_affected` statement with a
`justification` value — and that round-trips losslessly in both
directions.

## The real-system vs abstract-vuln invariant

VEX `fixed` is a **supplier claim about a product version**. HDF
describes an **assessed system**. Those are not the same thing.

When a vendor publishes `vex: {status: fixed}` for openssl 1.1.1k → 1.1.1l,
nothing about that statement tells us whether the host *we just scanned*
has the patch. The patch could be available without being installed; the
system could be running a different distro's repackage; the scanner could
be looking at the wrong path. Trusting the supplier claim as evidence of
system state is exactly how false-clean results sneak into authorization
packages.

So every VEX importer in HDF enforces:

> **Importing a `fixed` VEX statement produces an open POA&M pinned to
> `failed`, not a status flip.** The remediation is recorded; the
> assessed-system status stays unsatisfied until a re-scan confirms
> the patch.

And every exporter enforces the symmetric rule:

> **An open POA&M never round-trips to `fixed` / `resolved`.** The
> exporter only emits the closure status when every milestone is in
> `completed` state. Otherwise the override surfaces as
> `affected` / `exploitable` / `known_affected` with the planned
> remediation attached as `action_statement`, `response`, or
> `remediations[]`.

This means the **`fixed` round-trip is intentionally asymmetric**. A
VEX `fixed` document round-trips through HDF as
`fixed → POA&M (failed) → exploitable + workaround_available`. Anything
else would lie to downstream consumers about whether a system has the
patch.

## Status mapping

The canonical VEX status across all three ecosystems:

| Canonical (HDF) | OpenVEX `status` | CSAF `product_status` bucket | CycloneDX `analysis.state` |
|---|---|---|---|
| `not_affected` | `not_affected` | `known_not_affected` | `not_affected` |
| `affected` | `affected` | `known_affected` (and several others) | `exploitable` |
| `fixed` | `fixed` | `fixed` / `first_fixed` | `resolved` |
| `under_investigation` | `under_investigation` | `under_investigation` | `in_triage` |

The shared `vex` package (`hdf-converters/shared/{go,typescript}/vex/`)
normalizes all ecosystem-specific strings to the canonical status before
the HDF mapping logic runs. Adding a new VEX-shaped format is a
~30-line additive change there, not new converter-internal switch
statements.

## Justification

`Justification` is an HDF enum on `Standalone_Override` that records the
**structured reason** a `not_affected` claim is true. As of v3.3.x it
covers the full vocabulary across all three formats:

| HDF `Justification` | OpenVEX / CSAF (long-form) | CycloneDX (short-form) |
|---|---|---|
| `component_not_present` | `component_not_present` | `code_not_present` |
| `vulnerable_code_not_present` | `vulnerable_code_not_present` | — *(HDF-only)* |
| `vulnerable_code_not_in_execute_path` | `vulnerable_code_not_in_execute_path` | `code_not_reachable` |
| `vulnerable_code_cannot_be_controlled_by_adversary` | `vulnerable_code_cannot_be_controlled_by_adversary` | — *(HDF-only)* |
| `inline_mitigations_already_exist` | `inline_mitigations_already_exist` | `protected_by_mitigating_control` |
| `requires_configuration` | — | `requires_configuration` |
| `requires_dependency` | — | `requires_dependency` |
| `requires_environment` | — | `requires_environment` |
| `protected_by_compiler` | — | `protected_by_compiler` |
| `protected_at_runtime` | — | `protected_at_runtime` |
| `protected_at_perimeter` | — | `protected_at_perimeter` |

When exporting back to CycloneDX, `justificationForCycloneDX` translates
HDF long-form names to CycloneDX short-form. When exporting to OpenVEX
or CSAF, values they don't recognize are passed through verbatim
(documented partial-fidelity boundary — extend the helper if a real
consumer asks).

The two HDF-only values without a CycloneDX equivalent are emitted with
no `analysis.justification` field on CycloneDX export rather than a
spec-violating value.

## Product identity: `affectedPackages`

VEX statements scope to specific products. CycloneDX `affects[].ref`,
OpenVEX `products[].@id`, and CSAF `product_status[*]` all carry product
references — and they have **nothing in common at the wire-format level**.
CycloneDX bom-refs are BOM-local opaque strings; CSAF product_ids are
document-local opaque strings pointing into `product_tree`; OpenVEX
`@id`s are typically purls or CPEs.

HDF normalizes all of them into `Standalone_Override.affectedPackages[]`,
an array of `Affected_Package` primitives. The schema requires *at least
one* of:

- `name + version + ecosystem` (the explicit triple)
- `purl` alone (purl encodes name/version/ecosystem)
- `cpe` alone (CPE 2.3 encodes vendor/product/version)

The relaxation to `anyOf` is intentional: a CycloneDX bom-ref that's a
purl gets stored as-is without re-deriving name+version+ecosystem; a
CSAF `product_identification_helper.cpe` is stored verbatim; only fully
opaque source identifiers (unresolvable bom-refs, plain document-local
strings) are dropped — the schema forbids fabricating identity.

Importer behavior per format:

- **OpenVEX** — `products[].@id` is normalized by
  `affectedPackagesFromIdentifiers` (purl-prefix and cpe-prefix
  recognition). `identifiers.{purl,cpe22,cpe23}` from the OpenVEX
  product object is folded in when present.
- **CSAF** — the importer walks `product_tree.branches[]` recursively,
  tracking ancestor `product_name` and `product_version` branches.
  `product_identification_helper.purl` and `.cpe` take precedence over
  name+version derivation. Documents that scope by `product_version_range`
  (range expressions, not concrete versions) drop the entry rather than
  emit a range string as a version.
- **CycloneDX** — `affects[].ref` looks up in the BOM's `components[]`
  table. If the component carries a purl, that becomes the structured
  source. Otherwise name+version is used. Opaque bom-refs with no
  component-table match are dropped.

The `componentRef` field on `Standalone_Override` stays UUID-constrained
and continues to scope amendments to **HDF Components** (system-internal
hosts, applications, repositories). It is structurally distinct from
`affectedPackages[]`, which scopes to **foreign-format product
identifiers**. Both can coexist on the same override.

## Round-trip fidelity

Round-trip means **same-format-in → HDF → same-format-out**. Cross-format
conversion (CSAF → HDF → OpenVEX) is not a contract — the formats have
overlapping but distinct vocabularies and we lose what doesn't translate.

What survives same-format round-trip:

| Field | Survives |
|---|---|
| CVE id (`requirementId`) | ✓ |
| Canonical status (`not_affected`, `affected`, `fixed`, `under_investigation`) | ✓ |
| Justification enum | ✓ |
| `affectedPackages[]` (purl/cpe/name+version) | ✓ |
| Document timestamp | ✓ |
| Publisher / appliedBy identity (email vs simple vs system) | ✓ |
| `amendmentId` ↔ document id / serialNumber / tracking.id | ✓ |
| Reason free-text → impact_statement / threats[].details / analysis.detail | ✓ (best-effort prose mapping) |
| Evidence URLs | ✓ for CSAF / CycloneDX |
| `previousChecksum`, amendment chain history | ✗ collapsed to single statement |
| Non-CVE `requirementId` (e.g. NIST AC-2) | ✗ dropped — VEX is vulnerability-keyed |
| `expiresAt` per statement | ✗ no per-statement expiry in any format; re-import gets a fresh 1-year horizon |
| CSAF `product_version_range` → concrete version | ✗ schema requires concrete identity |

The dropped items are documented partial-fidelity boundaries. The
chain-collapse is by design — the chain is an HDF-internal integrity
primitive; consumers re-importing a re-exported VEX statement are
filing a fresh consumer action, not re-linking an audit chain.

## CLI

The six converters cover both directions of all three formats:

```bash
# Import: VEX → HDF Amendments
hdf convert --from openvex   vex.openvex.json   -o amendments.json
hdf convert --from csaf-vex  advisory.csaf.json -o amendments.json
hdf convert --from cyclonedx-vex bom.cdx.json   -o amendments.json

# Export: HDF Amendments → VEX
hdf convert --from hdf-amendments --to openvex   amendments.json -o out.openvex.json --no-validate
hdf convert --from hdf-amendments --to csaf-vex  amendments.json -o out.csaf.json    --no-validate
hdf convert --from hdf-amendments --to cyclonedx-vex amendments.json -o out.cdx.json --no-validate
```

`--no-validate` is required on the export side: the CLI's default
auto-validation looks for HDF document shapes, and the export output is
intentionally non-HDF.

To validate an HDF Amendments document at any step:

```bash
hdf validate amendments.json
```

## Auto-detection

CycloneDX VEX is a CycloneDX BOM with `vulnerabilities[].analysis`
populated. Auto-detect routes those documents to `cyclonedx-vex-to-hdf`
(producing HDF Amendments). Plain SBOMs without analysis still route to
`cyclonedx-to-hdf` (producing HDF Results). The fingerprint score
prioritizes VEX when analysis statements are present.

OpenVEX and CSAF VEX have distinct top-level shapes (`@context` /
`@id` for OpenVEX; `document.category` for CSAF) and auto-detect
unambiguously.

## See also

- Per-converter provenance + partial-fidelity tables:
  [openvex-to-hdf](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/openvex-to-hdf/fixtures/README.md),
  [csaf-vex-to-hdf](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/csaf-vex-to-hdf/fixtures/README.md),
  [cyclonedx-vex-to-hdf](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/cyclonedx-vex-to-hdf/fixtures/README.md),
  [hdf-to-openvex](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/hdf-to-openvex/fixtures/README.md),
  [hdf-to-csaf-vex](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/hdf-to-csaf-vex/fixtures/README.md),
  [hdf-to-cyclonedx-vex](https://github.com/mitre/hdf-libs/blob/main/hdf-converters/converters/hdf-to-cyclonedx-vex/fixtures/README.md)
- Schema reference: [HDF Amendments — Standalone Override](https://mitre.github.io/hdf-libs/schemas/hdf-amendments.html)
- Format specs: [OpenVEX](https://github.com/openvex/spec),
  [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html),
  [CycloneDX VEX](https://cyclonedx.org/use-cases/#vulnerability-exploitability)
- Companion guide: [CVE Ecosystem](./cve-ecosystem.md) — the typed
  CVSS / EPSS / KEV / CWE / AffectedPackage slots VEX amendments often
  enrich
