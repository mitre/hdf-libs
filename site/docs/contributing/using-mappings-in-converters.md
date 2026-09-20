# Using Mappings in Converters

Many security tools report findings against a standardized identifier — a CCI, a CWE, an OWASP category — rather than against NIST 800-53 controls directly. `@mitre/hdf-mappings` holds those correspondences, and a converter uses it to enrich its output with `tags.nist` so a finding is traceable to the control it bears on.

This page is the convention for doing that. For what each mapper covers and its exact signature, see the [hdf-mappings package reference](/docs/packages/hdf-mappings).

## Prefer a shared helper when one exists

Mapping is not a one-liner. Several source identifiers commonly map to the same control, so the results need deduplicating; and a stable order matters because converter output is compared against goldens. The shared converter layer already encapsulates that for CWE:

```typescript
import { mapCWEToNIST, DEFAULT_STATIC_ANALYSIS_NIST_TAGS } from '../../../shared/typescript/converterutil.js';

tags.nist = mapCWEToNIST(cweIDs, [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS]);
```

```go
tags["nist"] = shared.MapCWEToNIST(cweIDs, shared.DefaultStaticAnalysisNIST)
```

Pass the shared fallback constant rather than a literal: `DEFAULT_STATIC_ANALYSIS_NIST_TAGS` / `DefaultStaticAnalysisNIST` is `SA-11, RA-5`, and the two languages are kept in step there.

It strips the `CWE-` prefix, looks each identifier up, deduplicates, sorts, and falls back to the controls you supply when nothing resolves. Hand-rolling that sequence gets you a second implementation to keep in step with the first, which is the most common defect in this repository.

## The pattern when no shared helper exists

Not every mapping has one yet. CCI does not, so a converter assembles it directly — extract the identifiers, map each, flatten, deduplicate, sort:

```typescript
import { getCCINistMappings } from '@mitre/hdf-mappings';

const nist = [...new Set(cciIds.flatMap((c) => getCCINistMappings(c) ?? []))].sort();
```

The `?? []` is load-bearing: a lookup that finds nothing returns `undefined`, and without the fallback a single unmapped identifier puts `undefined` into the array and produces schema-invalid output.

If you find yourself writing this for a mapping that two converters now share, promote it to a shared helper rather than copying it a third time.

## Emit the tags together

`nist` and `cci` travel together, and `buildNistCciTags` writes both plus any extras in one place, so the tag shape stays identical across converters:

```typescript
const tags = buildNistCciTags(nist, cciIds, { severity: 'medium' });
```

```go
tags := shared.BuildNISTCCITags(nist, cciIDs)
```

## When to map, and when not to

Map when the source carries a standardized identifier, the target is a control framework the mappings cover, and the correspondence genuinely aids traceability.

Do not map when the tool already reports the target controls itself — pass those through rather than re-deriving them — or when no standardized identifier is present. An invented or approximate mapping is worse than none: it reads as an assessed correspondence when it is a guess.

## Missing mappings are normal

A lookup returns `undefined` (TypeScript) or an empty result (Go) when the identifier is absent from the mapping data, malformed, or empty. That is an ordinary outcome, not an error — mapping data does not cover every identifier a scanner can emit.

Handle it by supplying a fallback, which is what the `fallback` argument to `mapCWEToNIST` is for. Where a converter uses a broad fallback such as `SA-11, RA-5`, tag the requirement so a consumer can tell a derived control from a defaulted one; `kics-to-hdf` does this with a `nistMapping` tag reading `cwe-derived` or `static-fallback`.

## Testing

Assert the mapping produced a specific control, not merely that the array is non-empty — a test that only checks for presence passes when the mapping silently returns the fallback:

```typescript
it('maps CCI identifiers to NIST controls', () => {
  const req = convertToHdf(input).baselines[0].requirements[0];
  expect(req.tags.nist).toContain('CM-6 b');
});
```

Because mapping data is shared between the TypeScript and Go implementations, the two must agree for the same input. The differential tests described in the [developer guide](./developer-guide.md) are what hold that line.
