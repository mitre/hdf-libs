import { describe, it, expect } from 'vitest';
import { generateDeltaJson, generateDeltaMarkdown } from '../src/delta-report.js';
import type { DeltaResult, LinkRecord } from '../src/delta-types.js';

function makeDeltaResult(overrides?: Partial<DeltaResult>): DeltaResult {
  return {
    profile: { inspecYml: '', controls: new Map() },
    linkRecords: [],
    statistics: {
      oldControlsLength: 0, newControlsLength: 0, totalMappedControls: 0,
      match: 0, posMisMatch: 0, dupMatch: 0, noMatch: 0,
    },
    ...overrides,
  };
}

describe('generateDeltaJson', () => {
  it('should include links array', () => {
    const links: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false,
      },
    ];
    const result = makeDeltaResult({ linkRecords: links });

    const json = generateDeltaJson(result);

    expect(json.links).toHaveLength(1);
    expect(json.links[0]!.oldId).toBe('V-001');
  });

  it('should handle empty links', () => {
    const json = generateDeltaJson(makeDeltaResult());
    expect(json.links).toHaveLength(0);
  });
});

describe('generateDeltaMarkdown', () => {
  it('should include SAF CLI-compatible statistics', () => {
    const result = makeDeltaResult({
      statistics: {
        oldControlsLength: 5,
        newControlsLength: 3,
        totalMappedControls: 2,
        match: 1,
        posMisMatch: 0,
        dupMatch: 1,
        noMatch: 1,
      },
    });

    const md = generateDeltaMarkdown(result);

    expect(md).toContain('Control Counts');
    expect(md).toContain('Total Controls Available for Delta:  5');
    expect(md).toContain('Total Controls Found on XCCDF:  3');
    expect(md).toContain('Match Statistics');
    expect(md).toContain('Match Controls:  1');
    expect(md).toContain('Possible Mismatch Controls:  0');
    expect(md).toContain('Related Match Controls:  1');
    expect(md).toContain('No Match Controls:  1');
    expect(md).toContain('Statistics Validation');
  });

  it('should include mapping results', () => {
    const links: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: 'srgDeterministic',
        confidence: 1.0, relationship: 'primary', potentialMismatch: false,
      },
      {
        oldId: null, newId: 'SV-002', matchMethod: 'none',
        confidence: 0, relationship: 'no-match', potentialMismatch: false,
      },
    ];
    const result = makeDeltaResult({
      linkRecords: links,
      statistics: {
        oldControlsLength: 1, newControlsLength: 2, totalMappedControls: 1,
        match: 1, posMisMatch: 0, dupMatch: 0, noMatch: 1,
      },
    });

    const md = generateDeltaMarkdown(result);

    expect(md).toContain('Mapping Results');
    expect(md).toContain('V-001 -> SV-001');
    expect(md).toContain('Match Details');
    expect(md).toContain('SRG deterministic');
  });

  it('should include per-control match method details', () => {
    const links: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: 'srgCciTiebreak',
        confidence: 0.85, relationship: 'primary', potentialMismatch: false,
        srg: 'SRG-OS-000001',
      },
    ];
    const result = makeDeltaResult({
      linkRecords: links,
      statistics: {
        oldControlsLength: 1, newControlsLength: 1, totalMappedControls: 1,
        match: 1, posMisMatch: 0, dupMatch: 0, noMatch: 0,
      },
    });

    const md = generateDeltaMarkdown(result);

    expect(md).toContain('SRG block + CCI tiebreak (Jaccard=85%) [primary]');
  });

  it('should handle empty result', () => {
    const md = generateDeltaMarkdown(makeDeltaResult());

    expect(md).toContain('Control Counts');
    expect(md).toContain('Match Statistics');
    expect(md).not.toContain('Mapping Results');
    expect(md).not.toContain('Match Details');
  });

  it.each([
    ['vendorFuzzyTitle', 'Vendor fuzzy title (confidence=90%)'],
    ['exactId', 'Exact ID'],
    ['cciMatch', 'CCI match'],
    ['fuzzyTitle', 'Fuzzy title (confidence=90%)'],
    ['unknownStrategy', 'unknownStrategy'],
  ])('formats match method %s in delta.md', (method, expected) => {
    const links: LinkRecord[] = [
      {
        oldId: 'V-001', newId: 'SV-001', matchMethod: method,
        confidence: 0.9, relationship: 'primary', potentialMismatch: false,
      },
    ];
    const result = makeDeltaResult({
      linkRecords: links,
      statistics: {
        oldControlsLength: 1, newControlsLength: 1, totalMappedControls: 1,
        match: 1, posMisMatch: 0, dupMatch: 0, noMatch: 0,
      },
    });

    expect(generateDeltaMarkdown(result)).toContain(expected);
  });
});
