import { describe, it, expect } from 'vitest';
import { createPackageMatchStrategy } from '../../src/matching/package-match.js';

describe('PackageMatchStrategy', () => {
  const strategy = createPackageMatchStrategy();

  it('has name "packageMatch"', () => {
    expect(strategy.name).toBe('packageMatch');
  });

  it('matches when affectedPackages sets are identical (Jaccard = 1.0)', () => {
    const oldReqs = [
      {
        id: 'CVE-2024-1234',
        affectedPackages: [
          { name: 'openssl', version: '1.1.1' },
          { name: 'libcurl', version: '7.81.0' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'GHSA-aaaa-bbbb-cccc',
        affectedPackages: [
          { name: 'openssl', version: '1.1.1' },
          { name: 'libcurl', version: '7.81.0' },
        ],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('CVE-2024-1234');
    expect(result.matched[0]!.newReq['id']).toBe('GHSA-aaaa-bbbb-cccc');
    expect(result.matched[0]!.strategy).toBe('packageMatch');
    expect(result.matched[0]!.confidence).toBeCloseTo(1.0, 5);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('does not match below the default threshold (0.5)', () => {
    // Old: A, B, C, D — New: A, E, F, G — Jaccard = 1/7 ~= 0.14
    const oldReqs = [
      {
        id: 'CVE-2024-A',
        affectedPackages: [
          { name: 'a', version: '1' },
          { name: 'b', version: '1' },
          { name: 'c', version: '1' },
          { name: 'd', version: '1' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'CVE-2024-B',
        affectedPackages: [
          { name: 'a', version: '1' },
          { name: 'e', version: '1' },
          { name: 'f', version: '1' },
          { name: 'g', version: '1' },
        ],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('matches above the default 0.5 threshold (partial overlap)', () => {
    // Old: A, B — New: A, B, C — Jaccard = 2/3 ~= 0.67
    const oldReqs = [
      {
        id: 'CVE-2024-A',
        affectedPackages: [
          { name: 'openssl', version: '1.0.0' },
          { name: 'libcurl', version: '7.0.0' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'GHSA-foo',
        affectedPackages: [
          { name: 'openssl', version: '1.0.0' },
          { name: 'libcurl', version: '7.0.0' },
          { name: 'zlib', version: '1.2.0' },
        ],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.confidence).toBeCloseTo(2 / 3, 5);
  });

  it('treats name+version as the tuple (different version = different tuple)', () => {
    const oldReqs = [
      {
        id: 'CVE-2024-A',
        affectedPackages: [{ name: 'openssl', version: '1.0.0' }],
      },
    ];
    const newReqs = [
      {
        id: 'CVE-2024-B',
        affectedPackages: [{ name: 'openssl', version: '1.1.0' }],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Different versions: Jaccard = 0/2 = 0 — below threshold
    expect(result.matched).toHaveLength(0);
  });

  it('respects custom minJaccard threshold', () => {
    // Jaccard = 0.5 exactly — matches at threshold 0.5, not at 0.51
    const oldReqs = [
      {
        id: 'CVE-2024-A',
        affectedPackages: [
          { name: 'a', version: '1' },
          { name: 'b', version: '1' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'CVE-2024-B',
        affectedPackages: [
          { name: 'a', version: '1' },
          { name: 'b', version: '1' },
          { name: 'c', version: '1' },
          { name: 'd', version: '1' },
        ],
      },
    ];
    // Jaccard = 2/4 = 0.5

    expect(createPackageMatchStrategy(0.5).match(oldReqs, newReqs).matched).toHaveLength(1);
    expect(createPackageMatchStrategy(0.51).match(oldReqs, newReqs).matched).toHaveLength(0);
  });

  it('skips requirements without affectedPackages', () => {
    const oldReqs = [
      { id: 'CVE-2024-A', impact: 0.7 }, // no affectedPackages
      {
        id: 'CVE-2024-B',
        affectedPackages: [{ name: 'openssl', version: '1.0.0' }],
      },
    ];
    const newReqs = [
      { id: 'CVE-2024-X', impact: 0.7 }, // no affectedPackages
      {
        id: 'CVE-2024-Y',
        affectedPackages: [{ name: 'openssl', version: '1.0.0' }],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Only the second pair has packages — they match
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('CVE-2024-B');
    expect(result.matched[0]!.newReq['id']).toBe('CVE-2024-Y');
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('skips requirements with empty affectedPackages array', () => {
    const oldReqs = [{ id: 'CVE-2024-A', affectedPackages: [] }];
    const newReqs = [{ id: 'CVE-2024-B', affectedPackages: [] }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('picks the highest-Jaccard pair when one new has multiple candidates', () => {
    // newY shares 2/2 with oldA (1.0); newY shares 1/3 with oldB (~0.33).
    // newY should pair with oldA.
    const oldReqs = [
      {
        id: 'OLD-A',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl', version: '7' },
        ],
      },
      {
        id: 'OLD-B',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'foo', version: '2' },
          { name: 'bar', version: '3' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'NEW-Y',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl', version: '7' },
        ],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('OLD-A');
    expect(result.matched[0]!.confidence).toBeCloseTo(1.0, 5);
  });

  it('does not double-match the same old requirement', () => {
    // Two new reqs both want to match the same old — only one wins.
    const oldReqs = [
      {
        id: 'OLD-A',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl', version: '7' },
        ],
      },
    ];
    const newReqs = [
      {
        id: 'NEW-X',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl', version: '7' },
        ],
      },
      {
        id: 'NEW-Y',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl', version: '7' },
        ],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    // Whichever new didn't win is unmatched
    expect(result.unmatchedNew).toHaveLength(1);
    expect(result.unmatchedOld).toHaveLength(0);
  });

  it('ignores malformed affectedPackages entries (non-strings, missing fields)', () => {
    const oldReqs = [
      {
        id: 'OLD-A',
        affectedPackages: [
          { name: 'openssl', version: '1' },
          { name: 'libcurl' }, // missing version
          { version: '2' }, // missing name
          'not-an-object', // wrong type
          { name: 42, version: '1' }, // non-string name
        ],
      },
    ];
    const newReqs = [
      {
        id: 'NEW-X',
        affectedPackages: [{ name: 'openssl', version: '1' }],
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Only the well-formed openssl@1 tuple counts on old side.
    // Jaccard = 1/1 = 1.0 — matches.
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.confidence).toBeCloseTo(1.0, 5);
  });

  it('ignores requirements whose affectedPackages field is not an array', () => {
    const oldReqs = [
      { id: 'OLD-A', affectedPackages: 'oops' as unknown as unknown[] },
    ];
    const newReqs = [
      { id: 'NEW-X', affectedPackages: [{ name: 'openssl', version: '1' }] },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('handles empty inputs', () => {
    const result = strategy.match([], []);
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });
});
