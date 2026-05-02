import { describe, it, expect } from 'vitest';
import {
  createVendorFuzzyTitleStrategy,
  levenshteinDistance,
  normalizedLevenshtein,
} from '../../src/matching/vendor-fuzzy-title.js';
import { autoDetectPrefix, normalizeTitle } from '../../src/matching/vendor-fuzzy-title.js';

describe('levenshteinDistance', () => {
  it('should return 0 for identical strings', () => {
    expect(levenshteinDistance('abc', 'abc')).toBe(0);
  });

  it('should handle empty strings', () => {
    expect(levenshteinDistance('', '')).toBe(0);
    expect(levenshteinDistance('abc', '')).toBe(3);
    expect(levenshteinDistance('', 'abc')).toBe(3);
  });

  it('should compute correct edit distance', () => {
    expect(levenshteinDistance('kitten', 'sitting')).toBe(3);
    expect(levenshteinDistance('Saturday', 'Sunday')).toBe(3);
  });

  it('should handle single character', () => {
    expect(levenshteinDistance('a', 'b')).toBe(1);
    expect(levenshteinDistance('a', 'a')).toBe(0);
  });
});

describe('normalizedLevenshtein', () => {
  it('should return 0.0 for identical strings', () => {
    expect(normalizedLevenshtein('abc', 'abc')).toBe(0.0);
  });

  it('should return 0.0 for both empty', () => {
    expect(normalizedLevenshtein('', '')).toBe(0.0);
  });

  it('should return 1.0 for completely different single chars', () => {
    expect(normalizedLevenshtein('a', 'b')).toBe(1.0);
  });

  it('should return value between 0 and 1', () => {
    const dist = normalizedLevenshtein('kitten', 'sitting');
    expect(dist).toBeGreaterThan(0);
    expect(dist).toBeLessThan(1);
  });
});

describe('autoDetectPrefix', () => {
  it('should detect dominant multi-token prefix', () => {
    const titles = [
      'RHEL 9 must be supported.',
      'RHEL 9 must check GPG signatures.',
      'RHEL 9 must disable audit.',
      'Ubuntu 22 must use TLS.',
    ];
    expect(autoDetectPrefix(titles)).toBe('RHEL 9');
  });

  it('should detect prefix with outliers', () => {
    const titles = [
      'Nutanix VMM must enable logging.',
      'Nutanix VMM must restrict access.',
      'Nutanix VMM must enforce TLS.',
      'Something else must exist.',
    ];
    expect(autoDetectPrefix(titles)).toBe('Nutanix VMM');
  });

  it('should return empty for feature-focused corpus (no dominant prefix)', () => {
    const titles = [
      'Ensure password complexity is set.',
      'Verify SSH is configured.',
      'Check file permissions.',
      'Audit log rotation.',
    ];
    expect(autoDetectPrefix(titles)).toBe('');
  });

  it('should return empty for empty array', () => {
    expect(autoDetectPrefix([])).toBe('');
  });

  it('should stop before modal verbs', () => {
    const titles = [
      'The Apache web server must be configured.',
      'The Apache web server must limit connections.',
      'The Apache web server must use TLS.',
    ];
    expect(autoDetectPrefix(titles)).toBe('The Apache web server');
  });
});

describe('normalizeTitle', () => {
  it('should strip leading prefix', () => {
    expect(normalizeTitle('RHEL 9 must be supported.', 'RHEL 9')).toBe('must be supported.');
  });

  it('should return unchanged when prefix is empty', () => {
    expect(normalizeTitle('must be supported.', '')).toBe('must be supported.');
  });

  it('should return unchanged when prefix not at start', () => {
    expect(normalizeTitle('Ubuntu must use RHEL 9 tools.', 'RHEL 9')).toBe(
      'Ubuntu must use RHEL 9 tools.',
    );
  });

  it('should handle title equal to prefix', () => {
    expect(normalizeTitle('RHEL 9', 'RHEL 9')).toBe('');
  });
});

describe('VendorFuzzyTitleStrategy', () => {
  const strategy = createVendorFuzzyTitleStrategy();

  it('should have name "vendorFuzzyTitle"', () => {
    expect(strategy.name).toBe('vendorFuzzyTitle');
  });

  it('should match cross-vendor titles after prefix normalization', () => {
    const oldReqs = [
      { id: 'V-001', title: 'RHEL 9 must enable audit logging.', impact: 0.7, tags: {} },
      { id: 'V-002', title: 'RHEL 9 must configure SSH.', impact: 0.5, tags: {} },
    ];
    const newReqs = [
      {
        id: 'AL-001',
        title: 'Amazon Linux 2023 must enable audit logging.',
        impact: 0.7,
        tags: {},
      },
      { id: 'AL-002', title: 'Amazon Linux 2023 must configure SSH.', impact: 0.5, tags: {} },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should reject unrelated titles', () => {
    const oldReqs = [
      { id: 'V-001', title: 'RHEL 9 must enable audit logging.', impact: 0.7, tags: {} },
    ];
    const newReqs = [
      { id: 'AL-001', title: 'Amazon Linux 2023 must configure TLS certificates.', impact: 0.7, tags: {} },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle requirements with no title', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7, tags: {} }];
    const newReqs = [{ id: 'AL-001', impact: 0.7, tags: {} }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
  });

  it('should handle empty inputs', () => {
    const result = strategy.match([], []);
    expect(result.matched).toHaveLength(0);
  });

  it('should use relationship field', () => {
    const oldReqs = [
      { id: 'V-001', title: 'RHEL 9 must enable audit logging.', impact: 0.7, tags: {} },
    ];
    const newReqs = [
      {
        id: 'AL-001',
        title: 'Amazon Linux 2023 must enable audit logging.',
        impact: 0.7,
        tags: {},
      },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.relationship).toBe('primary');
  });

  it('should work with feature-focused corpus (no prefix to strip)', () => {
    const oldReqs = [
      { id: 'V-001', title: 'Ensure password complexity is set.', impact: 0.7, tags: {} },
      { id: 'V-002', title: 'Verify SSH is configured properly.', impact: 0.5, tags: {} },
    ];
    const newReqs = [
      { id: 'R-001', title: 'Ensure password complexity is set.', impact: 0.7, tags: {} },
      { id: 'R-002', title: 'Verify SSH is configured properly.', impact: 0.5, tags: {} },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
  });
});
