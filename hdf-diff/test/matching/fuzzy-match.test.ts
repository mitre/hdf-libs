import { describe, it, expect } from 'vitest';
import { createFuzzyTitleStrategy, tokenize, jaccardSimilarity } from '../../src/matching/fuzzy-match.js';

describe('FuzzyTitleStrategy', () => {
  describe('tokenize', () => {
    it('should lowercase and split on whitespace', () => {
      const tokens = tokenize('Ensure SSH Root Login');
      expect(tokens).toContain('ensure');
      expect(tokens).toContain('ssh');
      expect(tokens).toContain('root');
      expect(tokens).toContain('login');
    });

    it('should split on punctuation', () => {
      const tokens = tokenize('root-login/access');
      expect(tokens).toContain('root');
      expect(tokens).toContain('login');
      expect(tokens).toContain('access');
    });

    it('should remove common stop words', () => {
      const tokens = tokenize('the quick brown fox is a test');
      expect(tokens).not.toContain('the');
      expect(tokens).not.toContain('is');
      expect(tokens).not.toContain('a');
      expect(tokens).toContain('quick');
      expect(tokens).toContain('brown');
      expect(tokens).toContain('fox');
    });

    it('should return empty set for empty string', () => {
      const tokens = tokenize('');
      expect(tokens.size).toBe(0);
    });

    it('should return empty set for only stop words', () => {
      const tokens = tokenize('the a an is');
      expect(tokens.size).toBe(0);
    });
  });

  describe('jaccardSimilarity', () => {
    it('should return 1.0 for identical sets', () => {
      const a = new Set(['ssh', 'root', 'login']);
      const b = new Set(['ssh', 'root', 'login']);
      expect(jaccardSimilarity(a, b)).toBe(1.0);
    });

    it('should return 0.0 for completely disjoint sets', () => {
      const a = new Set(['ssh', 'root', 'login']);
      const b = new Set(['ntp', 'time', 'sync']);
      expect(jaccardSimilarity(a, b)).toBe(0.0);
    });

    it('should return correct similarity for partially overlapping sets', () => {
      const a = new Set(['ssh', 'root', 'login', 'disabled']);
      const b = new Set(['ssh', 'root', 'login', 'must', 'disabled']);
      // intersection = {ssh, root, login, disabled} = 4
      // union = {ssh, root, login, disabled, must} = 5
      expect(jaccardSimilarity(a, b)).toBeCloseTo(0.8, 5);
    });

    it('should return 0.0 for two empty sets', () => {
      expect(jaccardSimilarity(new Set(), new Set())).toBe(0.0);
    });

    it('should return 0.0 when one set is empty', () => {
      expect(jaccardSimilarity(new Set(['a']), new Set())).toBe(0.0);
    });
  });

  describe('strategy', () => {
    const strategy = createFuzzyTitleStrategy();

    it('should have name "fuzzyTitle"', () => {
      expect(strategy.name).toBe('fuzzyTitle');
    });

    it('should match similar titles above default threshold', () => {
      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'SSH root login must be disabled', impact: 0.7 },
      ];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(1);
      expect(result.matched[0]!.oldReq['id']).toBe('V-001');
      expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
      expect(result.matched[0]!.confidence).toBeGreaterThanOrEqual(0.6);
      expect(result.matched[0]!.strategy).toBe('fuzzyTitle');
    });

    it('should not match dissimilar titles', () => {
      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'Configure NTP time synchronization', impact: 0.7 },
      ];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(0);
      expect(result.unmatchedOld).toHaveLength(1);
      expect(result.unmatchedNew).toHaveLength(1);
    });

    it('should use custom minConfidence threshold', () => {
      const highThreshold = createFuzzyTitleStrategy(0.9);

      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'SSH root login must be disabled', impact: 0.7 },
      ];

      const result = highThreshold.match(oldReqs, newReqs);

      // With 0.9 threshold, slightly different titles should not match
      expect(result.matched).toHaveLength(0);
    });

    it('should use greedy best-match (prefer highest similarity)', () => {
      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'SSH root login must be disabled', impact: 0.7 },
        { id: 'RHEL-002', title: 'SSH protocol version must be 2', impact: 0.5 },
      ];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(1);
      expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
      expect(result.unmatchedNew).toHaveLength(1);
    });

    it('should handle requirements without title field', () => {
      const oldReqs = [{ id: 'V-001', impact: 0.7 }];
      const newReqs = [{ id: 'RHEL-001', impact: 0.7 }];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(0);
      expect(result.unmatchedOld).toHaveLength(1);
      expect(result.unmatchedNew).toHaveLength(1);
    });

    it('should handle empty title strings', () => {
      const oldReqs = [{ id: 'V-001', title: '', impact: 0.7 }];
      const newReqs = [{ id: 'RHEL-001', title: '', impact: 0.7 }];

      const result = strategy.match(oldReqs, newReqs);

      // Empty titles produce empty token sets -> similarity 0
      expect(result.matched).toHaveLength(0);
    });

    it('should match identical titles with confidence 1.0', () => {
      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      ];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(1);
      expect(result.matched[0]!.confidence).toBe(1.0);
    });

    it('should skip already-matched new requirements in greedy assignment', () => {
      const strategy = createFuzzyTitleStrategy(0.3); // low threshold so both old reqs match
      const oldReqs = [
        { id: '1', title: 'SSH root login configuration check', impact: 0.7 },
        { id: '2', title: 'SSH root login setting verification', impact: 0.7 },
      ];
      const newReqs = [
        // Both old reqs are similar to this single new req;
        // the greedy algorithm matches the best one and skips the other
        { id: 'A', title: 'SSH root login configuration check', impact: 0.7 },
      ];
      const result = strategy.match(
        oldReqs as unknown as Record<string, unknown>[],
        newReqs as unknown as Record<string, unknown>[],
      );
      // One match (best scoring pair), one unmatched old, zero unmatched new
      expect(result.matched).toHaveLength(1);
      expect(result.unmatchedOld).toHaveLength(1);
      expect(result.unmatchedNew).toHaveLength(0);
    });

    it('should match multiple requirements greedily', () => {
      const oldReqs = [
        { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
        { id: 'V-002', title: 'NTP time synchronization configured correctly', impact: 0.5 },
      ];
      const newReqs = [
        { id: 'RHEL-001', title: 'SSH root login must be disabled', impact: 0.7 },
        { id: 'RHEL-002', title: 'NTP time synchronization configured properly', impact: 0.5 },
      ];

      const result = strategy.match(oldReqs, newReqs);

      expect(result.matched).toHaveLength(2);
      expect(result.unmatchedOld).toHaveLength(0);
      expect(result.unmatchedNew).toHaveLength(0);
    });
  });
});
