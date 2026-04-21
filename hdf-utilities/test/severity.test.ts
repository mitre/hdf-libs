import { describe, it, expect } from 'vitest';
import { severityToImpact, impactToSeverity } from '../src/severity/index.js';

describe('Severity Utilities', () => {
  describe('severityToImpact', () => {
    it('should map "critical" to 0.9', () => {
      expect(severityToImpact('critical')).toBe(0.9);
    });

    it('should map "high" to 0.7', () => {
      expect(severityToImpact('high')).toBe(0.7);
    });

    it('should map "medium" to 0.5', () => {
      expect(severityToImpact('medium')).toBe(0.5);
    });

    it('should map "low" to 0.3', () => {
      expect(severityToImpact('low')).toBe(0.3);
    });

    it('should map "info" to 0.0', () => {
      expect(severityToImpact('info')).toBe(0.0);
    });

    it('should map "none" to 0.0', () => {
      expect(severityToImpact('none')).toBe(0.0);
    });

    it('should map "informational" to 0.0', () => {
      expect(severityToImpact('informational')).toBe(0.0);
    });

    it('should map "information" to 0.0', () => {
      expect(severityToImpact('information')).toBe(0.0);
    });

    // Case insensitivity
    it('should be case-insensitive for "Critical"', () => {
      expect(severityToImpact('Critical')).toBe(0.9);
    });

    it('should be case-insensitive for "HIGH"', () => {
      expect(severityToImpact('HIGH')).toBe(0.7);
    });

    it('should be case-insensitive for "MEDIUM"', () => {
      expect(severityToImpact('MEDIUM')).toBe(0.5);
    });

    it('should be case-insensitive for "Low"', () => {
      expect(severityToImpact('Low')).toBe(0.3);
    });

    it('should be case-insensitive for "INFO"', () => {
      expect(severityToImpact('INFO')).toBe(0.0);
    });

    it('should be case-insensitive for "NONE"', () => {
      expect(severityToImpact('NONE')).toBe(0.0);
    });

    it('should be case-insensitive for "Informational"', () => {
      expect(severityToImpact('Informational')).toBe(0.0);
    });

    it('should be case-insensitive for mixed case "CrItIcAl"', () => {
      expect(severityToImpact('CrItIcAl')).toBe(0.9);
    });

    // Default for unrecognized values
    it('should return 0.5 for unrecognized severity strings', () => {
      expect(severityToImpact('unknown')).toBe(0.5);
    });

    it('should return 0.5 for empty string', () => {
      expect(severityToImpact('')).toBe(0.5);
    });

    it('should return 0.5 for arbitrary text', () => {
      expect(severityToImpact('something')).toBe(0.5);
    });

    it('should return 0.5 for numeric strings', () => {
      expect(severityToImpact('5')).toBe(0.5);
    });

    it('should return 0.5 for whitespace-padded severity', () => {
      // Whitespace is not trimmed, so " critical " is unrecognized
      expect(severityToImpact(' critical ')).toBe(0.5);
    });
  });

  describe('impactToSeverity', () => {
    // Critical threshold (>= 0.9)
    it('should return "critical" for impact 1.0', () => {
      expect(impactToSeverity(1.0)).toBe('critical');
    });

    it('should return "critical" for impact 0.9 (boundary)', () => {
      expect(impactToSeverity(0.9)).toBe('critical');
    });

    it('should return "critical" for impact 0.95', () => {
      expect(impactToSeverity(0.95)).toBe('critical');
    });

    // High threshold ([0.7, 0.9))
    it('should return "high" for impact 0.7 (boundary)', () => {
      expect(impactToSeverity(0.7)).toBe('high');
    });

    it('should return "high" for impact 0.8', () => {
      expect(impactToSeverity(0.8)).toBe('high');
    });

    it('should return "high" for impact 0.89 (just below critical)', () => {
      expect(impactToSeverity(0.89)).toBe('high');
    });

    it('should return "high" for impact 0.8999999', () => {
      expect(impactToSeverity(0.8999999)).toBe('high');
    });

    // Medium threshold ([0.4, 0.7))
    it('should return "medium" for impact 0.4 (boundary)', () => {
      expect(impactToSeverity(0.4)).toBe('medium');
    });

    it('should return "medium" for impact 0.5', () => {
      expect(impactToSeverity(0.5)).toBe('medium');
    });

    it('should return "medium" for impact 0.6', () => {
      expect(impactToSeverity(0.6)).toBe('medium');
    });

    it('should return "medium" for impact 0.69 (just below high)', () => {
      expect(impactToSeverity(0.69)).toBe('medium');
    });

    // Low threshold ((0.0, 0.4))
    it('should return "low" for impact 0.3', () => {
      expect(impactToSeverity(0.3)).toBe('low');
    });

    it('should return "low" for impact 0.1', () => {
      expect(impactToSeverity(0.1)).toBe('low');
    });

    it('should return "low" for impact 0.39 (just below medium)', () => {
      expect(impactToSeverity(0.39)).toBe('low');
    });

    it('should return "low" for impact 0.01 (just above zero)', () => {
      expect(impactToSeverity(0.01)).toBe('low');
    });

    it('should return "low" for very small positive value', () => {
      expect(impactToSeverity(0.001)).toBe('low');
    });

    // Informational threshold (0.0)
    it('should return "informational" for impact 0.0', () => {
      expect(impactToSeverity(0.0)).toBe('informational');
    });

    it('should return "informational" for impact 0', () => {
      expect(impactToSeverity(0)).toBe('informational');
    });

    // Negative values (edge case)
    it('should return "informational" for negative impact', () => {
      expect(impactToSeverity(-0.1)).toBe('informational');
    });

    it('should return "informational" for -1', () => {
      expect(impactToSeverity(-1)).toBe('informational');
    });

    // Values above 1.0 (edge case)
    it('should return "critical" for impact above 1.0', () => {
      expect(impactToSeverity(1.5)).toBe('critical');
    });
  });

  describe('Round-trip consistency', () => {
    it('severityToImpact then impactToSeverity returns "critical" for "critical"', () => {
      // severityToImpact('critical') = 0.9, impactToSeverity(0.9) = 'critical'
      expect(impactToSeverity(severityToImpact('critical'))).toBe('critical');
    });

    it('severityToImpact then impactToSeverity returns "high" for "high"', () => {
      // severityToImpact('high') = 0.7, impactToSeverity(0.7) = 'high'
      expect(impactToSeverity(severityToImpact('high'))).toBe('high');
    });

    it('severityToImpact then impactToSeverity returns "medium" for "medium"', () => {
      // severityToImpact('medium') = 0.5, impactToSeverity(0.5) = 'medium'
      expect(impactToSeverity(severityToImpact('medium'))).toBe('medium');
    });

    it('severityToImpact then impactToSeverity returns "low" for "low"', () => {
      // severityToImpact('low') = 0.3, impactToSeverity(0.3) = 'low'
      expect(impactToSeverity(severityToImpact('low'))).toBe('low');
    });

    it('severityToImpact then impactToSeverity returns "informational" for "info"', () => {
      // severityToImpact('info') = 0.0, impactToSeverity(0.0) = 'informational'
      expect(impactToSeverity(severityToImpact('info'))).toBe('informational');
    });

    it('severityToImpact then impactToSeverity returns "informational" for "none"', () => {
      expect(impactToSeverity(severityToImpact('none'))).toBe('informational');
    });

    it('severityToImpact then impactToSeverity returns "informational" for "informational"', () => {
      expect(impactToSeverity(severityToImpact('informational'))).toBe('informational');
    });

    it('severityToImpact then impactToSeverity returns "informational" for "information"', () => {
      expect(impactToSeverity(severityToImpact('information'))).toBe('informational');
    });
  });

  describe('CVSS alignment', () => {
    it('critical maps to CVSS 9.0 band floor (0.9)', () => {
      expect(severityToImpact('critical')).toBe(0.9);
    });

    it('high maps to CVSS 7.0 band floor (0.7)', () => {
      expect(severityToImpact('high')).toBe(0.7);
    });

    it('medium maps to 0.5 (midpoint of CVSS 4.0-6.9 band)', () => {
      expect(severityToImpact('medium')).toBe(0.5);
    });

    it('low maps to 0.3 (within CVSS 0.1-3.9 band)', () => {
      expect(severityToImpact('low')).toBe(0.3);
    });

    it('all informational-type labels map to 0.0', () => {
      const infoLabels = ['info', 'none', 'informational', 'information'];
      for (const label of infoLabels) {
        expect(severityToImpact(label)).toBe(0.0);
      }
    });
  });
});
