import { describe, it, expect } from 'vitest';
import {
  getScoutsuiteNistMapping,
  getScoutsuiteNistControl,
  getAllScoutsuiteRules,
  scoutsuiteRuleExists,
  getAllScoutsuiteMappings,
} from '../src/scoutsuite/index.js';

describe('ScoutSuite Mapping Functions', () => {
  describe('getScoutsuiteNistMapping', () => {
    it('should return mapping for valid rule', () => {
      const mapping = getScoutsuiteNistMapping('acm-certificate-with-close-expiration-date');
      expect(mapping).toBeDefined();
      expect(mapping?.RULE).toBe('acm-certificate-with-close-expiration-date');
      expect(mapping?.['NIST-ID']).toBe('SC-12');
    });

    it('should return undefined for invalid rule', () => {
      const mapping = getScoutsuiteNistMapping('invalid-rule-name');
      expect(mapping).toBeUndefined();
    });

    it('should handle multiple rules', () => {
      const mapping1 = getScoutsuiteNistMapping(
        'acm-certificate-with-transparency-logging-disabled'
      );
      const mapping2 = getScoutsuiteNistMapping('cloudformation-stack-with-role');
      expect(mapping1?.['NIST-ID']).toBe('SC-12');
      expect(mapping2?.['NIST-ID']).toBe('AC-6');
    });
  });

  describe('getScoutsuiteNistControl', () => {
    it('should return NIST control ID for valid rule', () => {
      const nistId = getScoutsuiteNistControl('acm-certificate-with-close-expiration-date');
      expect(nistId).toBe('SC-12');
    });

    it('should return undefined for invalid rule', () => {
      const nistId = getScoutsuiteNistControl('invalid-rule-name');
      expect(nistId).toBeUndefined();
    });

    it('should handle complex NIST IDs with pipes', () => {
      const nistId = getScoutsuiteNistControl('cloudtrail-no-cloudwatch-integration');
      expect(nistId).toBe('AU-12|SI-4(2)');
    });
  });

  describe('getAllScoutsuiteRules', () => {
    it('should return all rule names', () => {
      const rules = getAllScoutsuiteRules();
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.length).toBeGreaterThan(0);
      expect(rules).toContain('acm-certificate-with-close-expiration-date');
      expect(rules).toContain('cloudformation-stack-with-role');
    });

    it('should return rules in a consistent order', () => {
      const rules1 = getAllScoutsuiteRules();
      const rules2 = getAllScoutsuiteRules();
      expect(rules1).toEqual(rules2);
    });
  });

  describe('scoutsuiteRuleExists', () => {
    it('should return true for valid rules', () => {
      expect(scoutsuiteRuleExists('acm-certificate-with-close-expiration-date')).toBe(true);
      expect(scoutsuiteRuleExists('cloudformation-stack-with-role')).toBe(true);
    });

    it('should return false for invalid rule', () => {
      expect(scoutsuiteRuleExists('invalid-rule-name')).toBe(false);
    });
  });

  describe('getAllScoutsuiteMappings', () => {
    it('should return all mappings', () => {
      const mappings = getAllScoutsuiteMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllScoutsuiteMappings();
      const firstMapping = mappings[0];
      expect(firstMapping).toHaveProperty('RULE');
      expect(firstMapping).toHaveProperty('NIST-ID');
    });

    it('should include specific rules', () => {
      const mappings = getAllScoutsuiteMappings();
      const rules = mappings.map((m) => m.RULE);
      expect(rules).toContain('acm-certificate-with-close-expiration-date');
      expect(rules).toContain('cloudformation-stack-with-role');
    });
  });
});
