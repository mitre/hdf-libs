import { describe, it, expect } from 'vitest';
import {
  getAwsConfigNistMappingByIdentifier,
  getAwsConfigNistMappingByName,
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
  getAllAwsConfigIdentifiers,
  getAllAwsConfigRuleNames,
  awsConfigIdentifierExists,
  awsConfigRuleNameExists,
  getAllAwsConfigMappings,
} from '../src/awsconfig/index.js';

describe('AWS Config Mapping Functions', () => {
  describe('getAwsConfigNistMappingByIdentifier', () => {
    it('should return mapping for valid identifier', () => {
      const mapping = getAwsConfigNistMappingByIdentifier(
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK'
      );
      expect(mapping).toBeDefined();
      expect(mapping?.AwsConfigRuleSourceIdentifier).toBe(
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK'
      );
      expect(mapping?.AwsConfigRuleName).toBe(
        'secretsmanager-scheduled-rotation-success-check'
      );
      expect(mapping?.['NIST-ID']).toBe('AC-2(1)|AC-2(j)');
    });

    it('should return undefined for invalid identifier', () => {
      const mapping = getAwsConfigNistMappingByIdentifier('INVALID_IDENTIFIER');
      expect(mapping).toBeUndefined();
    });
  });

  describe('getAwsConfigNistMappingByName', () => {
    it('should return mapping for valid rule name', () => {
      const mapping = getAwsConfigNistMappingByName(
        'secretsmanager-scheduled-rotation-success-check'
      );
      expect(mapping).toBeDefined();
      expect(mapping?.AwsConfigRuleSourceIdentifier).toBe(
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK'
      );
      expect(mapping?.['NIST-ID']).toBe('AC-2(1)|AC-2(j)');
    });

    it('should return undefined for invalid rule name', () => {
      const mapping = getAwsConfigNistMappingByName('invalid-rule-name');
      expect(mapping).toBeUndefined();
    });
  });

  describe('getAwsConfigNistControlByIdentifier', () => {
    it('should return NIST control for valid identifier', () => {
      const nistId = getAwsConfigNistControlByIdentifier(
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK'
      );
      expect(nistId).toBe('AC-2(1)|AC-2(j)');
    });

    it('should return undefined for invalid identifier', () => {
      const nistId = getAwsConfigNistControlByIdentifier('INVALID_IDENTIFIER');
      expect(nistId).toBeUndefined();
    });

    it('should handle complex NIST IDs', () => {
      const nistId = getAwsConfigNistControlByIdentifier('IAM_PASSWORD_POLICY');
      expect(nistId).toBe('AC-2(1)|AC-2(f)|AC-2(j)|IA-2|IA-5(1)(a)(d)(e)|IA-5(4)');
    });
  });

  describe('getAwsConfigNistControlByName', () => {
    it('should return NIST control for valid rule name', () => {
      const nistId = getAwsConfigNistControlByName(
        'secretsmanager-scheduled-rotation-success-check'
      );
      expect(nistId).toBe('AC-2(1)|AC-2(j)');
    });

    it('should return undefined for invalid rule name', () => {
      const nistId = getAwsConfigNistControlByName('invalid-rule-name');
      expect(nistId).toBeUndefined();
    });
  });

  describe('getAllAwsConfigIdentifiers', () => {
    it('should return all identifiers', () => {
      const identifiers = getAllAwsConfigIdentifiers();
      expect(Array.isArray(identifiers)).toBe(true);
      expect(identifiers.length).toBeGreaterThan(0);
      expect(identifiers).toContain('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK');
      expect(identifiers).toContain('IAM_USER_GROUP_MEMBERSHIP_CHECK');
    });

    it('should return identifiers in a consistent order', () => {
      const ids1 = getAllAwsConfigIdentifiers();
      const ids2 = getAllAwsConfigIdentifiers();
      expect(ids1).toEqual(ids2);
    });
  });

  describe('getAllAwsConfigRuleNames', () => {
    it('should return all rule names', () => {
      const names = getAllAwsConfigRuleNames();
      expect(Array.isArray(names)).toBe(true);
      expect(names.length).toBeGreaterThan(0);
      expect(names).toContain('secretsmanager-scheduled-rotation-success-check');
      expect(names).toContain('iam-user-group-membership-check');
    });

    it('should return names in a consistent order', () => {
      const names1 = getAllAwsConfigRuleNames();
      const names2 = getAllAwsConfigRuleNames();
      expect(names1).toEqual(names2);
    });
  });

  describe('awsConfigIdentifierExists', () => {
    it('should return true for valid identifiers', () => {
      expect(
        awsConfigIdentifierExists('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK')
      ).toBe(true);
      expect(awsConfigIdentifierExists('IAM_USER_GROUP_MEMBERSHIP_CHECK')).toBe(true);
    });

    it('should return false for invalid identifier', () => {
      expect(awsConfigIdentifierExists('INVALID_IDENTIFIER')).toBe(false);
    });
  });

  describe('awsConfigRuleNameExists', () => {
    it('should return true for valid rule names', () => {
      expect(awsConfigRuleNameExists('secretsmanager-scheduled-rotation-success-check')).toBe(
        true
      );
      expect(awsConfigRuleNameExists('iam-user-group-membership-check')).toBe(true);
    });

    it('should return false for invalid rule name', () => {
      expect(awsConfigRuleNameExists('invalid-rule-name')).toBe(false);
    });
  });

  describe('getAllAwsConfigMappings', () => {
    it('should return all mappings', () => {
      const mappings = getAllAwsConfigMappings();
      expect(Array.isArray(mappings)).toBe(true);
      expect(mappings.length).toBeGreaterThan(0);
    });

    it('should return mappings with correct structure', () => {
      const mappings = getAllAwsConfigMappings();
      const firstMapping = mappings[0];
      expect(firstMapping).toHaveProperty('AwsConfigRuleSourceIdentifier');
      expect(firstMapping).toHaveProperty('AwsConfigRuleName');
      expect(firstMapping).toHaveProperty('NIST-ID');
      expect(firstMapping).toHaveProperty('Rev');
    });

    it('should include specific rules', () => {
      const mappings = getAllAwsConfigMappings();
      const identifiers = mappings.map((m) => m.AwsConfigRuleSourceIdentifier);
      expect(identifiers).toContain('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK');
      expect(identifiers).toContain('IAM_USER_GROUP_MEMBERSHIP_CHECK');
    });
  });
});
