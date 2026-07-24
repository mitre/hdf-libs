import { describe, it, expect } from 'vitest';
import {
  getAwsConfigNistMappingByIdentifier,
  getAwsConfigNistMappingByName,
  getAwsConfigNistControlByIdentifier,
  getAwsConfigNistControlByName,
  getAwsConfigNistControlsBySubstring,
  getAllAwsConfigIdentifiers,
  getAllAwsConfigRuleNames,
  awsConfigIdentifierExists,
  awsConfigRuleNameExists,
  awsConfigMappedRevisions,
  getAllAwsConfigMappings,
} from '../src/awsconfig/index.js';

describe('AWS Config Mapping Functions', () => {
  describe('getAwsConfigNistMappingByIdentifier', () => {
    it('should return mapping for valid identifier', () => {
      // Rev4-only rule; pin the lookup so it is unaffected by the default revision.
      const mapping = getAwsConfigNistMappingByIdentifier(
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK',
        4
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
        'secretsmanager-scheduled-rotation-success-check',
        4
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
        'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK',
        4
      );
      expect(nistId).toBe('AC-2(1)|AC-2(j)');
    });

    it('should return undefined for invalid identifier', () => {
      const nistId = getAwsConfigNistControlByIdentifier('INVALID_IDENTIFIER');
      expect(nistId).toBeUndefined();
    });

    it('should handle complex NIST IDs', () => {
      const nistId = getAwsConfigNistControlByIdentifier('IAM_PASSWORD_POLICY', 4);
      // Rev-4 collapsed sub-parts IA-5(1)(a)(d)(e) are expanded to siblings.
      expect(nistId).toBe('AC-2(1)|AC-2(f)|AC-2(j)|IA-2|IA-5(1)|IA-5(a)|IA-5(d)|IA-5(e)|IA-5(4)');
    });
  });

  describe('getAwsConfigNistControlByName', () => {
    it('should return NIST control for valid rule name', () => {
      const nistId = getAwsConfigNistControlByName(
        'secretsmanager-scheduled-rotation-success-check',
        4
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
      const identifiers = getAllAwsConfigIdentifiers(4);
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
      const names = getAllAwsConfigRuleNames(4);
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
        awsConfigIdentifierExists('SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK', 4)
      ).toBe(true);
      expect(awsConfigIdentifierExists('IAM_USER_GROUP_MEMBERSHIP_CHECK', 4)).toBe(true);
    });

    it('should return false for invalid identifier', () => {
      expect(awsConfigIdentifierExists('INVALID_IDENTIFIER')).toBe(false);
    });
  });

  describe('awsConfigRuleNameExists', () => {
    it('should return true for valid rule names', () => {
      expect(awsConfigRuleNameExists('secretsmanager-scheduled-rotation-success-check', 4)).toBe(
        true
      );
      expect(awsConfigRuleNameExists('iam-user-group-membership-check', 4)).toBe(true);
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

  describe('awsConfigMappedRevisions', () => {
    it('returns both revisions for a rule mapped at each', () => {
      expect(awsConfigMappedRevisions('CLOUD_TRAIL_ENABLED', 'cloudtrail-enabled')).toEqual([4, 5]);
    });

    it('returns only Rev 5 for a Rev5-only rule', () => {
      expect(awsConfigMappedRevisions('API_GW_SSL_ENABLED', 'api-gw-ssl-enabled')).toEqual([5]);
    });

    it('returns only Rev 4 for a Rev4-only rule', () => {
      expect(
        awsConfigMappedRevisions(
          'SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK',
          'secretsmanager-scheduled-rotation-success-check'
        )
      ).toEqual([4]);
    });

    it('returns empty for an unmapped rule', () => {
      expect(awsConfigMappedRevisions('NOPE', 'no-such-rule')).toEqual([]);
    });
  });
});

describe('revision-aware lookup', () => {
  it('returns Rev 5 by default and Rev 4 when requested', () => {
    expect(getAwsConfigNistControlByName('access-keys-rotated')).toBe('AC-3(15)');
    expect(getAwsConfigNistControlByName('access-keys-rotated', 4)).toBe('AC-2(1)|AC-2(j)');
    expect(getAwsConfigNistControlByName('access-keys-rotated', 5)).toBe('AC-3(15)');
  });

  it('identifier lookup is revision-aware', () => {
    expect(getAwsConfigNistMappingByIdentifier('ACCESS_KEYS_ROTATED')?.Rev).toBe(5);
    expect(getAwsConfigNistMappingByIdentifier('ACCESS_KEYS_ROTATED', 4)?.Rev).toBe(4);
  });

  it('returns undefined for an unknown revision', () => {
    expect(getAwsConfigNistControlByName('access-keys-rotated', 99)).toBeUndefined();
  });
});

describe('getAwsConfigNistControlsBySubstring', () => {
  it('resolves a decorated Security Hub rule name to canonical controls', () => {
    const got = getAwsConfigNistControlsBySubstring(
      'securityhub-s3-bucket-public-read-prohibited-491148b1',
      4
    );
    expect(got.length).toBeGreaterThan(0);
    const raw = getAwsConfigNistControlByName('s3-bucket-public-read-prohibited', 4);
    expect(got).toEqual(raw?.split('|').map((s) => s.trim()));
  });

  it('returns [] for an unmatched name', () => {
    expect(getAwsConfigNistControlsBySubstring('totally-unknown-rule-xyz', 4)).toEqual([]);
  });

  it('returns [] for an empty name', () => {
    expect(getAwsConfigNistControlsBySubstring('')).toEqual([]);
  });
});

// Guards Rev-4 rows that once carried collapsed NIST sub-parts
// (e.g. IA-5(1)(a)(d)(e)) that split('|') left as single unreachable tokens.
describe('Rev-4 collapsed control expansion', () => {
  it('expands collapsed sub-parts into sibling controls', () => {
    const raw = getAwsConfigNistControlByIdentifier('IAM_PASSWORD_POLICY', 4);
    expect(raw).toBeDefined();
    const controls = raw!.split('|');
    for (const want of ['IA-5(1)', 'IA-5(a)', 'IA-5(d)', 'IA-5(e)']) {
      expect(controls).toContain(want);
    }
    // No token may retain more than one parenthetical group (a collapsed form).
    for (const c of controls) {
      expect((c.match(/\(/g) ?? []).length).toBeLessThanOrEqual(1);
    }
  });
});
