/**
 * TypeScript types for AWS Config to NIST mappings
 */

export interface AwsConfigNistMapping {
  AwsConfigRuleSourceIdentifier: string;
  AwsConfigRuleName: string;
  'NIST-ID': string;
  Rev: number;
  /**
   * Generator tier the row came from: config-pack, security-hub,
   * derived-theme, or crosswalk (rev-translated from the rule's native
   * revision; an empty NIST-ID means no equivalent exists at this Rev).
   */
  Source: string;
}

export type AwsConfigNistMappings = AwsConfigNistMapping[];
