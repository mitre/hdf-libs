/**
 * TypeScript types for AWS Config to NIST mappings
 */

export interface AwsConfigNistMapping {
  AwsConfigRuleSourceIdentifier: string;
  AwsConfigRuleName: string;
  'NIST-ID': string;
  Rev: number;
}

export type AwsConfigNistMappings = AwsConfigNistMapping[];
