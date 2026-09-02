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

/**
 * A maintainer-reviewed removal the generator applies after every source tier:
 * the (rule, control) pair is dropped at each listed revision on every
 * regeneration. Deliberately carries nothing else — no rationale or
 * attribution fields; git history records who committed a suppression and
 * when.
 */
export interface AwsConfigSuppression {
  rule: string;
  control: string;
  revisions: number[];
}

export type AwsConfigSuppressions = AwsConfigSuppression[];
