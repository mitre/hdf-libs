/**
 * Query functions for AWS Config to NIST mappings
 */

import type { AwsConfigNistMapping, AwsConfigNistMappings } from './types.js';
import rawMappings from '../data/awsconfig-mappings.json';

const mappings = rawMappings as AwsConfigNistMappings;
const indexByIdentifier = new Map<string, AwsConfigNistMapping>(
  mappings.map(m => [m.AwsConfigRuleSourceIdentifier, m])
);
const indexByRuleName = new Map<string, AwsConfigNistMapping>(
  mappings.map(m => [m.AwsConfigRuleName, m])
);

/**
 * Get the full mapping for an AWS Config rule by source identifier
 * @param identifier - The AWS Config rule source identifier
 * @returns The mapping object or undefined if not found
 */
export function getAwsConfigNistMappingByIdentifier(
  identifier: string
): AwsConfigNistMapping | undefined {
  return indexByIdentifier.get(identifier);
}

/**
 * Get the full mapping for an AWS Config rule by rule name
 * @param ruleName - The AWS Config rule name
 * @returns The mapping object or undefined if not found
 */
export function getAwsConfigNistMappingByName(
  ruleName: string
): AwsConfigNistMapping | undefined {
  return indexByRuleName.get(ruleName);
}

/**
 * Get the NIST control ID for an AWS Config rule by source identifier
 * @param identifier - The AWS Config rule source identifier
 * @returns The NIST control ID or undefined if not found
 */
export function getAwsConfigNistControlByIdentifier(identifier: string): string | undefined {
  const mapping = getAwsConfigNistMappingByIdentifier(identifier);
  return mapping?.['NIST-ID'];
}

/**
 * Get the NIST control ID for an AWS Config rule by rule name
 * @param ruleName - The AWS Config rule name
 * @returns The NIST control ID or undefined if not found
 */
export function getAwsConfigNistControlByName(ruleName: string): string | undefined {
  const mapping = getAwsConfigNistMappingByName(ruleName);
  return mapping?.['NIST-ID'];
}

/**
 * Get all AWS Config rule source identifiers
 * @returns Array of all rule source identifiers
 */
export function getAllAwsConfigIdentifiers(): string[] {
  return Array.from(indexByIdentifier.keys());
}

/**
 * Get all AWS Config rule names
 * @returns Array of all rule names
 */
export function getAllAwsConfigRuleNames(): string[] {
  return Array.from(indexByRuleName.keys());
}

/**
 * Check if an AWS Config rule exists by source identifier
 * @param identifier - The rule source identifier to check
 * @returns True if the rule exists
 */
export function awsConfigIdentifierExists(identifier: string): boolean {
  return indexByIdentifier.has(identifier);
}

/**
 * Check if an AWS Config rule exists by rule name
 * @param ruleName - The rule name to check
 * @returns True if the rule exists
 */
export function awsConfigRuleNameExists(ruleName: string): boolean {
  return indexByRuleName.has(ruleName);
}

/**
 * Get all AWS Config to NIST mappings
 * @returns Array of all mappings
 */
export function getAllAwsConfigMappings(): AwsConfigNistMappings {
  return [...mappings];
}
