/**
 * Represents a CCI (Control Correlation Identifier) item.
 */
export interface CCIItem {
  /** Definition/description of the CCI */
  def: string;
  /**
   * DISA's NIST SP 800-53 references keyed by revision, as published: "4" and
   * "5" where DISA gives them, and "3" only for an item with neither
   */
  nist: Partial<Record<string, string[]>>;
}

/**
 * CCI mappings database structure
 */
export type CCIMappings = Record<string, CCIItem>;

/**
 * NIST control → CCI ID mapping database structure.
 * Keys are base NIST controls (e.g. "SA-11"), values are arrays of CCI IDs.
 */
export type NistCCIMappings = Record<string, string[]>;
