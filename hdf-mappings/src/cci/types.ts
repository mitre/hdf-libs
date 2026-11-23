/**
 * Represents a CCI (Control Correlation Identifier) item.
 */
export interface CCIItem {
  /** Definition/description of the CCI */
  def: string;
  /**
   * DISA's NIST SP 800-53 references keyed by revision ("4", "5"), as
   * published; a revision DISA gives no reference for is absent
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
