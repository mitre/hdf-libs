/**
 * Represents a CCI (Control Correlation Identifier) item.
 */
export interface CCIItem {
  /** Definition/description of the CCI */
  def: string;
  /** Array of NIST control references this CCI maps to */
  nist: string[];
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
