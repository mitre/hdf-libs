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
