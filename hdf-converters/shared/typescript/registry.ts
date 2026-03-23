/**
 * Converter fingerprint registry.
 *
 * Lightweight fingerprint metadata — NO converter function imports.
 * Safe for client bundles. Converters are loaded lazily by consumers.
 */

export type InputFamily = 'json' | 'xml' | 'csv' | 'text';
export type ConverterDirection = 'ingest' | 'export';
export type OutputType = 'results' | 'baseline' | 'plan' | 'amendments'
                       | 'system' | 'evidence-package' | 'raw';

export interface ConverterFingerprint {
  /** Unique ID matching directory name: e.g. 'sarif-to-hdf' */
  id: string;
  /** Human-readable label: e.g. 'SARIF' */
  label: string;
  /** Direction of conversion */
  direction: ConverterDirection;
  /** Input format family */
  inputFamily: InputFamily;
  /** What the converter produces */
  outputType: OutputType;
  /** Structural fingerprint. Returns confidence 0.0-1.0. */
  fingerprint: (input: unknown) => number;
  /**
   * Optional version detector. Returns a version string from the parsed input.
   * For example, SARIF returns obj.version ("2.1.0"), CycloneDX returns
   * obj.specVersion ("1.5"). Undefined means version detection is not supported.
   */
  detectVersion?: (input: unknown) => string;
}

const registry: ConverterFingerprint[] = [];

export function registerFingerprint(fp: ConverterFingerprint): void {
  if (registry.some(d => d.id === fp.id)) {
    throw new Error(`Duplicate fingerprint: ${fp.id}`);
  }
  registry.push(fp);
}

export function getFingerprints(): readonly ConverterFingerprint[] {
  return [...registry];
}

export function getIngestFingerprints(): readonly ConverterFingerprint[] {
  return registry.filter(d => d.direction === 'ingest');
}

export function getFingerprint(id: string): ConverterFingerprint | undefined {
  const found = registry.find(d => d.id === id);
  return found ? { ...found } : undefined;
}

export function _resetRegistry(): void {
  registry.length = 0;
}
