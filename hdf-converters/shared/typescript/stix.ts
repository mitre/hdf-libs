// Shared STIX 2.1 bundle parse/detect helper — the TypeScript peer of
// shared/go/stix.go (kept at parity, no fork). Consumed by the enrichment pass
// and (in a later phase) the CLI source fingerprint.

export type StixObject = Record<string, unknown>;

export interface StixBundle {
  type: string;
  id?: string;
  objects: StixObject[];
}

/** Parse and validate a STIX 2.1 bundle. Objects are kept raw for lossless carriage. */
export function parseStixBundle(input: string): StixBundle {
  if (!input) throw new Error('stix: empty input');
  let raw: unknown;
  try {
    raw = JSON.parse(input);
  } catch (e) {
    throw new Error(`stix: parsing bundle: ${(e as Error).message}`);
  }
  const obj = (raw ?? {}) as Record<string, unknown>;
  if (obj.type !== 'bundle') {
    throw new Error(`stix: not a STIX bundle (type=${JSON.stringify(obj.type)})`);
  }
  if (!Array.isArray(obj.objects)) {
    throw new Error('stix: bundle has no objects[]');
  }
  return {
    type: 'bundle',
    id: typeof obj.id === 'string' ? obj.id : undefined,
    objects: obj.objects as StixObject[],
  };
}

/** Report whether the input looks like a STIX 2.1 bundle, without throwing. */
export function detectStixBundle(input: string): boolean {
  try {
    const o = JSON.parse(input) as Record<string, unknown>;
    return o?.type === 'bundle' && Array.isArray(o.objects);
  } catch {
    return false;
  }
}

/** A STIX object's id ('' if absent). */
export function stixObjectId(obj: StixObject): string {
  return typeof obj.id === 'string' ? obj.id : '';
}

/**
 * The CVE ids a STIX object cites via external_references (source_name "cve").
 * A STIX vulnerability records its CVE this way, not in a native field
 * (STIX 2.1 §4.19).
 */
export function stixObjectCVEs(obj: StixObject): string[] {
  const refs = obj.external_references;
  if (!Array.isArray(refs)) return [];
  const cves: string[] = [];
  for (const r of refs) {
    const ref = r as Record<string, unknown>;
    if (
      typeof ref.source_name === 'string' &&
      ref.source_name.toLowerCase() === 'cve' &&
      typeof ref.external_id === 'string' &&
      ref.external_id
    ) {
      cves.push(ref.external_id);
    }
  }
  return cves;
}
