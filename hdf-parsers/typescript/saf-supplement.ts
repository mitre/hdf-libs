// Backwards-compatible normalization of legacy SAF-supplement top-level keys
// (`target`, `passthrough`) into v3-native carriers, run before schema
// validation. Mirrors the Go side at hdf-parsers/go/saf_supplement.go — the two
// are pinned against a shared legacy-in/v3-out fixture pair.

const SAF_TARGET_DEPRECATION =
  "deprecated: top-level 'target' (saf supplement target write) was normalized into components[]; emit a component directly — this compatibility shim will be removed in a future release";
const SAF_PROVENANCE_DEPRECATION =
  "deprecated: top-level 'passthrough' was normalized into extensions.passthrough; write provenance under extensions — this compatibility shim will be removed in a future release";

// v3 component/target types. Kept in sync with the schema's Target_Type enum; an
// unknown type is left for the schema to reject rather than guessed.
const VALID_COMPONENT_TYPES = new Set([
  'aiModel', 'application', 'artifact', 'cloudAccount', 'cloudResource',
  'containerImage', 'containerInstance', 'containerPlatform', 'database',
  'dataset', 'host', 'network', 'repository',
]);

export interface SafNormalizeResult {
  /** The normalized JSON string (byte-identical to the input when nothing was rewritten). */
  output: string;
  /** One deprecation warning per rewritten legacy key. */
  warnings: string[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Rewrite the legacy SAF-supplement top-level keys into v3-native carriers so a
 * SAF-produced document becomes valid v3 before schema validation: `target` → a
 * components[] entry (type validated; id → name and, for cloudAccount, accountId,
 * falling back to name; labels and boundary → labels; merged into a matching or
 * platform-derived component rather than duplicated); `passthrough` →
 * extensions.passthrough.
 *
 * Deliberately narrow: input that is not a JSON object, or carries neither legacy
 * key, is returned BYTE-IDENTICAL with no warnings. A target whose type is not a
 * valid component type is left in place (with a warning) for the schema to reject.
 */
export function normalizeSafSupplement(input: string): SafNormalizeResult {
  let doc: unknown;
  try {
    doc = JSON.parse(input);
  } catch {
    return { output: input, warnings: [] }; // not JSON — let the validator surface it
  }
  if (!isObject(doc) || (!('target' in doc) && !('passthrough' in doc))) {
    return { output: input, warnings: [] }; // no legacy keys — byte-identical
  }

  const warnings: string[] = [];

  if ('target' in doc) {
    if (rewriteTarget(doc)) {
      warnings.push(SAF_TARGET_DEPRECATION);
    } else {
      warnings.push(
        `${SAF_TARGET_DEPRECATION} (target.type is not a recognized component type; left for schema validation)`,
      );
    }
  }

  if ('passthrough' in doc) {
    const relocations = rewritePassthrough(doc);
    warnings.push(SAF_PROVENANCE_DEPRECATION, ...relocations);
  }

  return { output: JSON.stringify(doc), warnings };
}

/** Lift a legacy top-level `target` object into components[]; returns false
 * (leaving `target` in place) when it is not an object or its type is invalid. */
function rewriteTarget(doc: Record<string, unknown>): boolean {
  const tgt = doc.target;
  if (!isObject(tgt)) return false;
  const typ = typeof tgt.type === 'string' ? tgt.type : '';
  if (!VALID_COMPONENT_TYPES.has(typ)) return false;
  // SAF writes `id`; the classic Heimdall/InSpec target carries `name` instead.
  const id =
    typeof tgt.id === 'string' && tgt.id !== '' ? tgt.id : typeof tgt.name === 'string' ? tgt.name : '';
  const boundary = typeof tgt.boundary === 'string' ? tgt.boundary : '';

  const comps: unknown[] = Array.isArray(doc.components) ? doc.components : [];

  let c = findComponent(comps, id, typ);
  if (!c) {
    c = platformComponent(comps, typ);
    if (c && id !== '') c.name = id;
  }
  if (!c) {
    c = { type: typ, name: id };
    if (typ === 'cloudAccount') c.accountId = id;
    comps.push(c);
  }
  applyLabels(c, stringLabels(tgt.labels));
  applyBoundaryLabel(c, boundary);
  doc.components = comps;
  delete doc.target;
  return true;
}

function findComponent(comps: unknown[], name: string, typ: string): Record<string, unknown> | undefined {
  return comps.find((c): c is Record<string, unknown> => isObject(c) && c.name === name && c.type === typ);
}

/** The lone component the v2 upgrade derives from an InSpec `platform` (no
 * componentId, OS name standing in as the name), which describes the same
 * assessed thing as the target. Any other shape is a distinct component and is
 * never renamed. */
function platformComponent(comps: unknown[], typ: string): Record<string, unknown> | undefined {
  if (comps.length !== 1) return undefined;
  const c = comps[0];
  if (!isObject(c) || 'componentId' in c || c.type !== typ) return undefined;
  if (typeof c.name !== 'string' || c.name === '' || c.name !== c.osName) return undefined;
  return c;
}

/** The string entries of a legacy target.labels; component labels admit only strings. */
function stringLabels(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isObject(v)) return out;
  for (const [k, val] of Object.entries(v)) {
    if (typeof val === 'string') out[k] = val;
  }
  return out;
}

/** Add target labels to a component without overriding its own. */
function applyLabels(c: Record<string, unknown>, labels: Record<string, string>): void {
  if (Object.keys(labels).length === 0) return;
  const existing = isObject(c.labels) ? c.labels : {};
  for (const [k, v] of Object.entries(labels)) {
    if (!(k in existing)) existing[k] = v;
  }
  c.labels = existing;
}

/** Record the legacy target.boundary as a component label (the deferred
 * first-class-field decision — ADR-0015). No-op for an empty boundary. */
function applyBoundaryLabel(c: Record<string, unknown>, boundary: string): void {
  if (boundary === '') return;
  const labels = isObject(c.labels) ? c.labels : {};
  if (!('boundary' in labels)) labels.boundary = boundary;
  c.labels = labels;
}

/** The only keys `extensions` admits. Anything else a producer wrote beside them
 * is exactly what `passthrough` is for. */
const EXTENSIONS_DEFINED_MEMBERS = new Set(['passthrough', 'rawSourceArtifacts']);

/** Move the legacy top-level `passthrough` under extensions.passthrough, then
 * relocate any other key left beside it into passthrough too: `extensions` is a
 * closed object, so a sibling it does not define makes the document invalid.
 * Returns a warning per relocated or undroppable key. */
function rewritePassthrough(doc: Record<string, unknown>): string[] {
  const ext = isObject(doc.extensions) ? doc.extensions : {};
  if (!('passthrough' in ext)) ext.passthrough = doc.passthrough;
  doc.extensions = ext;
  delete doc.passthrough;
  return relocateExtensionSiblings(ext);
}

/** Move undefined `extensions` keys into extensions.passthrough. Without this, a
 * legacy document carrying something like extensions.audit normalizes into a
 * document the closed `extensions` rejects. */
function relocateExtensionSiblings(ext: Record<string, unknown>): string[] {
  const warnings: string[] = [];
  const siblings = Object.keys(ext).filter((k) => !EXTENSIONS_DEFINED_MEMBERS.has(k));
  if (siblings.length === 0) return warnings;

  if ('passthrough' in ext && !isObject(ext.passthrough)) {
    // Nothing can be merged into a non-object passthrough. Leave the document
    // alone and let the schema reject it rather than reshape data we cannot place.
    for (const k of siblings) {
      warnings.push(
        `extensions.${k} could not be relocated because extensions.passthrough is not an object; \`extensions\` is closed, so this document will not validate`,
      );
    }
    return warnings;
  }

  const pt = isObject(ext.passthrough) ? ext.passthrough : {};
  for (const k of siblings) {
    if (k in pt) {
      warnings.push(
        `extensions.${k} was dropped: \`extensions\` is closed and extensions.passthrough.${k} already holds a value`,
      );
    } else {
      pt[k] = ext[k];
      warnings.push(
        `extensions.${k} was moved into extensions.passthrough.${k}; \`extensions\` accepts only its defined members`,
      );
    }
    delete ext[k];
  }
  ext.passthrough = pt;
  return warnings;
}
