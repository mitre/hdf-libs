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
 * components[] entry (type validated; id → name and, for cloudAccount, accountId;
 * boundary → labels.boundary; merged into a matching existing component rather
 * than duplicated); `passthrough` → extensions.passthrough.
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
    rewritePassthrough(doc);
    warnings.push(SAF_PROVENANCE_DEPRECATION);
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
  const id = typeof tgt.id === 'string' ? tgt.id : '';
  const boundary = typeof tgt.boundary === 'string' ? tgt.boundary : '';

  const comps: unknown[] = Array.isArray(doc.components) ? doc.components : [];

  let merged = false;
  for (const c of comps) {
    if (isObject(c) && c.name === id && c.type === typ) {
      applyBoundaryLabel(c, boundary);
      merged = true;
      break;
    }
  }
  if (!merged) {
    const c: Record<string, unknown> = { type: typ, name: id };
    if (typ === 'cloudAccount') c.accountId = id;
    applyBoundaryLabel(c, boundary);
    comps.push(c);
  }
  doc.components = comps;
  delete doc.target;
  return true;
}

/** Record the legacy target.boundary as a component label (the deferred
 * first-class-field decision — ADR-0015). No-op for an empty boundary. */
function applyBoundaryLabel(c: Record<string, unknown>, boundary: string): void {
  if (boundary === '') return;
  const labels = isObject(c.labels) ? c.labels : {};
  if (!('boundary' in labels)) labels.boundary = boundary;
  c.labels = labels;
}

/** Move the legacy top-level `passthrough` under extensions.passthrough, merging
 * into any existing extensions without clobbering other keys. */
function rewritePassthrough(doc: Record<string, unknown>): void {
  const ext = isObject(doc.extensions) ? doc.extensions : {};
  if (!('passthrough' in ext)) ext.passthrough = doc.passthrough;
  doc.extensions = ext;
  delete doc.passthrough;
}
