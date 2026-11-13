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

export interface SafNormalizeOptions {
  /** Let the target absorb the lone component the caller built from an InSpec
   * `platform` (no componentId, OS name standing in as the name). Only that
   * caller knows where the component came from; on a plain parse the same shape
   * is a genuine component and is never renamed. */
  mergePlatformComponent?: boolean;
}

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
 * SAF-produced document is valid v3 before schema validation: `target` → a
 * components[] entry (type validated; id, or failing that name, → name; id alone →
 * accountId for cloudAccount; labels and boundary → labels, boundary winning;
 * merged into a same-name component rather than duplicated, and only with
 * `mergePlatformComponent` into the platform-derived one); `passthrough` →
 * extensions.passthrough. Deliberately narrow: input that is not a JSON object,
 * or carries neither legacy key, is returned BYTE-IDENTICAL with no warnings. A
 * target of unmapped type is left in place, with a warning, for the schema to reject.
 */
export function normalizeSafSupplement(input: string, options: SafNormalizeOptions = {}): SafNormalizeResult {
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
    const reason = rewriteTarget(doc, options.mergePlatformComponent === true);
    if (reason === null) {
      warnings.push(SAF_TARGET_DEPRECATION);
    } else {
      warnings.push(`${SAF_TARGET_DEPRECATION} (${reason}; left for schema validation)`);
    }
  }

  if ('passthrough' in doc) {
    const relocations = rewritePassthrough(doc);
    warnings.push(SAF_PROVENANCE_DEPRECATION, ...relocations);
  }

  return { output: JSON.stringify(doc), warnings };
}

const UNMAPPED_TYPE = 'target.type is not a recognized component type';

/** Lift a legacy top-level `target` object into components[]. Returns a reason,
 * leaving `target` in place, when it cannot be placed: not an object, a type
 * that is not a component type, or no identity and no component to take it.
 * mergePlatform lets the component the v2 upgrade derived from `platform` take
 * it, renaming that component. */
function rewriteTarget(doc: Record<string, unknown>, mergePlatform: boolean): string | null {
  const tgt = doc.target;
  if (!isObject(tgt)) return UNMAPPED_TYPE;
  const typ = typeof tgt.type === 'string' ? tgt.type : '';
  if (!VALID_COMPONENT_TYPES.has(typ)) return UNMAPPED_TYPE;
  // SAF writes `id`; the classic Heimdall/InSpec target carries `name` instead.
  // Only an `id` is a provider identifier; a display name never becomes one.
  const id = typeof tgt.id === 'string' ? tgt.id : '';
  const name = id !== '' ? id : typeof tgt.name === 'string' ? tgt.name : '';
  const labels = stringLabels(tgt.labels);
  // The first-class boundary field is the SAF carrier, so it wins over a
  // `labels.boundary` entry (the deferred first-class-field decision — ADR-0015).
  if (typeof tgt.boundary === 'string' && tgt.boundary !== '') labels.boundary = tgt.boundary;

  const comps: unknown[] = Array.isArray(doc.components) ? doc.components : [];

  let c = findComponent(comps, name, typ);
  if (!c && mergePlatform) {
    c = platformComponent(comps, typ);
    if (c && name !== '') c.name = name;
  }
  if (!c && name === '') return 'target carries no id or name and matches no component';
  if (!c) {
    c = { type: typ, name };
    if (typ === 'cloudAccount' && id !== '') c.accountId = id;
    comps.push(c);
  }
  applyLabels(c, labels);
  doc.components = comps;
  delete doc.target;
  return null;
}

/** An empty name is no identity and matches nothing, so a component that lacks
 * a name is never joined to a target that lacks one too. */
function findComponent(comps: unknown[], name: string, typ: string): Record<string, unknown> | undefined {
  if (name === '') return undefined;
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

/** Own-property test: `in` walks the prototype chain, so a key named like an
 * Object.prototype member would read as present on an empty object. */
function hasOwn(o: Record<string, unknown>, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

/** Define an own data property, so a key named `__proto__` lands as data and
 * never reassigns the object's prototype. */
function setOwn(o: Record<string, unknown>, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/** The string entries of a legacy target.labels; component labels admit only strings. */
function stringLabels(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isObject(v)) return out;
  for (const [k, val] of Object.entries(v)) {
    if (typeof val === 'string') setOwn(out, k, val);
  }
  return out;
}

/** Add target labels to a component without overriding its own. */
function applyLabels(c: Record<string, unknown>, labels: Record<string, string>): void {
  if (Object.keys(labels).length === 0) return;
  const existing = isObject(c.labels) ? c.labels : {};
  for (const [k, v] of Object.entries(labels)) {
    if (!hasOwn(existing, k)) setOwn(existing, k, v);
  }
  c.labels = existing;
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
    if (hasOwn(pt, k)) {
      warnings.push(
        `extensions.${k} was dropped: \`extensions\` is closed and extensions.passthrough.${k} already holds a value`,
      );
    } else {
      setOwn(pt, k, ext[k]);
      warnings.push(
        `extensions.${k} was moved into extensions.passthrough.${k}; \`extensions\` accepts only its defined members`,
      );
    }
    delete ext[k];
  }
  ext.passthrough = pt;
  return warnings;
}
