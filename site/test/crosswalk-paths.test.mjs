// Every HDF property path the eMASS crosswalk cites must actually resolve,
// segment by segment, through the bundled schemas — following $refs and array
// items rather than merely checking that each name exists somewhere.
//
// The page's first review failed on four cited paths. The worst was
// `statusOverrides[].milestones[]`: `statusOverrides` is a real hdf-results
// property, and `milestones` is a real property elsewhere, so a name-existence
// check passes it — yet `Status_Override` has no `milestones`, so the path is
// nothing. Only real resolution catches that, which is why this walks the tree.
// The eMASS half of the page is verified against the specification itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const page = join(here, '..', 'docs', 'guides', 'emass-crosswalk.md');
// hdf-validators/go/schemas holds the committed copy of the bundles that
// hdf-schema's build:schemas syncs on every build, byte-identical to
// hdf-schema/dist/schemas. Read it rather than dist, because `pnpm check`
// rebuilds dist and the site tests can run while it is absent.
const schemaDir = join(here, '..', '..', 'hdf-validators', 'go', 'schemas');

// A path may belong to any of these documents; resolving against any one is enough.
const DOCUMENTS = ['hdf-results', 'hdf-amendments', 'hdf-evidence-package', 'hdf-system'];

// Keys are data, not schema: a consumer puts arbitrary names in them, so
// resolution stops here and anything past it is unverifiable by construction.
const OPEN_MAPS = new Set(['tags', 'externalIds', 'labels', 'metadata', 'passthrough']);

const docs = Object.fromEntries(
  DOCUMENTS.map((name) => [name, JSON.parse(readFileSync(join(schemaDir, `${name}.schema.json`), 'utf-8'))]),
);

// Bundled schemas are self-contained, so every $ref resolves inside its own
// document — either `#/$defs/X` or a URL whose fragment points at one.
function deref(node, root, seen = 0) {
  if (!node || typeof node !== 'object' || !node.$ref || seen > 20) return node;
  const hash = node.$ref.indexOf('#');
  const base = hash === -1 ? node.$ref : node.$ref.slice(0, hash);
  const fragment = hash === -1 ? '' : node.$ref.slice(hash + 1);

  // The bundler keys each embedded document by its schema URL under $defs, so a
  // ref with a base resolves inside that entry rather than from the root.
  const walk = (from) => {
    let target = from;
    for (const part of fragment.split('/').filter(Boolean)) {
      const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
      target = target?.[key];
      if (target === undefined) return undefined;
    }
    return target;
  };

  let target = base && root.$defs?.[base] ? walk(root.$defs[base]) : walk(root);

  // A fragment-only ref inside an embedded document re-bases to that document's
  // own $id, not the outer root. Rather than implement $id scoping, search the
  // embedded documents for the target. Safe here because the bundler emits one
  // definition per name; it would be wrong for a bundle with colliding names.
  if (target === undefined && !base) {
    for (const embedded of Object.values(root.$defs ?? {})) {
      if (!embedded || typeof embedded !== 'object') continue;
      const found = walk(embedded);
      if (found !== undefined) { target = found; break; }
    }
  }

  return target === undefined ? undefined : deref(target, root, seen + 1);
}

// True when every segment resolves as a property, following refs, `items` for
// arrays, and the composition keywords the schemas use.
function resolves(segments, root) {
  let node = deref(root, root);
  for (const segment of segments) {
    node = deref(node, root);
    if (!node || typeof node !== 'object') return false;

    while (node.type === 'array' && node.items) node = deref(node.items, root);

    // Composition nests: a polymorphic array's members each compose a shared
    // base, so a one-level expansion misses properties defined on that base.
    const expand = (n, depth = 0) => {
      const here = deref(n, root);
      if (!here || typeof here !== 'object' || depth > 6) return [];
      const unwrapped = here.type === 'array' && here.items ? deref(here.items, root) : here;
      if (!unwrapped || typeof unwrapped !== 'object') return [];
      return [
        unwrapped,
        ...[...(unwrapped.allOf ?? []), ...(unwrapped.anyOf ?? []), ...(unwrapped.oneOf ?? [])]
          .flatMap((child) => expand(child, depth + 1)),
      ];
    };

    const candidates = expand(node);
    const next = candidates.map((n) => n.properties?.[segment]).find(Boolean);
    if (!next) return false;
    if (OPEN_MAPS.has(segment)) return true;
    node = next;
  }
  return true;
}

function citedPaths(markdown) {
  const out = new Set();
  for (const [, token] of markdown.matchAll(/`([A-Za-z][A-Za-z0-9_.[\]]*)`/g)) {
    // eMASS schema names are PascalCase; HDF roots are not.
    if (/^[a-z]/.test(token) && (token.includes('.') || token.includes('[]'))) out.add(token);
  }
  return [...out];
}

const paths = citedPaths(readFileSync(page, 'utf-8'));

test('the crosswalk cites enough HDF paths for the check to mean something', () => {
  assert.ok(paths.length > 12, `only ${paths.length} HDF paths cited`);
});

test('every HDF path the crosswalk cites resolves through a bundled schema', () => {
  const unresolved = paths.filter((path) => {
    const segments = path
      .replace(/^hdf-(system|results|amendments)\./, '')
      .split('.')
      .map((s) => s.replace(/\[\]$/, ''))
      .filter(Boolean);
    return !DOCUMENTS.some((name) => resolves(segments, docs[name]));
  });
  assert.deepEqual(unresolved, [], `cited paths that resolve in no HDF document: ${unresolved.join(', ')}`);
});
