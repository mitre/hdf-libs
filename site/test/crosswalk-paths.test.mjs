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
const OPEN_MAPS = new Set(['tags', 'externalIds', 'labels', 'passthrough']);

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
    const bare = segment.replace(/\[\]$/, '');
    const next = candidates.map((n) => n.properties?.[bare]).find(Boolean);
    if (!next) return false;

    // A cited array must carry [] and a non-array must not, so the page cannot
    // quietly drop a marker and still pass.
    const resolved = deref(next, root);
    const isArray = resolved?.type === 'array';
    if (isArray !== segment.endsWith('[]')) return false;

    if (OPEN_MAPS.has(bare)) return true;
    node = next;
  }
  return true;
}

// The page cites a path in full once, then continues with `.foo` shorthand in
// the same cell. Those continuations were invisible to an earlier version of
// this check, which left 17 of the cited paths unverified — in exactly the rows
// the review's errors lived in. Resolve each against the last full path on its
// line, so the shorthand is checked as the reader would read it.
function citedPaths(markdown) {
  const out = [];
  const bare = [];
  for (const line of markdown.split('\n')) {
    let parent = null;
    for (const [, token] of line.matchAll(/`([A-Za-z.][A-Za-z0-9_.[\]-]*)`/g)) {
      // A JSON Schema location inside the eMASS spec, which is lowercase and
      // dotted like an HDF path. Matched narrowly: `required` on its own is a
      // real HDF property (Input.required, at baselines[].inputs[].required),
      // so only the nested-location forms are excluded.
      if (/(^|\.)(properties|items|allOf)\./.test(token)) continue;
      if (/^[a-z]/.test(token) && token.includes('.')) {
        out.push({ cited: token, path: token });
        parent = token.replace(/\.[A-Za-z0-9_]+(\[\])?$/, '');
      } else if (/^[a-z][A-Za-z0-9_]*(\[\])?$/.test(token)) {
        bare.push(token);
      } else if (token.startsWith('.') && parent) {
        out.push({ cited: token, path: parent + token });
      }
    }
  }
  return { paths: out, bare };
}

// Every HDF property name and whether it is an array, for checking the [] marker
// on a name cited on its own. A bare name that is not an HDF property at all is
// skipped rather than failed: the page also cites enum values, eMASS field names
// and ordinary prose in backticks, and nothing distinguishes those by shape. So
// this catches a dropped or spurious marker, not an invented bare name.
// The no-counterpart tables' first column is HDF by construction — every
// backticked token in it names an HDF property — so those can take full
// resolution rather than the marker-only check a bare name gets elsewhere.
// This is where the review found a live defect (externalReferences cited
// without its []), and where most bare names on the page live.
function noCounterpartPaths(markdown) {
  const out = [];
  let inSection = false;
  for (const line of markdown.split('\n')) {
    if (line.startsWith('## ')) inSection = /no eMASS counterpart/i.test(line);
    if (!inSection || !line.startsWith('|')) continue;
    const cell = line.split('|')[1] ?? '';
    if (/^\s*-+\s*$/.test(cell) || /^\s*HDF\s*$/.test(cell)) continue;
    let parent = null;
    for (const [, token] of cell.matchAll(/`([A-Za-z.][A-Za-z0-9_.[\]-]*)`/g)) {
      if (token.startsWith('.')) {
        if (parent) out.push({ cited: token, path: parent + token });
      } else {
        out.push({ cited: token, path: token });
        if (token.includes('.')) parent = token.replace(/\.[A-Za-z0-9_]+(\[\])?$/, '');
      }
    }
  }
  return out;
}

// Every property name and every enum value in the schemas. The no-counterpart
// column mixes full paths, sub-property names in parentheses and enum values,
// and nothing distinguishes those by shape — but a token that is none of the
// three is an invented name, which is what the check is for.
function vocabulary() {
  const names = new Set();
  const values = new Set();
  for (const root of Object.values(docs)) {
    const walk = (node, depth) => {
      if (!node || typeof node !== 'object' || depth > 16) return;
      Object.keys(node.properties ?? {}).forEach((n) => names.add(n));
      (node.enum ?? []).forEach((v) => typeof v === 'string' && values.add(v));
      for (const [key, value] of Object.entries(node)) {
        if (key === 'examples') continue;
        if (Array.isArray(value)) value.forEach((v) => walk(v, depth + 1));
        else if (value && typeof value === 'object') walk(value, depth + 1);
      }
    };
    walk(root, 0);
  }
  return { names, values };
}

function arrayness() {
  const seen = new Map();
  for (const root of Object.values(docs)) {
    const walk = (node, depth) => {
      if (!node || typeof node !== 'object' || depth > 14) return;
      for (const [name, child] of Object.entries(node.properties ?? {})) {
        const resolved = deref(child, root);
        const isArray = resolved?.type === 'array';
        if (seen.has(name) && seen.get(name) !== isArray) seen.set(name, null);
        else if (!seen.has(name)) seen.set(name, isArray);
      }
      for (const value of Object.values(node)) {
        if (Array.isArray(value)) value.forEach((v) => walk(deref(v, root), depth + 1));
        else if (value && typeof value === 'object') walk(deref(value, root), depth + 1);
      }
    };
    walk(root, 0);
  }
  return seen;
}

const { paths, bare } = citedPaths(readFileSync(page, 'utf-8'));
const arrays = arrayness();
const noCounterpart = noCounterpartPaths(readFileSync(page, 'utf-8'));
const vocab = vocabulary();

test('the crosswalk cites enough HDF paths for the check to mean something', () => {
  assert.ok(paths.length > 12, `only ${paths.length} HDF paths cited`);
});

test('an HDF property cited on its own carries the right array marker', () => {
  const wrong = bare.filter((token) => {
    const name = token.replace(/\[\]$/, '');
    const isArray = arrays.get(name);
    if (isArray === undefined || isArray === null) return false;
    return isArray !== token.endsWith('[]');
  });
  assert.deepEqual(wrong, [], `cited with the wrong array marker: ${wrong.join(', ')}`);
});

test('every field in the no-counterpart tables is a real HDF property', () => {
  const unresolved = noCounterpart
    .filter(({ path }) => {
      const segments = path.replace(/^hdf-(system|results|amendments|plan)\./, '').split('.').filter(Boolean);
      if (DOCUMENTS.some((name) => resolves(segments, docs[name]))) return false;
      // A single token may be a sub-property named in parentheses or an enum
      // value, neither of which resolves from a document root.
      // The escape is for existence only: a token carrying [] has made a claim
      // about its type, so it must resolve rather than be forgiven here.
      if (path.endsWith('[]')) return true;
      return !(segments.length === 1 && (vocab.names.has(path) || vocab.values.has(path)));
    })
    .map(({ cited, path }) => (cited === path ? cited : `${cited} (as ${path})`));
  assert.deepEqual(unresolved, [], `not HDF properties: ${unresolved.join(', ')}`);
});

test('every HDF path the crosswalk cites resolves through a bundled schema', () => {
  const unresolved = paths
    .filter(({ path }) => {
      const segments = path
        .replace(/^hdf-(system|results|amendments)\./, '')
        .split('.')
        .filter(Boolean);
      return !DOCUMENTS.some((name) => resolves(segments, docs[name]));
    })
    .map(({ cited, path }) => (cited === path ? cited : `${cited} (as ${path})`));
  assert.deepEqual(unresolved, [], `cited paths that resolve in no HDF document: ${unresolved.join(', ')}`);
});
