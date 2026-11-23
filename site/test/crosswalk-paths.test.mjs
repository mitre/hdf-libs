// Every HDF path the crosswalk cites must resolve segment by segment through the
// bundled schemas, following $refs, array items and composition. A name-existence
// check is not enough: it passes `statusOverrides[].milestones[]`, where both
// names exist but `Status_Override` has no `milestones`. The eMASS half of the
// page is verified against the specification itself.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagePath = join(here, '..', 'docs', 'guides', 'emass-crosswalk.md');
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

// The page cites a path in full, then continues with `.foo` in the same cell.
// Resolve each continuation against the last full path on its line.
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

// The no-counterpart column is HDF by construction, so it takes full resolution
// rather than the marker-only check a bare name gets elsewhere.
function noCounterpartPaths(markdown) {
  const out = [];
  let inSection = false;
  for (const line of markdown.split('\n')) {
    if (line.startsWith('## ')) inSection = /no eMASS counterpart/i.test(line);
    if (!inSection || !line.startsWith('|')) continue;
    const cell = line.split('|')[1] ?? '';
    if (/^\s*-+\s*$/.test(cell) || /^\s*HDF\s*$/.test(cell)) continue;
    // A row may name which document's root it covers; the three roots share
    // property names, so without that an unqualified token satisfies all three.
    const root = /\((results|evidence-package|amendments) root\)/.exec(line);
    const prefix = root ? `hdf-${root[1]}.` : '';
    let parent = null;
    for (const [, token] of cell.matchAll(/`([A-Za-z.][A-Za-z0-9_.[\]-]*)`/g)) {
      if (token.startsWith('.')) {
        if (parent) out.push({ cited: token, path: parent + token });
      } else {
        out.push({ cited: token, path: token, doc: root ? `hdf-${root[1]}` : null });
        if (prefix && !token.includes('.')) out.push({ cited: token, path: prefix + token });
        if (token.includes('.')) parent = token.replace(/\.[A-Za-z0-9_]+(\[\])?$/, '');
      }
    }
  }
  return out;
}

// Levels the page must cover exhaustively: every property mapped or listed.
// Declared, not inferred, so adding one is deliberate.
const EXHAUSTIVE_LEVELS = [
  ['hdf-results', []],
  ['hdf-results', ['baselines']],
  ['hdf-results', ['baselines', 'requirements']],
  ['hdf-results', ['baselines', 'requirements', 'results']],
  ['hdf-results', ['baselines', 'requirements', 'poams']],
  ['hdf-evidence-package', []],
  ['hdf-evidence-package', ['externalEvidence']],
  ['hdf-evidence-package', ['externalEvidence', 'metadata']],
  ['hdf-evidence-package', ['contents']],
  ['hdf-amendments', []],
  ['hdf-amendments', ['overrides']],
  ['hdf-amendments', ['overrides', 'milestones']],
  ['hdf-amendments', ['overrides', 'cvss']],
];

// Walk to a level and return its property names, expanding composition.
function propertiesAt(doc, segments) {
  let node = deref(docs[doc], docs[doc]);
  for (const segment of segments) {
    const candidates = [];
    const collect = (n, depth) => {
      const here = deref(n, docs[doc]);
      if (!here || typeof here !== 'object' || depth > 8) return;
      const unwrapped = here.type === 'array' && here.items ? deref(here.items, docs[doc]) : here;
      if (!unwrapped || typeof unwrapped !== 'object') return;
      candidates.push(unwrapped);
      for (const kw of ['allOf', 'anyOf', 'oneOf']) (unwrapped[kw] ?? []).forEach((c) => collect(c, depth + 1));
    };
    collect(node, 0);
    const next = candidates.map((c) => c.properties?.[segment]).find(Boolean);
    if (!next) return null;
    node = next;
  }
  const names = new Set();
  const gather = (n, depth) => {
    const here = deref(n, docs[doc]);
    if (!here || typeof here !== 'object' || depth > 8) return;
    const unwrapped = here.type === 'array' && here.items ? deref(here.items, docs[doc]) : here;
    if (!unwrapped || typeof unwrapped !== 'object') return;
    Object.keys(unwrapped.properties ?? {}).forEach((k) => names.add(k));
    for (const kw of ['allOf', 'anyOf', 'oneOf']) (unwrapped[kw] ?? []).forEach((c) => gather(c, depth + 1));
  };
  gather(node, 0);
  return names;
}

// Property names and enum values, for tokens that cannot resolve from a root.
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

// Array-ness per name, for the [] marker on a name cited alone. An unknown name
// is skipped: the page also cites enum values and eMASS fields in backticks.
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

const { paths, bare } = citedPaths(readFileSync(pagePath, 'utf-8'));
const arrays = arrayness();
const noCounterpart = noCounterpartPaths(readFileSync(pagePath, 'utf-8'));
const vocab = vocabulary();

test('the crosswalk cites enough HDF paths for the check to mean something', () => {
  assert.ok(paths.length > 12, `only ${paths.length} HDF paths cited`);
});

test('every property at a level the page covers exhaustively is accounted for', () => {
  const strip = (path) => path.replace(/\[\]/g, '');

  // Terminal citations and the parents the page descends through, kept apart:
  // a parent is accounted for by the rows beneath it, a terminal only by itself.
  const terminal = new Set();
  const descended = new Set();
  for (const { path } of [...paths, ...noCounterpart]) {
    const segments = strip(path).split('.');
    terminal.add(segments.join('.'));
    for (let i = 1; i < segments.length; i += 1) descended.add(segments.slice(0, i).join('.'));
  }

  // The three document roots share property names, so a row naming one root
  // counts only for that document; an unlabeled row counts for any.
  const rootAny = new Set();
  const rootByDoc = new Map();
  for (const { path, doc } of noCounterpart) {
    if (path.includes('.')) continue;
    const name = strip(path);
    if (!doc) rootAny.add(name);
    else rootByDoc.set(doc, (rootByDoc.get(doc) ?? new Set()).add(name));
  }

  const missing = [];
  for (const [doc, segments] of EXHAUSTIVE_LEVELS) {
    const names = propertiesAt(doc, segments);
    assert.ok(names && names.size > 0, `level ${doc}.${segments.join('.')} resolved to nothing — the level list is stale`);
    for (const name of names) {
      const full = [...segments, name].join('.');
      const ok = segments.length === 0
        ? rootAny.has(name) || rootByDoc.get(doc)?.has(name) || descended.has(name)
        : terminal.has(full) || descended.has(full);
      if (!ok) missing.push(`${doc}.${full}`);
    }
  }
  assert.deepEqual(missing, [], `HDF properties neither mapped nor listed at their level: ${missing.join(', ')}`);
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

test('the no-counterpart tables were actually found', () => {
  // Scoped by heading text, so a docs tidy-up could silently empty it and leave
  // the check below passing over nothing.
  assert.ok(noCounterpart.length > 50, `only ${noCounterpart.length} tokens found — has the heading changed?`);
});

test('every field in the no-counterpart tables is a real HDF property', () => {
  const unresolved = noCounterpart
    .filter(({ path }) => {
      const segments = path.replace(/^hdf-(system|results|amendments|evidence-package|plan)\./, '').split('.').filter(Boolean);
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
        .replace(/^hdf-(system|results|amendments|evidence-package)\./, '')
        .split('.')
        .filter(Boolean);
      return !DOCUMENTS.some((name) => resolves(segments, docs[name]));
    })
    .map(({ cited, path }) => (cited === path ? cited : `${cited} (as ${path})`));
  assert.deepEqual(unresolved, [], `cited paths that resolve in no HDF document: ${unresolved.join(', ')}`);
});
