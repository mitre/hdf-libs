import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateOscalVocabulary,
  readVocabulary,
  HDF_NAMESPACE,
} from '../generate-oscal-vocabulary.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PAGE = path.resolve(__dirname, '../ns/oscal.md');

// The page is git-ignored and produced by `pnpm generate`. Generate it here into
// an emptied directory rather than reading whatever a previous local run left
// behind: without this the suite fails in CI (nothing has generated yet) and
// passes locally for the wrong reason. Emptying first means a row this run fails
// to produce cannot be stood in for by a stale page.
test('generate the vocabulary page', () => {
  fs.rmSync(path.dirname(PAGE), { recursive: true, force: true });
  generateOscalVocabulary();
  assert.ok(fs.existsSync(PAGE), 'the run must write ns/oscal.md');
});

function page() {
  return fs.readFileSync(PAGE, 'utf8');
}

// A row is `| \`name\` | ...`; the name is always the first cell. Presence of
// this exact prefix is the row-existence guarantee the drift guard rests on.
function rowMarker(name) {
  return `| \`${name}\` |`;
}

// The vocabulary table is the single source (ADR-0014 §1.5). The expected set is
// read from it, never restated here — a hand-kept list would agree with itself
// while a real row went unrendered.
const vocab = readVocabulary();
const hdfProps = vocab.props.filter((p) => p.ns === HDF_NAMESPACE);
const thirdPartyProps = vocab.props.filter((p) => p.ns !== HDF_NAMESPACE);
const thirdPartyNamespaces = [...new Set(thirdPartyProps.map((p) => p.ns))];

test('the vocabulary table carries both HDF and third-party rows', () => {
  assert.ok(hdfProps.length > 0, 'no HDF props in the vocabulary table');
  assert.ok(thirdPartyProps.length > 0, 'no third-party props in the vocabulary table');
});

// The HDF section is everything before the third-party section; the third-party
// section is the remainder. Slicing on the h2 headings lets each row be checked
// against the namespace it must sit under.
function hdfSection() {
  const p = page();
  const idx = p.indexOf('## Third-party properties');
  assert.notEqual(idx, -1, 'the page must have a Third-party properties section');
  return p.slice(0, idx);
}

function thirdPartySectionFor(ns) {
  const p = page();
  const tp = p.slice(p.indexOf('## Third-party properties'));
  const marker = '`' + ns + '`';
  const at = tp.indexOf(marker);
  assert.notEqual(at, -1, `no third-party heading names the namespace ${ns}`);
  const headStart = tp.lastIndexOf('### ', at);
  const next = tp.indexOf('### ', at + marker.length);
  return tp.slice(headStart === -1 ? 0 : headStart, next === -1 ? tp.length : next);
}

test('every HDF prop appears under the HDF namespace', () => {
  const section = hdfSection();
  assert.ok(
    section.includes(HDF_NAMESPACE),
    'the HDF section must declare the HDF namespace URI',
  );
  for (const prop of hdfProps) {
    assert.ok(
      section.includes(rowMarker(prop.name)),
      `HDF prop ${prop.name} is missing from the HDF section`,
    );
  }
});

test('every third-party prop appears under its owner namespace', () => {
  for (const ns of thirdPartyNamespaces) {
    const section = thirdPartySectionFor(ns);
    for (const prop of thirdPartyProps.filter((p) => p.ns === ns)) {
      assert.ok(
        section.includes(rowMarker(prop.name)),
        `third-party prop ${prop.name} is missing from the ${ns} section`,
      );
    }
  }
});

// Drift both ways: a row dropped from the page (missing marker, caught above)
// AND an extra row the table does not have. Counting rendered rows against the
// table size catches the second.
test('the page renders exactly one row per vocabulary prop', () => {
  const rows = page().match(/^\| `[^`]+` \|/gm) ?? [];
  assert.equal(
    rows.length,
    vocab.props.length,
    'the number of rendered rows must equal the number of vocabulary props',
  );
});

test('the page states the namespace URI is a stable identifier', () => {
  const p = page();
  assert.ok(p.includes(HDF_NAMESPACE), 'the page must name the namespace URI');
  assert.match(
    p,
    /will not change/,
    'the page must state the namespace URI will not change',
  );
});

test('the page carries no emoji (site convention)', () => {
  assert.doesNotMatch(
    page(),
    /\p{Extended_Pictographic}/u,
    'the vocabulary page must contain no emoji',
  );
});
