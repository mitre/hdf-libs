// Generate the HDF OSCAL extension vocabulary page (ns/oscal.md) from the
// single vocabulary table at
// hdf-converters/converters/oscal-to-hdf/go/oscal-vocabulary.json (ADR-0014
// §1.5). The page is served at the namespace URI a consumer meets in OSCAL
// output produced by hdf-libs, so it never drifts from what the exporters emit:
// the exporters, importers, tests and this page all read that one file.
//
// The output is git-ignored and rebuilt at site-build time, like the schema,
// converter and package pages. site/test/generate-oscal-vocabulary.test.mjs
// drift-guards it: a table row missing from the page fails that test.
//
// Run: node generate-oscal-vocabulary.mjs

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VOCAB_FILE = path.resolve(
  __dirname,
  '../hdf-converters/converters/oscal-to-hdf/go/oscal-vocabulary.json',
);
const OUTPUT_DIR = path.resolve(__dirname, 'ns');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'oscal.md');

export function readVocabulary() {
  return JSON.parse(fs.readFileSync(VOCAB_FILE, 'utf8'));
}

export const HDF_NAMESPACE = readVocabulary().namespace;

// Friendly labels for the third-party owners we recognise. A namespace with no
// entry still renders — its heading falls back to the URI alone — so a new owner
// is never silently dropped.
const OWNER_LABELS = {
  'https://fedramp.gov/ns/oscal': 'FedRAMP',
  'http://csrc.nist.gov/ns/oscal': 'NIST',
};

// Escape the three characters that would break a markdown table cell or be eaten
// by the HTML-aware renderer: a pipe closes the cell, and `<n>`-style group
// suffixes in the meanings would otherwise read as HTML tags.
function cell(text) {
  return String(text)
    .replace(/\|/g, '\\|')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function code(text) {
  // A code span cannot escape `<`/`>` (they render literally inside it), so only
  // the table-breaking pipe needs handling here.
  return '`' + String(text).replace(/\|/g, '\\|') + '`';
}

function objectsCell(objects) {
  return objects.map(code).join('; ');
}

function hdfFieldCell(hdfField) {
  return hdfField ? code(hdfField) : '(none)';
}

function row(prop) {
  return [
    code(prop.name),
    objectsCell(prop.objects),
    cell(prop.meaning),
    cell(prop.valueFormat),
    hdfFieldCell(prop.hdfField),
  ]
    .map((c) => ` ${c} `)
    .join('|');
}

const TABLE_HEADER = [
  '| Name | OSCAL object(s) | Meaning | Value format | HDF field |',
  '| --- | --- | --- | --- | --- |',
];

function propsTable(props) {
  return [...TABLE_HEADER, ...props.map((p) => `|${row(p)}|`)].join('\n');
}

export function renderVocabularyPage(vocab) {
  const hdfProps = vocab.props.filter((p) => p.ns === vocab.namespace);
  const thirdPartyProps = vocab.props.filter((p) => p.ns !== vocab.namespace);
  const thirdPartyNamespaces = [...new Set(thirdPartyProps.map((p) => p.ns))].sort();

  const lines = [
    '---',
    'outline: deep',
    '---',
    '',
    '# HDF OSCAL Extension Vocabulary',
    '',
    'When hdf-libs writes OSCAL (an Assessment Results / SAR or a Plan of Action',
    'and Milestones), it stamps every property it invents with a namespace, as',
    "NIST's OSCAL extension guidance directs. This page defines every such",
    'property so a consumer who meets one can look up what it means.',
    '',
    `The HDF extension namespace is \`${vocab.namespace}\`. It is an identifier`,
    'and will not change, even if the site that publishes this page moves.',
    '',
    'This page is generated from the vocabulary table that the exporters and',
    'importers themselves read, so it cannot describe a property they do not emit,',
    'or omit one they do.',
    '',
    '## HDF properties',
    '',
    `Every property below carries the namespace \`${vocab.namespace}\`.`,
    '',
    propsTable(hdfProps),
    '',
    '## Third-party properties',
    '',
    'These properties are defined by other organizations. hdf-libs emits or reads',
    "them under their owner's namespace, not the HDF namespace, and reproduces",
    'them on re-export exactly as received.',
    '',
  ];

  for (const ns of thirdPartyNamespaces) {
    const label = OWNER_LABELS[ns];
    const heading = label ? `${label} — \`${ns}\`` : `\`${ns}\``;
    lines.push(`### ${heading}`);
    lines.push('');
    lines.push(propsTable(thirdPartyProps.filter((p) => p.ns === ns)));
    lines.push('');
  }

  return lines.join('\n').replace(/\n+$/, '\n');
}

export function generateOscalVocabulary() {
  const vocab = readVocabulary();
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  fs.writeFileSync(OUTPUT_FILE, renderVocabularyPage(vocab));
  console.log(
    `Generated ${path.relative(process.cwd(), OUTPUT_FILE)} — ` +
      `${vocab.props.length} vocabulary properties.`,
  );
}

// Imported as a library by its test; only run when invoked directly. Compare
// native paths, not URLs, so the guard holds on Windows (see generate-packages).
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  generateOscalVocabulary();
}
