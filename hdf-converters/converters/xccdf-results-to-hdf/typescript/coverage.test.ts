import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { parseXml } from '@mitre/hdf-utilities';
import { Severity } from '@mitre/hdf-schema';
import type { HDFBaseline } from '@mitre/hdf-schema';
import { convertXccdfBenchmarkToHdf } from './converter.js';

// Completeness of the benchmark path against the XCCDF schemas: every element
// and attribute path the 1.1.4 and 1.2 XSDs admit under Benchmark, Group and
// Rule is mapped to a Baseline field or skipped with a reason in
// fixtures/xccdf-coverage.json, which the Go suite reads too. The walker reads
// the XSDs as plain XML; the allowlist's schemaPaths digest pins its output.

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = join(__dirname, '..', '..', 'hdf-to-xccdf', 'schemas');
const ALLOWLIST_PATH = join(__dirname, '..', 'fixtures', 'xccdf-coverage.json');

const XML_SCHEMA_NS = 'http://www.w3.org/2001/XMLSchema';

// Walked as their own path roots; a reference to one from a parent records
// the element path and does not descend.
const XCCDF_COVERAGE_ROOTS = ['Benchmark', 'Group', 'Rule'];

// Facets carry no element or attribute paths, so a restriction's facets are
// passed over; every other schema construct the walker does not model is
// reported, so a construct outside its rules fails the test instead of
// silently dropping paths.
const XSD_IGNORED_CONSTRUCTS = new Set([
  'annotation', 'enumeration', 'pattern', 'length', 'minLength', 'maxLength',
  'minInclusive', 'maxInclusive', 'minExclusive', 'maxExclusive', 'totalDigits',
  'fractionDigits', 'whiteSpace',
]);

type XsdNode = Record<string, unknown>;

function attr(node: XsdNode, name: string): string {
  const value = node[name];
  return typeof value === 'string' ? value : '';
}

function byteOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

class XsdWalker {
  private targetNS = '';
  private readonly nsByPrefix = new Map<string, string>();
  private readonly complexTypes = new Map<string, XsdNode>();
  private readonly simpleTypes = new Set<string>();
  private readonly elements = new Map<string, XsdNode>();
  private readonly roots: Set<string>;
  readonly paths = new Set<string>();
  readonly unsupported: string[] = [];

  constructor(schema: XsdNode, roots: string[]) {
    this.roots = new Set(roots);
    for (const [key, value] of Object.entries(schema)) {
      if (typeof value !== 'string') {
        continue;
      }
      if (key.startsWith('xmlns:')) {
        this.nsByPrefix.set(key.slice('xmlns:'.length), value);
      } else if (key === 'xmlns') {
        this.nsByPrefix.set('', value);
      } else if (key === 'targetNamespace') {
        this.targetNS = value;
      }
    }
    for (const [local, child] of this.schemaChildren(schema)) {
      if (local === 'complexType') {
        this.complexTypes.set(attr(child, 'name'), child);
      } else if (local === 'simpleType') {
        this.simpleTypes.add(attr(child, 'name'));
      } else if (local === 'element') {
        this.elements.set(attr(child, 'name'), child);
      }
    }
  }

  // Children in the XML Schema namespace as [local name, node] pairs. The
  // parser keeps prefixes so the namespace is resolved, as Go's decoder does.
  private *schemaChildren(node: XsdNode): Generator<[string, XsdNode]> {
    for (const [key, value] of Object.entries(node)) {
      const colon = key.indexOf(':');
      if (colon < 0 || this.nsByPrefix.get(key.slice(0, colon)) !== XML_SCHEMA_NS) {
        continue;
      }
      const local = key.slice(colon + 1);
      for (const child of Array.isArray(value) ? value : [value]) {
        if (typeof child === 'object' && child !== null) {
          yield [local, child as XsdNode];
        }
      }
    }
  }

  // Splits a qualified reference into its local name and whether it names
  // something in this schema's own namespace (as opposed to a built-in XML
  // Schema type or an imported namespace).
  private resolve(qname: string): { local: string; own: boolean } {
    const colon = qname.indexOf(':');
    if (colon < 0) {
      return { local: qname, own: this.nsByPrefix.get('') === this.targetNS };
    }
    return {
      local: qname.slice(colon + 1),
      own: this.nsByPrefix.get(qname.slice(0, colon)) === this.targetNS,
    };
  }

  walkRoot(name: string): void {
    const el = this.elements.get(name);
    if (!el) {
      this.unsupported.push(`no global element named ${name}`);
      return;
    }
    this.walkElementContent(el, name, new Set());
  }

  private walkElementContent(el: XsdNode, path: string, stack: Set<string>): void {
    const typeName = attr(el, 'type');
    if (typeName) {
      this.walkNamedType(typeName, path, stack);
      return;
    }
    for (const [local, child] of this.schemaChildren(el)) {
      if (local === 'complexType') {
        this.walkType(child, path, stack);
      }
    }
  }

  // Follows a type reference. Built-in and imported types carry no paths of
  // this schema; a type already on the stack is the complex-check recursion,
  // whose element path is recorded and whose content repeats its parent's,
  // so descent stops there.
  private walkNamedType(qname: string, path: string, stack: Set<string>): void {
    const { local, own } = this.resolve(qname);
    if (!own) {
      return;
    }
    const t = this.complexTypes.get(local);
    if (!t) {
      if (!this.simpleTypes.has(local)) {
        this.unsupported.push(`unresolved type ${qname} at ${path}`);
      }
      return;
    }
    if (stack.has(local)) {
      return;
    }
    stack.add(local);
    this.walkType(t, path, stack);
    stack.delete(local);
  }

  private walkType(t: XsdNode, path: string, stack: Set<string>): void {
    for (const [local, child] of this.schemaChildren(t)) {
      switch (local) {
        case 'sequence':
        case 'choice':
        case 'all':
        case 'complexContent':
        case 'simpleContent':
          this.walkType(child, path, stack);
          break;
        case 'extension':
        case 'restriction': {
          const base = attr(child, 'base');
          if (base) {
            this.walkNamedType(base, path, stack);
          }
          this.walkType(child, path, stack);
          break;
        }
        case 'attribute': {
          const name = attr(child, 'name') || this.resolve(attr(child, 'ref')).local;
          this.paths.add(`${path}/@${name}`);
          break;
        }
        case 'anyAttribute':
          this.paths.add(`${path}/@*`);
          break;
        case 'any':
          this.paths.add(`${path}/*`);
          break;
        case 'element':
          this.walkElement(child, path, stack);
          break;
        default:
          if (!XSD_IGNORED_CONSTRUCTS.has(local)) {
            this.unsupported.push(`xsd:${local} at ${path}`);
          }
      }
    }
  }

  private walkElement(el: XsdNode, path: string, stack: Set<string>): void {
    let name = attr(el, 'name');
    let target: XsdNode | undefined = el;
    const ref = attr(el, 'ref');
    if (ref) {
      const { local, own } = this.resolve(ref);
      name = local;
      target = undefined;
      if (own) {
        target = this.elements.get(local);
        if (!target) {
          this.unsupported.push(`unresolved element ref ${ref} at ${path}`);
        }
      }
    }
    const p = `${path}/${name}`;
    this.paths.add(p);
    if (!target || this.roots.has(name)) {
      return;
    }
    this.walkElementContent(target, p, stack);
  }
}

function parseXsd(name: string): XsdNode {
  const parsed = parseXml(readFileSync(join(SCHEMAS_DIR, name), 'utf-8'), {
    removeNSPrefix: false,
    isArray: (tagName, _jPath, _isLeaf, isAttribute) => !isAttribute && tagName.includes(':'),
  });
  for (const [key, value] of Object.entries(parsed)) {
    // The isArray rule above wraps the root element too.
    const root = Array.isArray(value) ? value[0] : value;
    if ((key === 'schema' || key.endsWith(':schema')) && typeof root === 'object' && root !== null) {
      return root as XsdNode;
    }
  }
  throw new Error(`${name}: no schema root element`);
}

// The sorted union of the paths both schemas admit under the coverage roots.
function walkXccdfSchemas(): string[] {
  const union = new Set<string>();
  for (const name of ['xccdf-1.1.4.xsd', 'xccdf_1.2.xsd']) {
    const walker = new XsdWalker(parseXsd(name), XCCDF_COVERAGE_ROOTS);
    for (const root of XCCDF_COVERAGE_ROOTS) {
      walker.walkRoot(root);
    }
    if (walker.unsupported.length > 0) {
      throw new Error(`${name} uses a construct the walker does not resolve: ${walker.unsupported.join('; ')}`);
    }
    for (const p of walker.paths) {
      union.add(p);
    }
  }
  return [...union].sort(byteOrder);
}

interface CoverageRow {
  target: string[];
  reason?: string;
  fixture?: string;
}

// Pins the walker's whole output, so the Go and TypeScript walkers cannot
// drift apart inside a subtree row: the path count and the SHA-256 of the
// sorted paths joined by newlines.
interface CoverageSchemaPaths {
  count: number;
  sha256: string;
}

// fixtures/xccdf-coverage.json: paths keyed in the walker's output form (a
// key ending in /** covers the paths below it), and vendor rows for content the
// schemas leave opaque, keyed by a schema path extended with the vendor's own
// elements or a [@attr=value] selector.
interface CoverageAllowlist {
  schemaPaths?: CoverageSchemaPaths;
  paths: Record<string, CoverageRow>;
  vendor: Record<string, CoverageRow>;
}

function schemaPathsDigest(paths: string[]): string {
  return createHash('sha256').update(`${paths.join('\n')}\n`).digest('hex');
}

function parseSchemaPaths(value: unknown): CoverageSchemaPaths | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('schemaPaths must be an object');
  }
  const fields = value as Record<string, unknown>;
  const count = fields['count'];
  const sha256 = fields['sha256'];
  if (typeof count !== 'number' || typeof sha256 !== 'string') {
    throw new Error('schemaPaths needs a numeric count and a sha256 string');
  }
  return { count, sha256 };
}

const ROW_FIELDS = new Set(['target', 'reason', 'fixture']);

function optionalString(row: Record<string, unknown>, field: string, where: string): string | undefined {
  const value = row[field];
  if (value !== undefined && typeof value !== 'string') {
    throw new Error(`${where}: ${field} must be a string`);
  }
  return value;
}

function parseCoverageRows(section: unknown, where: string): Record<string, CoverageRow> {
  if (typeof section !== 'object' || section === null || Array.isArray(section)) {
    throw new Error(`${where} must be an object of rows`);
  }
  const rows: Record<string, CoverageRow> = {};
  for (const [key, raw] of Object.entries(section)) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new Error(`${where}.${key} must be a row`);
    }
    const row = raw as Record<string, unknown>;
    for (const field of Object.keys(row)) {
      if (!ROW_FIELDS.has(field)) {
        throw new Error(`${where}.${key}: unknown field ${field}`);
      }
    }
    const target = row['target'];
    let targets: string[];
    if (target === undefined) {
      targets = [];
    } else if (typeof target === 'string') {
      targets = [target];
    } else if (Array.isArray(target) && target.every((t) => typeof t === 'string')) {
      targets = target as string[];
    } else {
      throw new Error(`${where}.${key}: target must be a string or a list of strings`);
    }
    const parsed: CoverageRow = { target: targets };
    const reason = optionalString(row, 'reason', `${where}.${key}`);
    if (reason !== undefined) {
      parsed.reason = reason;
    }
    const fixture = optionalString(row, 'fixture', `${where}.${key}`);
    if (fixture !== undefined) {
      parsed.fixture = fixture;
    }
    rows[key] = parsed;
  }
  return rows;
}

function parseCoverageAllowlist(text: string): CoverageAllowlist {
  const doc: unknown = JSON.parse(text);
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new Error('allowlist must be an object');
  }
  for (const key of Object.keys(doc)) {
    if (!['$comment', 'schemaPaths', 'paths', 'vendor'].includes(key)) {
      throw new Error(`allowlist: unknown field ${key}`);
    }
  }
  const fields = doc as Record<string, unknown>;
  const allow: CoverageAllowlist = {
    paths: parseCoverageRows(fields['paths'] ?? {}, 'paths'),
    vendor: parseCoverageRows(fields['vendor'] ?? {}, 'vendor'),
  };
  const schemaPaths = parseSchemaPaths(fields['schemaPaths']);
  if (schemaPaths !== undefined) {
    allow.schemaPaths = schemaPaths;
  }
  return allow;
}

function loadCoverageAllowlist(): CoverageAllowlist {
  return parseCoverageAllowlist(readFileSync(ALLOWLIST_PATH, 'utf-8'));
}

// Targets name where a source value lands in the Baseline: the document, a
// requirement, a group, a tag, a description label, extensions.passthrough,
// refs, or the requirements/groups a container element becomes.
const COVERAGE_TARGET_FORM =
  /^(skip|refs|requirements|groups|(document|requirement|groups|tags|descriptions|passthrough)\.[A-Za-z][A-Za-z0-9_]*)$/;

const COVERAGE_PREDICATE = /\[[^\]]*\]/g;

function sortedKeys(rows: Record<string, CoverageRow>): string[] {
  return Object.keys(rows).sort(byteOrder);
}

// Reports every way the walked paths and the allowlist disagree, in sorted
// order, so the failing test names the first offender.
function coverageProblems(walked: string[], allow: CoverageAllowlist): string[] {
  const walkedSet = new Set(walked);
  const subtrees = Object.keys(allow.paths)
    .filter((key) => key.endsWith('/**'))
    .map((key) => key.slice(0, -'/**'.length))
    .sort(byteOrder);
  const under = (p: string, prefix: string): boolean => p.startsWith(`${prefix}/`);

  const problems: string[] = [];
  for (const p of walked) {
    if (Object.prototype.hasOwnProperty.call(allow.paths, p)) {
      continue;
    }
    if (!subtrees.some((prefix) => under(p, prefix))) {
      problems.push(`schema path not in the allowlist: ${p}`);
    }
  }
  for (const key of sortedKeys(allow.paths)) {
    if (key.endsWith('/**')) {
      const prefix = key.slice(0, -'/**'.length);
      if (!walked.some((p) => under(p, prefix))) {
        problems.push(`allowlist subtree defined by no schema: ${key}`);
      }
      continue;
    }
    if (!walkedSet.has(key)) {
      problems.push(`allowlist path defined by no schema: ${key}`);
    }
    for (const prefix of subtrees) {
      if (under(key, prefix)) {
        problems.push(`exact row shadowed by subtree row ${prefix}/**: ${key}`);
      }
    }
  }
  for (const key of sortedKeys(allow.vendor)) {
    const base = key.replace(COVERAGE_PREDICATE, '');
    if (base !== key) {
      if (!walkedSet.has(base)) {
        problems.push(`vendor selector on a path no schema defines: ${key}`);
      }
    } else if (walkedSet.has(key)) {
      problems.push(`vendor path is schema-defined and belongs in paths: ${key}`);
    } else {
      let ancestor = false;
      for (let i = key.lastIndexOf('/'); i > 0; i = key.lastIndexOf('/', i - 1)) {
        if (walkedSet.has(key.slice(0, i))) {
          ancestor = true;
          break;
        }
      }
      if (!ancestor) {
        problems.push(`vendor path has no schema-defined ancestor: ${key}`);
      }
    }
  }
  for (const section of [allow.paths, allow.vendor]) {
    for (const key of sortedKeys(section)) {
      const row = section[key]!;
      if (row.target.length === 0) {
        problems.push(`row without a target: ${key}`);
        continue;
      }
      let skip = false;
      for (const target of row.target) {
        if (!COVERAGE_TARGET_FORM.test(target)) {
          problems.push(`row with an unknown target form: ${key} -> ${target}`);
        }
        skip = skip || target === 'skip';
      }
      if (skip && row.target.length > 1) {
        problems.push(`skip combined with another target: ${key}`);
      }
      if (skip && !row.reason) {
        problems.push(`skip row without a reason: ${key}`);
      }
    }
  }
  return problems;
}

// The part of a Baseline the arrival rules read.
type ArrivalBaseline = Pick<HDFBaseline, 'name' | 'title' | 'version' | 'summary' | 'requirements' | 'groups' | 'extensions'>;
type ArrivalRequirement = ArrivalBaseline['requirements'][number];

// "Non-empty" for a tag or passthrough value: a string with text, a list or
// object with members, or a bool or number, which is present by being there.
// An unexpected type is not arrived, so it fails visibly.
function nonEmptyValue(value: unknown): boolean {
  if (typeof value === 'string') {
    return value !== '';
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === 'boolean' || typeof value === 'number') {
    return true;
  }
  if (typeof value === 'object' && value !== null) {
    return Object.keys(value).length > 0;
  }
  return false;
}

function nonEmptyString(value: string | undefined): boolean {
  return value !== undefined && value !== '';
}

// Whether the Baseline carries a non-empty value at a coverage target. The
// converter's output decides, never the input. Impact is numeric and present
// by schema, so it counts as arrived when above zero.
function targetArrives(b: ArrivalBaseline, target: string): boolean {
  const dot = target.indexOf('.');
  const section = dot < 0 ? target : target.slice(0, dot);
  const field = dot < 0 ? '' : target.slice(dot + 1);
  const anyRequirement = (holds: (r: ArrivalRequirement) => boolean): boolean => b.requirements.some(holds);
  const groups = b.groups ?? [];
  switch (section) {
    case 'requirements':
      return field === '' && b.requirements.length > 0;
    case 'groups':
      switch (field) {
        case '':
          return groups.length > 0;
        case 'id':
          return groups.some((g) => g.id !== '');
        case 'title':
          return groups.some((g) => nonEmptyString(g.title));
        default:
          return false;
      }
    case 'document':
      switch (field) {
        case 'name':
          return b.name !== '';
        case 'title':
          return nonEmptyString(b.title);
        case 'version':
          return nonEmptyString(b.version);
        case 'summary':
          return nonEmptyString(b.summary);
        default:
          return false;
      }
    case 'requirement':
      switch (field) {
        case 'id':
          return anyRequirement((r) => r.id !== '');
        case 'title':
          return anyRequirement((r) => nonEmptyString(r.title));
        case 'impact':
          return anyRequirement((r) => r.impact > 0);
        case 'severity':
          return anyRequirement((r) => nonEmptyString(r.severity));
        default:
          return false;
      }
    case 'tags':
      return field !== '' && anyRequirement((r) => nonEmptyValue(r.tags[field]));
    case 'descriptions':
      return field !== '' && anyRequirement((r) => r.descriptions.some((d) => d.label === field && d.data !== ''));
    case 'refs':
      return field === '' && anyRequirement((r) => (r.refs ?? []).length > 0);
    case 'passthrough':
      return field !== '' && nonEmptyValue(b.extensions?.passthrough?.[field]);
    default:
      return false;
  }
}

type BaselineLoader = (fixture: string) => Promise<ArrivalBaseline>;

// The second half of the completeness test: every mapped row names a fixture,
// that fixture converts, and every target of the row arrives non-empty. Rows
// marked "none: <reason>" come back as skipped so the test lists them by name
// instead of passing them silently.
async function arrivalProblems(
  allow: CoverageAllowlist,
  load: BaselineLoader
): Promise<{ problems: string[]; skipped: string[] }> {
  const problems: string[] = [];
  const skipped: string[] = [];
  for (const section of [allow.paths, allow.vendor]) {
    for (const key of sortedKeys(section)) {
      const row = section[key]!;
      const fixture = row.fixture ?? '';
      if (row.target.includes('skip')) {
        if (fixture !== '') {
          problems.push(`skip row names a fixture: ${key}`);
        }
        continue;
      }
      if (fixture === '') {
        problems.push(`mapped row without a fixture: ${key}`);
        continue;
      }
      if (fixture.startsWith('none:')) {
        const reason = fixture.slice('none:'.length).trim();
        if (reason === '') {
          problems.push(`fixture: none without a reason: ${key}`);
        } else {
          skipped.push(`${key}: ${reason}`);
        }
        continue;
      }
      let baseline: ArrivalBaseline;
      try {
        baseline = await load(fixture);
      } catch (err) {
        problems.push(`fixture ${fixture} for ${key}: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      for (const target of row.target) {
        if (!targetArrives(baseline, target)) {
          problems.push(`target ${target} does not arrive from ${fixture}: ${key}`);
        }
      }
    }
  }
  return { problems, skipped };
}

function rowsOf(...pairs: string[]): Record<string, CoverageRow> {
  const rows: Record<string, CoverageRow> = {};
  for (let i = 0; i + 1 < pairs.length; i += 2) {
    rows[pairs[i]!] = { target: [pairs[i + 1]!], reason: 'because' };
  }
  return rows;
}

describe('xccdf coverage', () => {
  it('every XSD path is in the allowlist', () => {
    const paths = walkXccdfSchemas();
    console.log(`${paths.length} schema paths; first ten: ${paths.slice(0, 10).join(', ')}`);

    // Paths the specification places in each schema, as a check on the walker
    // itself: an attribute three elements deep, an anyAttribute, a 1.2-only
    // element (dc-status) and a 1.1.4-only imported element (cdfp).
    for (const p of [
      'Rule/check/check-content-ref/@href', 'Rule/ident/@*',
      'Benchmark/Profile/select/@idref', 'Rule/dc-status', 'Benchmark/Platform-Specification',
    ]) {
      expect(paths).toContain(p);
    }

    const problems = coverageProblems(paths, loadCoverageAllowlist());
    expect(problems, `xccdf-coverage.json disagrees with the schemas:\n${problems.join('\n')}`).toEqual([]);
  });

  it('walker output matches the shared digest', () => {
    const paths = walkXccdfSchemas();
    const pinned = loadCoverageAllowlist().schemaPaths;
    expect(pinned, 'xccdf-coverage.json has no schemaPaths').toBeDefined();
    expect(paths.length, 'the walker\'s path count changed; update schemaPaths in xccdf-coverage.json once both languages agree').toBe(pinned!.count);
    expect(schemaPathsDigest(paths), 'the walker\'s path list changed; update schemaPaths in xccdf-coverage.json once both languages agree').toBe(pinned!.sha256);
  });

  it('names an unlisted path', () => {
    const problems = coverageProblems(['A/b', 'A/c'], { paths: rowsOf('A/b', 'skip'), vendor: {} });
    expect(problems).toEqual(['schema path not in the allowlist: A/c']);
  });

  it('names an allowlist path no schema defines', () => {
    const problems = coverageProblems(['A/b'], {
      paths: rowsOf('A/b', 'skip', 'A/zzz', 'skip', 'A/q/**', 'skip'),
      vendor: {},
    });
    expect(problems).toEqual([
      'allowlist subtree defined by no schema: A/q/**',
      'allowlist path defined by no schema: A/zzz',
    ]);
  });

  // An exact row inside a subtree row would fall to the subtree silently if
  // deleted, so the pair is refused: split the subtree instead.
  it('names an exact row shadowed by a subtree row', () => {
    const walked = ['A/b', 'A/b/c', 'A/b/d'];
    const allow = { paths: rowsOf('A/b', 'skip', 'A/b/**', 'skip', 'A/b/c', 'tags.x'), vendor: {} };
    expect(coverageProblems(walked, allow)).toEqual(['exact row shadowed by subtree row A/b/**: A/b/c']);
  });

  // A subtree row covers the paths below its root, never the root itself, so
  // deleting the root's own row is always caught.
  it('a subtree row covers its descendants only', () => {
    const walked = ['A/b', 'A/b/c', 'A/b/c/@d', 'A/bx'];
    const problems = coverageProblems(walked, { paths: rowsOf('A/b/**', 'skip'), vendor: {} });
    expect(problems).toEqual([
      'schema path not in the allowlist: A/b',
      'schema path not in the allowlist: A/bx',
    ]);
  });

  it('a skip row without a reason fails', () => {
    const problems = coverageProblems(['A/b'], { paths: { 'A/b': { target: ['skip'] } }, vendor: {} });
    expect(problems).toEqual(['skip row without a reason: A/b']);
  });

  it('checks the target form', () => {
    const problems = coverageProblems(['A/b', 'A/c', 'A/d'], {
      paths: {
        'A/b': { target: ['tag.cce'] },
        'A/c': { target: ['skip', 'tags.cce'], reason: 'because' },
        'A/d': { target: [] },
      },
      vendor: {},
    });
    expect(problems).toEqual([
      'row with an unknown target form: A/b -> tag.cce',
      'skip combined with another target: A/c',
      'row without a target: A/d',
    ]);
  });

  it('vendor rows extend schema paths', () => {
    const walked = ['Rule/description', 'Rule/ident'];
    const problems = coverageProblems(walked, {
      paths: rowsOf('Rule/description', 'descriptions.default', 'Rule/ident', 'tags.cci'),
      vendor: rowsOf(
        'Rule/description/FalsePositives', 'skip',
        'Rule/ident[@system=cci]', 'tags.cci',
        'Rule/descriptions/FalseNegatives', 'skip',
        'Rule/identifier[@system=cce]', 'skip',
        'Rule/ident', 'tags.cci',
      ),
    });
    expect(problems).toEqual([
      'vendor path has no schema-defined ancestor: Rule/descriptions/FalseNegatives',
      'vendor path is schema-defined and belongs in paths: Rule/ident',
      'vendor selector on a path no schema defines: Rule/identifier[@system=cce]',
    ]);
  });

  it('every mapped field arrives from its fixture', async () => {
    const baselines = new Map<string, HDFBaseline>();
    const load = async (fixture: string): Promise<HDFBaseline> => {
      const cached = baselines.get(fixture);
      if (cached) {
        return cached;
      }
      const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', fixture), 'utf-8');
      const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(input)) as HDFBaseline;
      baselines.set(fixture, baseline);
      return baseline;
    };
    const { problems, skipped } = await arrivalProblems(loadCoverageAllowlist(), load);
    console.log(`${skipped.length} rows skipped (fixture: none):\n${skipped.join('\n')}`);
    expect(problems, `mapped fields that do not arrive:\n${problems.join('\n')}`).toEqual([]);
  });

  it('names a row whose target does not arrive', async () => {
    const filled: ArrivalBaseline = { name: 'n', requirements: [{ id: 'r', impact: 0.5, descriptions: [], tags: { cci: ['CCI-000001'] } }] };
    const load = (fixture: string): Promise<ArrivalBaseline> =>
      fixture === 'x.xml' ? Promise.resolve(filled) : Promise.reject(new Error(`no fixture ${fixture}`));
    const { problems, skipped } = await arrivalProblems({
      paths: {
        A: { target: ['tags.cci'], fixture: 'x.xml' },
        B: { target: ['tags.cce'], fixture: 'x.xml' },
        C: { target: ['skip'], reason: 'because' },
        D: { target: ['tags.cci'] },
        E: { target: ['tags.cci'], fixture: 'none: no fixture carries it' },
        F: { target: ['tags.cci'], fixture: 'none:' },
        G: { target: ['tags.cci'], fixture: 'missing.xml' },
        H: { target: ['skip'], reason: 'because', fixture: 'x.xml' },
      },
      vendor: {},
    }, load);
    expect(problems).toEqual([
      'target tags.cce does not arrive from x.xml: B',
      'mapped row without a fixture: D',
      'fixture: none without a reason: F',
      'fixture missing.xml for G: no fixture missing.xml',
      'skip row names a fixture: H',
    ]);
    expect(skipped).toEqual(['E: no fixture carries it']);
  });

  // Every target form the allowlist admits has an arrival rule, and each rule
  // is false on an empty Baseline and true on one that carries the value.
  it('targetArrives covers every target kind', () => {
    const full: ArrivalBaseline = {
      name: 'n', title: 't', version: 't', summary: 't',
      groups: [{ id: 'g', title: 't', requirements: ['r'] }],
      requirements: [{
        id: 'r', title: 't', impact: 0.7, severity: Severity.High,
        descriptions: [{ label: 'check', data: 'c' }],
        refs: [{ url: 'https://example.invalid' }],
        tags: { cci: ['CCI-000001'], rid: 'SV-1', documentable: false, empty: '', none: [] },
      }],
      extensions: { passthrough: { releaseInfo: 'Release: 9', blank: '' } },
    };
    const empty: ArrivalBaseline = { name: '', requirements: [] };
    // One requirement and one group with every field blank: present, not arrived.
    const blank: ArrivalBaseline = {
      name: '',
      groups: [{ id: '', requirements: [] }],
      requirements: [{ id: '', impact: 0, descriptions: [{ label: 'check', data: '' }], tags: { cci: [] } }],
      extensions: { passthrough: { releaseInfo: '' } },
    };
    for (const target of [
      'document.name', 'document.title', 'document.version', 'document.summary',
      'requirements', 'groups', 'groups.id', 'groups.title',
      'requirement.id', 'requirement.title', 'requirement.impact', 'requirement.severity',
      'tags.cci', 'tags.rid', 'tags.documentable', 'descriptions.check', 'refs', 'passthrough.releaseInfo',
    ]) {
      expect(COVERAGE_TARGET_FORM.test(target), target).toBe(true);
      expect(targetArrives(full, target), `${target} on a full Baseline`).toBe(true);
      expect(targetArrives(empty, target), `${target} on an empty Baseline`).toBe(false);
      if (target !== 'requirements' && target !== 'groups') {
        expect(targetArrives(blank, target), `${target} on a blank Baseline`).toBe(false);
      }
    }
    for (const target of ['tags.empty', 'tags.none', 'passthrough.blank', 'descriptions.fix', 'groups.weight', 'document.id', 'requirement.weight', 'tag.cci']) {
      expect(targetArrives(full, target), target).toBe(false);
    }
  });

  it('target accepts a string or a list, nothing else', () => {
    const allow = parseCoverageAllowlist(
      '{"paths":{"A":{"target":"tags.x"},"B":{"target":["requirement.id","tags.rid"]}},"vendor":{}}'
    );
    expect(allow.paths['A']!.target).toEqual(['tags.x']);
    expect(allow.paths['B']!.target).toEqual(['requirement.id', 'tags.rid']);
    expect(() => parseCoverageAllowlist('{"paths":{"A":{"target":7}},"vendor":{}}')).toThrow(/target/);
    expect(() => parseCoverageAllowlist('{"paths":{"A":{"target":"skip","why":"x"}},"vendor":{}}')).toThrow(/why/);
  });
});
