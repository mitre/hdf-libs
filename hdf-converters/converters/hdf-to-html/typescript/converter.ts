/**
 * Renders an HDF results document as one self-contained HTML report. The Go
 * peer emits the same bytes for the same input, so every choice here that
 * affects output (ordering, escaping, number and time formatting) mirrors it
 * and is pinned by the shared goldens.
 */

import {
  canonicalJson,
  computeEffectiveStatus,
  formatTimestamp,
  governingStatusOverrideIndex,
  parseTimestamp,
  worstStatus,
  type StatusOverrideInput,
} from '@mitre/hdf-utilities';
import {
  calculateCompliance,
  countControlsByStatus,
  deriveSeverity,
  type SeverityCounts,
  type StatusCounts,
} from '@mitre/hdf-engine';
import type { EvaluatedBaseline, HDFResults, Severity } from '@mitre/hdf-schema';
import { requireHdfResults } from '../../../shared/typescript/converterutil.js';
import { byCodePoint } from '../../../shared/typescript/exportmap.js';
import { SCRIPT, SCRIPT_HASH, STYLESHEET } from './assets.js';

const CONVERTER_NAME = 'hdf-to-html';

/**
 * How much of the document the report shows. The three levels are the ones
 * `saf convert hdf2html` offers, each a superset of the last.
 */
export type HtmlReportType = 'executive' | 'manager' | 'administrator';

export interface HtmlReportOptions {
  /** Case-insensitive; defaults to 'administrator'. */
  reportType?: string;
}

/** Reads a report type case-insensitively; empty selects 'administrator'. */
export function parseReportType(value: string | undefined | null): HtmlReportType {
  const normalized = (value ?? '').trim().toLowerCase();
  switch (normalized) {
    case '':
    case 'administrator':
      return 'administrator';
    case 'manager':
      return 'manager';
    case 'executive':
      return 'executive';
    default:
      throw new Error(
        `unknown report type ${JSON.stringify(value)}: must be one of executive, manager, administrator`,
      );
  }
}

type Json = Record<string, unknown>;

/**
 * Renders an HDF results document as HTML. The output depends on the input and
 * options alone: nothing is read from the clock or the host, so the same
 * document always yields the same report.
 */
export function convertHdfToHtml(input: string, options: HtmlReportOptions = {}): string {
  return render([{ name: '', content: input }], options, false);
}

/** One results document going into an aggregated report. `name` is how the report refers to it, usually its file name. */
export interface HtmlReportDocument {
  name: string;
  content: string;
}

/**
 * Renders several results documents as one report: combined status, severity
 * and compliance, then each document's own context, components and results
 * under its name. Documents appear in the order given.
 */
export function convertHdfDocumentsToHtml(documents: HtmlReportDocument[], options: HtmlReportOptions = {}): string {
  if (documents.length === 0) {
    throw new Error(`${CONVERTER_NAME}: no documents to report on`);
  }
  return render(documents, options, true);
}

/** One input document and the instant its overrides are judged at. */
interface Source {
  name: string;
  doc: Json;
  baselines: Json[];
  ref: AssessmentTime;
}

function render(documents: HtmlReportDocument[], options: HtmlReportOptions, aggregated: boolean): string {
  let reportType: HtmlReportType;
  try {
    reportType = parseReportType(options.reportType);
  } catch (err) {
    throw new Error(`${CONVERTER_NAME}: ${(err as Error).message}`);
  }

  const sources = documents.map((document): Source => {
    let doc: Json;
    try {
      ({ doc } = requireHdfResults(document.content, CONVERTER_NAME));
    } catch (err) {
      if (!aggregated) throw err;
      throw new Error(`${document.name}: ${(err as Error).message}`);
    }
    const baselines = list(doc.baselines).map(obj);
    return { name: document.name, doc, baselines, ref: assessmentTime(doc, baselines) };
  });

  const r = new Renderer(reportType, sources, aggregated);
  r.document();
  return r.lines.join('');
}

/** A JSON value as an object; anything else reads as an empty one, as Go's zero struct does. */
function obj(value: unknown): Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Json) : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** A string field as text; absent or wrong-typed reads as empty, as Go's zero value does. */
function text(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function numeric(value: unknown): number {
  return typeof value === 'number' ? value : 0;
}

/** HDF's canonical trimmed-UTC RFC3339; absent or unparseable is empty. */
function formatTime(value: unknown): string {
  const parsed = toDate(value);
  return parsed ? formatTimestamp(parsed) : '';
}

/** Go's zero time (0001-01-01T00:00:00Z), which the legacy converters write when a source has no time. It is not a time. */
const GO_ZERO_TIME = -62135596800000;

function toDate(value: unknown): Date | null {
  const parsed = parsedDate(value);
  return parsed && parsed.getTime() !== GO_ZERO_TIME ? parsed : null;
}

function parsedDate(value: unknown): Date | null {
  if (value instanceof Date) return value;
  return typeof value === 'string' ? parseTimestamp(value) : null;
}

interface AssessmentTime {
  /** Canonical timestamp override expiry is judged against. */
  stamp: string;
  date: Date;
  /** False when the document carries no usable time; the epoch stands in, leaving every override in force. */
  known: boolean;
}

/**
 * When the assessment ran: the document timestamp, else its latest result start
 * time. Overrides are judged against it instead of the wall clock, which is
 * what keeps the report reproducible.
 */
function assessmentTime(doc: Json, baselines: Json[]): AssessmentTime {
  const latest = toDate(doc.timestamp) ?? latestStart(baselines);
  if (!latest) {
    const epoch = new Date(0);
    return { stamp: formatTimestamp(epoch), date: epoch, known: false };
  }
  return { stamp: formatTimestamp(latest), date: latest, known: true };
}

/** The latest result start time in the document, if any result carries one. */
function latestStart(baselines: Json[]): Date | null {
  let latest: Date | null = null;
  const results = baselines.flatMap((baseline) => list(baseline.requirements).map(obj)).flatMap((req) => list(req.results).map(obj));
  for (const res of results) {
    const start = toDate(res.startTime);
    if (start && (!latest || start > latest)) latest = start;
  }
  return latest;
}

function emptyCounts(): StatusCounts {
  const bucket = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 });
  return { passed: bucket(), failed: bucket(), skipped: bucket(), error: bucket(), noImpact: bucket() };
}

/** A count set's five status buckets in the order the report's columns and stat lists use them. */
function statusBuckets(c: StatusCounts): SeverityCounts[] {
  return [c.passed, c.failed, c.skipped, c.noImpact, c.error];
}

function addSeverities(dst: SeverityCounts, src: SeverityCounts): void {
  dst.critical += src.critical;
  dst.high += src.high;
  dst.medium += src.medium;
  dst.low += src.low;
  dst.informational += src.informational;
  dst.total += src.total;
}

/** Rolls `src` into `dst`: the engine counts one document at a time, and the report rolls baselines up into sources and sources into a whole. */
function addCounts(dst: StatusCounts, src: StatusCounts): void {
  const to = statusBuckets(dst);
  statusBuckets(src).forEach((bucket, i) => addSeverities(to[i]!, bucket));
}

function countTotal(c: StatusCounts): number {
  return statusBuckets(c).reduce((n, bucket) => n + bucket.total, 0);
}

/** Sums each severity across the statuses: the severity panel counts every requirement, whatever its status. */
function severityTotals(c: StatusCounts): SeverityCounts {
  const out: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  for (const bucket of statusBuckets(c)) addSeverities(out, bucket);
  return out;
}

/**
 * The compliance percentage hdf-engine computes, to two places, so the report
 * never disagrees with `hdf validate threshold` in the last digit. The Go peer
 * formats the same number with FormatFixed, which is toFixed's rounding.
 */
export function compliancePercent(c: StatusCounts): string {
  return calculateCompliance(c).toFixed(2);
}

export function compliance(c: StatusCounts): string {
  return `${compliancePercent(c)}%`;
}

/** The requirement's severity through the engine, exactly as its tally derives it. */
function requirementSeverity(req: Json): string {
  return deriveSeverity(numeric(req.impact), (req.severity ?? null) as Severity | null);
}

/**
 * Maps overrides onto the canonical effective-status input shape. formatTime
 * drops Go's zero time, which the legacy converters leave in `expiresAt` to
 * mean "no expiry": handing the raw value to the status ladder would read it as
 * an expiry in the year 1 and disagree with both the overrides table and Go,
 * whose zero time.Time already means absent. Effective status and the table's
 * governing/expired column read the same normalized overrides.
 */
function overrideInputs(overrides: Json[]): StatusOverrideInput[] {
  return overrides.map((o) => ({
    status: text(o.status) === '' ? undefined : text(o.status),
    appliedAt: formatTime(o.appliedAt) || undefined,
    expiresAt: formatTime(o.expiresAt) || undefined,
  }));
}

/** Bands the engine's compliance percentage at 90 and 60. */
function complianceLevel(pct: number): readonly [cls: string, label: string] {
  if (pct >= 90) return ['high', 'High compliance'];
  if (pct >= 60) return ['medium', 'Medium compliance'];
  return ['low', 'Low compliance'];
}

/** Maps a severity onto the fixed set the stylesheet knows; an informational, absent or unrecognized one is 'none'. */
export function severityClass(severity: string): string {
  return severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' ? severity : 'none';
}

export function severityLabel(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    case '':
    case 'none':
    case 'informational':
      return 'None';
    default:
      return severity;
  }
}

/** Names a description the way the Heimdall report does. */
export function descriptionHeading(label: string): string {
  switch (label) {
    case 'default':
      return 'Description';
    case 'check':
      return 'Check Text';
    case 'fix':
      return 'Fix Text';
    case 'rationale':
      return 'Rationale';
    case 'caveat':
      return 'Caveat';
    default:
      return label;
  }
}

function plural(n: number, noun: string): string {
  return n === 1 ? `1 ${noun}` : `${n} ${noun}s`;
}

function stat(cls: string, n: number, label: string, sub: string): string {
  const subHtml = sub === '' ? '' : `<span class="sub">${sub}</span>`;
  return `<li class="stat c-${cls}"><span class="num">${n}</span><span class="lbl">${label}</span>${subHtml}</li>`;
}

type Segment = readonly [cls: string, name: string, n: number];

/**
 * A proportional strip; a zero count contributes no segment. It is an image to
 * assistive technology, described by the same counts the list above it states,
 * so nothing is conveyed by colour alone.
 */
function bar(label: string, segments: readonly Segment[]): string {
  const described = segments.map(([, name, n]) => `${n} ${name}`).join(', ');
  const spans = segments
    .filter(([, , n]) => n > 0)
    .map(([cls, , n]) => `<span class="seg c-${cls}" style="--n:${n}"></span>`)
    .join('');
  return `<div class="bar" role="img" aria-label="${label}: ${described}">${spans}</div>`;
}

/** A heading and a value that are already HTML. */
function detailRow(heading: string, value: string): string {
  return `<tr><th scope="row">${heading}</th><td>${value}</td></tr>`;
}

/** Carries text verbatim. An HTML parser drops one newline directly after <pre>, so one is always written for it to drop. */
function prose(value: string): string {
  return `<pre class="prose">\n${escapeHtml(value)}</pre>`;
}

const REPORT_TYPE_LABEL: Record<HtmlReportType, string> = {
  executive: 'Executive',
  manager: 'Manager',
  administrator: 'Administrator',
};

type Pair = readonly [term: string, value: string];

const STATUS_FILTERS: ReadonlyArray<readonly [string, string]> = [
  ['passed', 'Passed'],
  ['failed', 'Failed'],
  ['not-applicable', 'Not Applicable'],
  ['not-reviewed', 'Not Reviewed'],
  ['error', 'Error'],
];

/** An open collapsible block. */
interface Fold {
  id: string;
  label: string;
  long: boolean;
}

/**
 * The size past which a block starts closed: anything longer than two lines or
 * rows is behind its heading, so a long report is a list of headings with
 * counts instead of a scroll.
 */
const COLLAPSED_ABOVE = 2;

/** How many lines text occupies. */
function lineCount(value: string): number {
  return value.split('\n').length;
}

/** Text that would take more than two lines on the page: more than two lines of its own, or one long enough to wrap that far. */
export function isLongText(value: string): boolean {
  return lineCount(value) > COLLAPSED_ABOVE || Array.from(value).length > 240;
}

function countFacts(pairs: readonly Pair[]): number {
  return pairs.filter(([, value]) => value !== '').length;
}

class Renderer {
  readonly lines: string[] = [];

  /** The source being rendered, which fixes the reference time. */
  private src: Source;
  /** These number the blocks a reader can jump back to. */
  private folds = 0;
  private requirements = 0;

  /**
   * `aggregated` lays the report out by source, even for a single document;
   * the single-document layout has no source level.
   */
  constructor(
    private readonly reportType: HtmlReportType,
    private readonly sources: Source[],
    private readonly aggregated: boolean,
  ) {
    this.src = sources[0]!;
  }

  /** The heading outline stays in order: the aggregated layout has a source heading above the baselines. */
  private get baselineHeading(): string {
    return this.aggregated ? 'h4' : 'h3';
  }

  private get detailHeading(): 'h4' | 'h5' {
    return this.aggregated ? 'h5' : 'h4';
  }

  /**
   * Starts a collapsible block: a heading with a count that opens onto the
   * content. `title` is HTML; `label` is the plain text the return link names.
   * An empty id takes the next number.
   */
  private openFold(cls: string, id: string, tag: string, title: string, label: string, count: number): Fold {
    if (id === '') {
      this.folds++;
      id = `block-${this.folds}`;
    }
    const long = count > COLLAPSED_ABOVE;
    const classes = cls === '' ? 'fold' : `fold ${cls}`;
    this.line(`<details class="${classes}" id="${id}"${long ? '' : ' open="open"'}>`);
    this.line(`<summary><${tag}>${title}</${tag}><span class="count">${count}</span></summary>`);
    this.line('<div class="fold-body">');
    return { id, label, long };
  }

  /** Ends the block, with a way back to its top when it is long enough to need one. */
  private closeFold(f: Fold): void {
    if (f.long) {
      this.line(`<p class="to-top"><a href="#${f.id}">Back to the top of ${escapeHtml(f.label)}</a></p>`);
    }
    this.line('</div>');
    this.line('</details>');
  }

  private line(s: string): void {
    this.lines.push(s, '\n');
  }

  document(): void {
    const detailed = this.reportType !== 'executive';
    const policy = `default-src 'none'; style-src 'unsafe-inline'; script-src '${SCRIPT_HASH}'`;

    this.line('<!DOCTYPE html>');
    this.line('<html lang="en">');
    this.line('<head>');
    this.line('<meta charset="utf-8" />');
    this.line(`<meta http-equiv="Content-Security-Policy" content="${policy}" />`);
    this.line('<meta name="viewport" content="width=device-width, initial-scale=1" />');
    // Declared in the head so the browser's own controls and scrollbars follow
    // the reader's scheme before the stylesheet is parsed.
    this.line('<meta name="color-scheme" content="light dark" />');
    this.line('<title>HDF Assessment Report</title>');
    this.line('<style>');
    this.lines.push(STYLESHEET);
    this.line('</style>');
    this.line('</head>');
    this.line('<body>');
    this.line('<a class="skip" href="#main">Skip to content</a>');
    this.line('<header class="topbar" id="top">');
    this.line('<h1 class="brand">HDF Assessment Report</h1>');
    this.line(`<span class="report-type">Report type: ${REPORT_TYPE_LABEL[this.reportType]}</span>`);
    this.line('<nav aria-label="Sections">');
    this.line('<ul>');
    this.line('<li><a href="#status">Status</a></li>');
    this.line(this.aggregated ? '<li><a href="#sources">Sources</a></li>' : '<li><a href="#assessment">Assessment</a></li>');
    this.line('<li><a href="#components">Components</a></li>');
    if (detailed) this.line('<li><a href="#results">Results</a></li>');
    this.line('</ul>');
    this.line('</nav>');
    this.line('<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>');
    this.line('</header>');
    this.line('<main id="main" class="container">');

    this.status();
    if (this.aggregated) this.sourceList();
    else this.assessment(this.sources[0]!.doc);
    this.components();
    if (detailed) this.results();

    this.line('</main>');
    this.line('<a class="page-top" href="#top">Top</a>');
    this.line('<script>');
    this.lines.push(SCRIPT);
    this.line('</script>');
    this.line('</body>');
    this.line('</html>');
  }

  /** Writes the non-empty pairs and reports whether it wrote any. */
  private definitionList(pairs: readonly Pair[]): boolean {
    let wrote = false;
    for (const [term, value] of pairs) {
      if (value === '') continue;
      if (!wrote) {
        this.line('<dl>');
        wrote = true;
      }
      this.line(`<dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd>`);
    }
    if (wrote) this.line('</dl>');
    return wrote;
  }

  private assessment(doc: Json): void {
    this.line('<section id="assessment" class="card" aria-labelledby="assessment-heading">');
    this.line('<h2 id="assessment-heading">Assessment</h2>');

    this.line('<div class="facts">');
    const facts = documentFacts(doc);
    const f = this.openFold('', '', 'h3', 'Document', 'the document facts', countFacts(facts));
    if (!this.definitionList(facts)) {
      this.line('<p class="empty">The document carries no assessment metadata.</p>');
    }
    this.closeFold(f);

    if (doc.runner != null) {
      const runner = runnerFacts(obj(doc.runner));
      const rf = this.openFold('', '', 'h3', 'Runner', 'the runner facts', countFacts(runner));
      this.definitionList(runner);
      this.closeFold(rf);
    }
    this.line('</div>');
    this.externalReferences('h3', 'Enrichment and External References', doc.externalReferences);
    this.line('</section>');
  }

  /** The aggregated layout's assessment section: one panel per input document, each the target of the links in the status tables. */
  private sourceList(): void {
    this.line('<section id="sources" class="card" aria-labelledby="sources-heading">');
    this.line(`<h2 id="sources-heading">Sources (${this.sources.length})</h2>`);
    this.line('<div class="facts">');
    this.sources.forEach((src, i) => {
      const facts = documentFacts(src.doc);
      const f = this.openFold('', sourceId(i), 'h3', escapeHtml(src.name), src.name, countFacts(facts));
      if (!this.definitionList(facts)) {
        this.line('<p class="empty">The document carries no assessment metadata.</p>');
      }
      if (src.doc.runner != null) {
        this.line('<h4>Runner</h4>');
        this.definitionList(runnerFacts(obj(src.doc.runner)));
      }
      this.externalReferences('h4', 'Enrichment and External References', src.doc.externalReferences);
      this.closeFold(f);
    });
    this.line('</div>');
    this.line('</section>');
  }

  private components(): void {
    const perSource = this.sources.map((src) => list(src.doc.components).map(obj));
    const total = perSource.reduce((n, components) => n + components.length, 0);
    this.line('<section id="components" class="card" aria-labelledby="components-heading">');
    this.line(`<h2 id="components-heading">Components (${total})</h2>`);
    if (total > 0) {
      this.line('<div class="components">');
      this.sources.forEach((src, i) => {
        this.src = src;
        for (const c of perSource[i]!) this.component(c);
      });
      this.line('</div>');
    } else if (this.aggregated) {
      this.line('<p class="empty">The documents name no components.</p>');
    } else {
      this.line('<p class="empty">The document names no components.</p>');
    }
    this.line('</section>');
  }

  private component(c: Json): void {
    const pairs: Pair[] = [['Source', this.aggregated ? this.src.name : ''] as const];
    for (const [term, key] of COMPONENT_FIELDS) pairs.push(componentField(c, term, key));
    const f = this.openFold(
      'component',
      '',
      'h3',
      `${escapeHtml(text(c.name))} <span class="type">${escapeHtml(text(c.type))}</span>`,
      text(c.name),
      countFacts(pairs) + Object.keys(obj(c.labels)).length + Object.keys(obj(c.externalIds)).length,
    );
    this.definitionList(pairs);
    this.chips('Labels', c.labels);
    this.chips('External IDs', c.externalIds);
    this.closeFold(f);
  }

  /** A map as key/value chips in key order. An empty value is kept: the key itself is the information. */
  private chips(heading: string, value: unknown): void {
    const m = obj(value);
    const keys = Object.keys(m).sort(byCodePoint);
    if (keys.length === 0) return;

    this.line(`<h4>${heading}</h4>`);
    this.line('<ul class="chips">');
    for (const k of keys) {
      this.line(`<li><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(text(m[k]))}</span></li>`);
    }
    this.line('</ul>');
  }

  private effectiveStatus(req: Json): string {
    return computeEffectiveStatus(
      {
        // Go's typed decode gives an absent impact the zero value, so the ladder
        // there reads it as notApplicable; the same defaulting keeps the two
        // languages agreeing on a document that omits impact.
        impact: numeric(req.impact),
        resultStatuses: list(req.results).map(obj).map((res) => text(res.status)),
        overrides: overrideInputs(list(req.statusOverrides).map(obj)),
      },
      this.src.ref.stamp,
    );
  }

  private status(): void {
    const all = emptyCounts();
    // Individual results, worded as the Heimdall report words them. A requirement
    // passed by an override keeps its failed checks out of the passed tally.
    const checks = { underPassed: 0, passedUnderFailed: 0, failedUnderFailed: 0, total: 0 };
    const perSource: StatusCounts[] = [];
    const perBaseline = this.sources.map((src) => {
      this.src = src;
      const sourceCounts = emptyCounts();
      perSource.push(sourceCounts);
      return src.baselines.map((baseline) => {
        const requirements = list(baseline.requirements).map(obj);
        for (const req of requirements) {
          const status = this.effectiveStatus(req);
          for (const res of list(req.results).map(obj)) {
            checks.total++;
            const resultStatus = text(res.status);
            if (status === 'passed' && resultStatus === 'passed') checks.underPassed++;
            else if (status === 'failed' && resultStatus === 'passed') checks.passedUnderFailed++;
            else if (status === 'failed' && resultStatus === 'failed') checks.failedUnderFailed++;
          }
        }
        // The engine owns the status and severity tally, so the report's numbers
        // are the ones the threshold gate and the MCP tools report. It is handed
        // the normalized requirements because a null array member reaches it
        // otherwise, where Go's typed decode had already made one a zero struct.
        const counts = countControlsByStatus(
          { baselines: [{ requirements } as unknown as EvaluatedBaseline] } as HDFResults,
          (req) => this.effectiveStatus(req as unknown as Json),
        );
        addCounts(sourceCounts, counts);
        addCounts(all, counts);
        return counts;
      });
    });
    const severities = severityTotals(all);
    const anyRef = this.sources.some((src) => src.ref.known);

    this.line('<section id="status" class="card" aria-labelledby="status-heading">');
    this.line('<h2 id="status-heading">Status</h2>');
    if (countTotal(all) > 0 && anyRef) {
      if (this.aggregated) {
        this.line(
          '<p class="as-of">Effective status evaluated for each source as of its own assessment time. ' +
            'Overrides that had expired by then are not applied.</p>',
        );
      } else {
        this.line(
          `<p class="as-of">Effective status evaluated as of ${escapeHtml(this.sources[0]!.ref.stamp)}` +
            ', the time of the assessment. Overrides that had expired by then are not applied.</p>',
        );
      }
    }

    this.line('<div class="dashboard">');

    this.line('<div class="panel">');
    this.line('<h3>Requirements</h3>');
    this.line('<ul class="stats">');
    this.line(stat('passed', all.passed.total, 'Passed', `${plural(checks.underPassed, 'individual check')} passed`));
    this.line(
      stat(
        'failed',
        all.failed.total,
        'Failed',
        `${plural(checks.passedUnderFailed, 'individual check')} passed, ` +
          `${checks.failedUnderFailed} failed out of ${plural(checks.total, 'total check')}`,
      ),
    );
    this.line(stat('not-applicable', all.noImpact.total, 'Not Applicable', ''));
    this.line(stat('not-reviewed', all.skipped.total, 'Not Reviewed', ''));
    this.line(stat('error', all.error.total, 'Error', ''));
    this.line(`<li class="stat stat-total"><span class="num">${countTotal(all)}</span><span class="lbl">Total</span></li>`);
    this.line('</ul>');
    this.line(
      bar('Requirements by status', [
        ['passed', 'passed', all.passed.total],
        ['failed', 'failed', all.failed.total],
        ['not-applicable', 'not applicable', all.noImpact.total],
        ['not-reviewed', 'not reviewed', all.skipped.total],
        ['error', 'error', all.error.total],
      ]),
    );
    this.line('</div>');

    this.line('<div class="panel">');
    this.line('<h3>Severity</h3>');
    this.line('<ul class="stats">');
    this.line(stat('critical', severities.critical, 'Critical', ''));
    this.line(stat('high', severities.high, 'High', ''));
    this.line(stat('medium', severities.medium, 'Medium', ''));
    this.line(stat('low', severities.low, 'Low', ''));
    // The engine's informational bucket is this report's "none": every severity
    // outside critical/high/medium/low lands there under both namings.
    this.line(stat('none', severities.informational, 'None', ''));
    this.line('</ul>');
    this.line(
      bar('Requirements by severity', [
        ['critical', 'critical', severities.critical],
        ['high', 'high', severities.high],
        ['medium', 'medium', severities.medium],
        ['low', 'low', severities.low],
        ['none', 'none', severities.informational],
      ]),
    );
    this.line('</div>');

    const [level, levelLabel] = complianceLevel(calculateCompliance(all));
    this.line(`<div class="panel compliance compliance-${level}">`);
    this.line('<h3 id="compliance-heading">Compliance</h3>');
    // A measurement on a fixed scale, not work in progress, so the ring is a
    // meter to assistive technology. The percentage is printed inside it because
    // the sweep and its band colour say nothing on their own.
    this.line(
      `<div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${compliancePercent(all)}"` +
        ` aria-labelledby="compliance-heading" style="--pct:${compliancePercent(all)}">` +
        `<span class="pct">${compliance(all)}</span></div>`,
    );
    this.line(`<p class="level">${levelLabel}</p>`);
    this.line('<p class="formula">Passed / (Passed + Failed + Not Reviewed + Error) \u00d7 100</p>');
    this.line('</div>');

    this.line('</div>');

    if (this.aggregated) {
      const bySource = this.openFold('', '', 'h3', 'Status by source', 'the status by source', this.sources.length);
      this.line('<div class="table-wrap">');
      this.line('<table class="summary" aria-label="Status by source">');
      this.line(summaryHead('Source'));
      this.line('<tbody>');
      this.sources.forEach((src, si) =>
        this.line(summaryRow(`<a href="#${sourceId(si)}">${escapeHtml(src.name)}</a>`, perSource[si]!)),
      );
      this.line('</tbody>');
      this.line('<tfoot>');
      this.line(summaryRow('All sources', all));
      this.line('</tfoot>');
      this.line('</table>');
      this.line('</div>');
      this.closeFold(bySource);
    }

    const baselineCount = this.sources.reduce((n, src) => n + src.baselines.length, 0);
    const byBaseline = this.openFold('', '', 'h3', 'Status by baseline', 'the status by baseline', baselineCount);
    this.line('<div class="table-wrap">');
    this.line('<table class="summary" aria-label="Status by baseline">');
    this.line(summaryHead('Baseline'));
    this.line('<tbody>');
    this.sources.forEach((src, si) => {
      src.baselines.forEach((baseline, i) => {
        const name = this.aggregated ? `${src.name} \u203a ${text(baseline.name)}` : text(baseline.name);
        this.line(summaryRow(escapeHtml(name), perBaseline[si]![i]!));
      });
    });
    this.line('</tbody>');
    this.line('<tfoot>');
    this.line(summaryRow('All baselines', all));
    this.line('</tfoot>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(byBaseline);
    this.line('</section>');
  }

  private results(): void {
    this.line('<section id="results" class="card" aria-labelledby="results-heading">');
    this.line('<h2 id="results-heading">Results</h2>');
    this.line('<div class="toolbar">');
    this.line(
      '<input type="search" id="filter-text" placeholder="Filter by ID, title or control" aria-label="Filter requirements by ID, title or control" />',
    );
    this.line('<div class="filters" role="group" aria-label="Filter by status">');
    this.line('<button type="button" class="filter" data-status="all" aria-pressed="true">All</button>');
    for (const [key, label] of STATUS_FILTERS) {
      this.line(`<button type="button" class="filter" data-status="${key}" aria-pressed="false">${label}</button>`);
    }
    this.line('</div>');
    this.line('<button type="button" id="expand-all">Expand all</button>');
    this.line('<button type="button" id="collapse-all">Collapse all</button>');
    this.line('<span id="filter-count" class="shown" aria-live="polite"></span>');
    this.line('</div>');

    for (const src of this.sources) {
      this.src = src;
      let f: Fold | undefined;
      if (this.aggregated) {
        const total = src.baselines.reduce((n, baseline) => n + list(baseline.requirements).length, 0);
        f = this.openFold('group source', '', 'h3', escapeHtml(src.name), src.name, total);
      }
      for (const baseline of src.baselines) this.baseline(baseline);
      if (f) this.closeFold(f);
    }
    this.line('</section>');
  }

  private baseline(baseline: Json): void {
    const requirements = list(baseline.requirements).map(obj);
    const f = this.openFold(
      'group baseline',
      '',
      this.baselineHeading,
      escapeHtml(text(baseline.name)),
      text(baseline.name),
      requirements.length,
    );
    const facts: Pair[] = [
      ['Title', text(baseline.title)],
      ['Version', text(baseline.version)],
      ['Summary', text(baseline.summary)],
      ['Description', text(baseline.description)],
      ['Maintainer', text(baseline.maintainer)],
      ['License', text(baseline.license)],
      ['Copyright', text(baseline.copyright)],
      ['Status message', text(baseline.statusMessage)],
    ];
    const factCount = countFacts(facts);
    if (factCount > 0) {
      const details = this.openFold('', '', this.detailHeading, 'Baseline details', 'the baseline details', factCount);
      this.definitionList(facts);
      this.closeFold(details);
    }
    this.externalReferences(this.detailHeading, 'Enrichment and External References', baseline.externalReferences);
    if (requirements.length > 0) {
      this.line(
        '<div class="req-head" aria-hidden="true"><span>Status</span><span>ID</span><span>Severity</span>' +
          '<span>Title</span><span>800-53 Controls &amp; CCIs</span></div>',
      );
    }
    for (const req of requirements) this.requirement(req);
    this.closeFold(f);
  }

  private requirement(req: Json): void {
    const effective = this.effectiveStatus(req);
    const results = list(req.results).map(obj);
    const severity = requirementSeverity(req);
    const tags = obj(req.tags);
    const nist = tagItems(tags, 'nist');
    const cci = tagItems(tags, 'cci');

    const [cls] = statusPresentation(effective);
    this.requirements++;
    const id = `req-${this.requirements}`;
    // Each requirement is independently meaningful, so it is an article holding
    // one disclosure rather than a bare disclosure.
    this.line(`<article class="requirement c-${cls}" data-status="${cls}" id="${id}">`);
    this.line('<details>');
    const referenceCount = list(req.externalReferences).length;
    const tagHtml =
      [...nist, ...cci]
        .map((t, i) => `${i === 0 ? '<span class="vh">Controls: </span>' : ''}<span class="tag">${escapeHtml(t)}</span>`)
        .join('') + (referenceCount > 0 ? `<span class="tag enriched">Enriched (${referenceCount})</span>` : '');
    this.line(
      `<summary>${statusBadge(effective)}<span class="req-id">${escapeHtml(text(req.id))}</span>` +
        `<span class="sev c-${severityClass(severity)}"><span class="vh">Severity: </span>${escapeHtml(severityLabel(severity))}</span>` +
        `<span class="req-title">${escapeHtml(text(req.title))}</span><span class="tags">${tagHtml}</span></summary>`,
    );
    this.line('<div class="req-body">');

    // The first default description leads the body; every other one is a detail row.
    const descriptions = list(req.descriptions).map(obj);
    const lead = descriptions.findIndex((d) => d.label === 'default');
    const location = sourceLocation(req.sourceLocation);
    if (location !== '') {
      this.line(`<p class="location"><span class="k">Location</span><code>${escapeHtml(location)}</code></p>`);
    }
    const leadText = lead >= 0 ? text(descriptions[lead]!.data) : '';
    if (leadText !== '' && isLongText(leadText)) {
      const f = this.openFold('', '', this.detailHeading, 'Description', 'the description', lineCount(leadText));
      this.line(prose(leadText));
      this.closeFold(f);
    } else if (leadText !== '') {
      this.line(prose(leadText));
    }

    this.resultRows(results);

    const impact = numeric(req.impact);
    const rows = [
      detailRow('Effective status', statusBadge(effective)),
      detailRow('Assessed status', statusBadge(worstStatus(results.map((r) => text(r.status))))),
    ];
    const details: Pair[] = [
      ['Control', text(req.id)],
      ['Title', text(req.title)],
      ['Severity', severity],
      ['Impact', impact.toFixed(2)],
      ['Effective impact', typeof req.effectiveImpact === 'number' ? req.effectiveImpact.toFixed(2) : ''],
      ['Disposition', text(req.disposition)],
      ['Control type', text(req.controlType)],
      ['Verification method', text(req.verificationMethod)],
      ['Applicability', text(req.applicability)],
      ['Source location', location],
      ['NIST Controls', nist.join(', ')],
      ['CCI Controls', cci.join(', ')],
      ['CWE', strings(req.cwe).join(', ')],
      ['CVSS', cvssText(list(req.cvss).map(obj))],
      ['EPSS', epssText(req.epss)],
      ['KEV', kevText(req.kev)],
      ['Affected packages', packagesText(list(req.affectedPackages).map(obj))],
      ['Evidence', evidenceText(list(req.evidence).map(obj))],
    ];
    for (const [term, value] of details) {
      if (value !== '') rows.push(detailRow(term, escapeHtml(value)));
    }
    const references = referenceLines(list(req.refs).map(obj));
    if (references.length > 0) {
      rows.push(detailRow('References', prose(references.join('\n'))));
    }
    descriptions.forEach((d, i) => {
      if (i !== lead) rows.push(detailRow(escapeHtml(descriptionHeading(text(d.label))), prose(text(d.data))));
    });
    const detailsFold = this.openFold('', '', this.detailHeading, 'Result Details', 'the result details', rows.length);
    this.line('<div class="table-wrap">');
    this.line('<table class="details" aria-label="Result details">');
    this.line('<tbody>');
    for (const row of rows) this.line(row);
    this.line('</tbody>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(detailsFold);

    this.tagChips(tags);
    this.externalReferences(this.detailHeading, 'Enrichment and External References', req.externalReferences);
    const overrides = list(req.statusOverrides).map(obj);
    this.overrideRows(overrides);
    overrides.forEach((o, i) =>
      this.externalReferences(this.detailHeading, `References for override ${i + 1}`, o.externalReferences),
    );
    this.poamRows(list(req.poams).map(obj));

    const code = text(req.code);
    if (this.reportType === 'administrator' && code !== '') {
      const f = this.openFold('', '', this.detailHeading, 'Code', 'the code', lineCount(code));
      this.line(`<pre class="code">\n${escapeHtml(code)}</pre>`);
      this.closeFold(f);
    }
    this.line(`<p class="to-top"><a href="#${id}">Back to the top of this requirement</a></p>`);
    this.line('</div>');
    this.line('</details>');
    this.line('</article>');
  }

  private resultRows(results: Json[]): void {
    if (results.length === 0) return;
    const f = this.openFold('', '', this.detailHeading, 'Test Results', 'the test results', results.length);
    this.line('<div class="table-wrap">');
    this.line('<table aria-label="Test results">');
    this.line(
      '<thead><tr><th scope="col">Status</th><th scope="col">Test</th><th scope="col">Result</th>' +
        '<th scope="col">Started</th></tr></thead>',
    );
    this.line('<tbody>');
    for (const res of results) {
      const runTime = typeof res.runTime === 'number' ? `${res.runTime.toFixed(3)} s` : '';
      this.line(
        `<tr><td>${statusBadge(text(res.status))}</td><td class="text">${escapeHtml(text(res.codeDesc))}` +
          subLine('Resource', joinNonEmpty(' \u00b7 ', text(res.resource), text(res.resourceId))) +
          `</td><td class="text">${escapeHtml(text(res.message))}` +
          subLine('Exception', text(res.exception)) +
          subLine('Backtrace', strings(res.backtrace).join('\n')) +
          `</td><td>${escapeHtml(formatTime(res.startTime))}${subLine('Run time', runTime)}</td></tr>`,
      );
    }
    this.line('</tbody>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(f);
  }

  private overrideRows(overrides: Json[]): void {
    if (overrides.length === 0) return;
    const governing = governingStatusOverrideIndex(overrideInputs(overrides), this.src.ref.stamp);

    const f = this.openFold('', '', this.detailHeading, 'Overrides', 'the overrides', overrides.length);
    this.line('<div class="table-wrap">');
    this.line('<table aria-label="Overrides">');
    this.line(
      '<thead><tr><th scope="col">Type</th><th scope="col">Status</th><th scope="col">Reason</th>' +
        '<th scope="col">Applied by</th><th scope="col">Applied at</th><th scope="col">Expires at</th>' +
        '<th scope="col">State</th></tr></thead>',
    );
    this.line('<tbody>');
    overrides.forEach((o, i) => {
      const status = text(o.status) === '' ? '' : statusBadge(text(o.status));
      const expires = toDate(o.expiresAt);
      let state = '';
      if (i === governing) {
        state = 'governing';
      } else if (expires && expires <= this.src.ref.date) {
        state = 'expired';
      }
      const impact = o.impact == null ? '' : numeric(obj(o.impact).value).toFixed(2);
      this.line(
        `<tr><td>${escapeHtml(text(o.type))}</td><td>${status}${subLine('Impact', impact)}` +
          subLine('CVSS', o.cvss == null ? '' : cvssText([obj(o.cvss)])) +
          `</td><td class="text">${escapeHtml(text(o.reason))}${subLine('Justification', text(o.justification))}` +
          `</td><td>${escapeHtml(text(obj(o.appliedBy).identifier))}</td><td>${escapeHtml(formatTime(o.appliedAt))}` +
          `</td><td>${escapeHtml(formatTime(o.expiresAt))}</td><td>${state}</td></tr>`,
      );
    });
    this.line('</tbody>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(f);
  }

  /**
   * References to artifacts outside the document: a CVE, an ATT&CK technique, a
   * STIX object. A reference that embeds its payload is an enrichment envelope,
   * and the payload is shown whole because HDF carries it untouched rather than
   * mapping it into fields.
   */
  private externalReferences(headingTag: 'h3' | 'h4' | 'h5', heading: string, value: unknown): void {
    const refs = list(value).map(obj);
    if (refs.length === 0) return;
    const f = this.openFold('', '', headingTag, heading, heading.charAt(0).toLowerCase() + heading.slice(1), refs.length);
    this.line('<div class="table-wrap">');
    this.line(`<table aria-label="${heading}">`);
    this.line(
      '<thead><tr><th scope="col">Source</th><th scope="col">ID</th><th scope="col">Kind</th>' +
        '<th scope="col">Relation</th><th scope="col">Detail</th></tr></thead>',
    );
    this.line('<tbody>');
    for (const ref of refs) {
      const checksum = ref.checksum == null ? {} : obj(ref.checksum);
      const added = joinNonEmpty(
        ' \u00b7 ',
        ref.addedBy == null ? '' : text(obj(ref.addedBy).identifier),
        formatTime(ref.addedAt),
      );
      this.line(
        `<tr><td>${escapeHtml(text(ref.sourceName))}</td><td>${escapeHtml(text(ref.externalId))}</td><td>` +
          `${escapeHtml(text(ref.kind))}</td><td>${escapeHtml(text(ref.rel))}</td><td class="text">` +
          escapeHtml(text(ref.description)) +
          subLine('Location', text(ref.href)) +
          subLine('Media type', text(ref.mediaType)) +
          subLine('Checksum', joinNonEmpty(':', text(checksum.algorithm), text(checksum.value))) +
          subLine('Added', added) +
          embeddedDocument(ref.document) +
          '</td></tr>',
      );
    }
    this.line('</tbody>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(f);
  }

  private poamRows(poams: Json[]): void {
    if (poams.length === 0) return;
    const f = this.openFold('', '', this.detailHeading, 'POA&amp;Ms', 'the POA&Ms', poams.length);
    this.line('<div class="table-wrap">');
    this.line('<table aria-label="Plans of action and milestones">');
    this.line(
      '<thead><tr><th scope="col">Type</th><th scope="col">Explanation</th><th scope="col">Applied by</th>' +
        '<th scope="col">Applied at</th><th scope="col">Expires at</th></tr></thead>',
    );
    this.line('<tbody>');
    for (const p of poams) {
      const milestones = list(p.milestones)
        .map(obj)
        .map((m) =>
          subLine(
            'Milestone',
            joinNonEmpty(' \u00b7 ', text(m.status), text(m.title), text(m.description), formatTime(m.estimatedCompletion)),
          ),
        )
        .join('');
      this.line(
        `<tr><td>${escapeHtml(text(p.type))}</td><td class="text">${escapeHtml(text(p.explanation))}${milestones}` +
          `</td><td>${escapeHtml(text(obj(p.appliedBy).identifier))}</td><td>${escapeHtml(formatTime(p.appliedAt))}` +
          `</td><td>${escapeHtml(formatTime(p.expiresAt))}</td></tr>`,
      );
    }
    this.line('</tbody>');
    this.line('</table>');
    this.line('</div>');
    this.closeFold(f);
  }

  /**
   * The tags the detail table does not show: every tag but nist and cci whose
   * value is text, a list of text, or a boolean. Numbers and nested values are
   * left out because the two languages do not print them alike.
   */
  private tagChips(tags: Json): void {
    const entries: Array<readonly [string, string]> = [];
    for (const key of Object.keys(tags).sort(byCodePoint)) {
      if (key === 'nist' || key === 'cci') continue;
      const value = tagText(tags[key]);
      if (value !== null) entries.push([key, value]);
    }
    if (entries.length === 0) return;

    const f = this.openFold('', '', this.detailHeading, 'Tags', 'the tags', entries.length);
    this.line('<ul class="chips">');
    for (const [k, v] of entries) {
      this.line(`<li><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(v)}</span></li>`);
    }
    this.line('</ul>');
    this.closeFold(f);
  }
}

/**
 * Counts the external references anywhere in the document and breaks them down
 * by kind, so even the executive report says whether the results carry
 * enrichment.
 */
function referenceCensus(doc: Json): string {
  let total = 0;
  const kinds = new Map<string, number>();
  const count = (value: unknown): void => {
    for (const ref of list(value).map(obj)) {
      total++;
      const kind = text(ref.kind);
      if (kind !== '') kinds.set(kind, (kinds.get(kind) ?? 0) + 1);
    }
  };
  count(doc.externalReferences);
  for (const baseline of list(doc.baselines).map(obj)) {
    count(baseline.externalReferences);
    for (const req of list(baseline.requirements).map(obj)) {
      count(req.externalReferences);
      for (const o of list(req.statusOverrides).map(obj)) count(o.externalReferences);
    }
  }
  if (total === 0) return '';
  const parts = [...kinds.keys()].sort(byCodePoint).map((kind) => `${kind} ${kinds.get(kind)}`);
  return parts.length === 0 ? String(total) : `${total} (${parts.join(', ')})`;
}

/**
 * An enrichment payload: what it says it is, then the whole object. Canonical
 * JSON is what makes the text the same in both languages.
 */
function embeddedDocument(value: unknown): string {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return '';
  const document = value as Json;
  return (
    subLine('Embedded', joinNonEmpty(' \u00b7 ', text(document.type), text(document.name))) +
    '<details class="doc"><summary>Embedded document</summary><pre class="code">\n' +
    `${escapeHtml(indentJson(canonicalJson(document)))}</pre></details>`
  );
}

/**
 * Lays compact JSON out over lines, two spaces a level. It only inserts
 * whitespace between tokens, so the values stay exactly as serialized.
 */
export function indentJson(compact: string): string {
  let out = '';
  let depth = 0;
  const newline = (): string => `\n${'  '.repeat(depth)}`;
  let i = 0;
  while (i < compact.length) {
    const c = compact[i]!;
    const next = compact[i + 1];
    let end = i + 1;
    if (c === '"') {
      end = stringEnd(compact, i);
      out += compact.slice(i, end);
    } else if ((c === '{' || c === '[') && (next === '}' || next === ']')) {
      end = i + 2;
      out += c + next;
    } else if (c === '{' || c === '[') {
      depth++;
      out += c + newline();
    } else if (c === '}' || c === ']') {
      depth--;
      out += newline() + c;
    } else if (c === ',') {
      out += c + newline();
    } else {
      out += c === ':' ? ': ' : c;
    }
    i = end;
  }
  return out;
}

/** The index just past the JSON string that opens at `start`; the end of the text when it never closes. */
function stringEnd(text: string, start: number): number {
  let i = start + 1;
  while (i < text.length) {
    if (text[i] === '"') return i + 1;
    i += text[i] === '\\' ? 2 : 1;
  }
  return text.length;
}

function strings(value: unknown): string[] {
  return list(value).filter((item): item is string => typeof item === 'string');
}

function tagText(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    const items = strings(value);
    return items.length > 0 ? items.join(', ') : null;
  }
  return null;
}

/** A labelled secondary line inside a table cell; empty when there is nothing to say. */
function subLine(label: string, value: string): string {
  return value === '' ? '' : `<span class="sub"><span class="k">${label}</span> ${escapeHtml(value)}</span>`;
}

/** Where the finding sits in the assessed source: file, and line when there is one. */
export function sourceLocation(value: unknown): string {
  if (value == null) return '';
  const loc = obj(value);
  const ref = text(loc.ref);
  if (typeof loc.line !== 'number') return ref;
  return ref === '' ? `line ${loc.line}` : `${ref}:${loc.line}`;
}

function cvssText(entries: Json[]): string {
  const parts: string[] = [];
  for (const c of entries) {
    const score = typeof c.computedScore === 'number' ? c.computedScore : c.baseScore;
    const severity = typeof c.computedSeverity === 'string' ? c.computedSeverity : text(c.baseSeverity);
    const version = text(c.version);
    const source = text(c.source);
    const part = joinNonEmpty(
      ' ',
      version === '' ? '' : `v${version}`,
      typeof score === 'number' ? score.toFixed(1) : '',
      severity,
      text(c.baseVector),
      source === '' ? '' : `(${source})`,
    );
    if (part !== '') parts.push(part);
  }
  return parts.join('; ');
}

function epssText(value: unknown): string {
  if (value == null) return '';
  const e = obj(value);
  const date = text(e.date);
  return (
    `score ${numeric(e.score).toFixed(5)}, percentile ${numeric(e.percentile).toFixed(5)}` +
    (date === '' ? '' : `, as of ${date}`)
  );
}

function kevText(value: unknown): string {
  if (value == null) return '';
  const k = obj(value);
  let out = k.inKev === true ? 'Listed' : 'Not listed';
  if (text(k.dateAdded) !== '') out += `, added ${text(k.dateAdded)}`;
  if (text(k.dueDate) !== '') out += `, due ${text(k.dueDate)}`;
  if (text(k.notes) !== '') out += `, ${text(k.notes)}`;
  return out;
}

function packagesText(packages: Json[]): string {
  const parts: string[] = [];
  for (const p of packages) {
    let part = joinNonEmpty(' ', text(p.name), text(p.version));
    if (part === '') part = joinNonEmpty(' ', text(p.purl), text(p.cpe));
    const fixed = text(p.fixedInVersion);
    if (fixed !== '') part = joinNonEmpty(' ', part, `(fixed in ${fixed})`);
    if (part !== '') parts.push(part);
  }
  return parts.join('; ');
}

function evidenceText(evidence: Json[]): string {
  return evidence
    .map((e) => joinNonEmpty(': ', text(e.type), text(e.description)))
    .filter((part) => part !== '')
    .join('; ');
}

/**
 * Each reference's text. A structured ref is reduced to the URLs inside it,
 * sorted, because the Go peer decodes it to a map, which has no order to
 * preserve.
 */
function referenceLines(refs: Json[]): string[] {
  const lines: string[] = [];
  for (const ref of refs) {
    if (typeof ref.ref === 'string') {
      if (ref.ref !== '') lines.push(ref.ref);
    } else if (Array.isArray(ref.ref)) {
      const urls = new Set<string>();
      collectUrls(ref.ref, urls);
      lines.push(...[...urls].sort(byCodePoint));
    }
    for (const s of [text(ref.url), text(ref.uri)]) {
      if (s !== '') lines.push(s);
    }
  }
  return lines;
}

function collectUrls(value: unknown, into: Set<string>): void {
  if (Array.isArray(value)) {
    for (const child of value) collectUrls(child, into);
  } else if (typeof value === 'object' && value !== null) {
    for (const [k, child] of Object.entries(value)) {
      if (k === 'url' && typeof child === 'string' && child !== '') into.add(child);
      else collectUrls(child, into);
    }
  }
}

/** Component fields in display order; the second member is the JSON key. */
const COMPONENT_FIELDS: ReadonlyArray<readonly [string, string]> = [
  ['Component ID', 'componentId'],
  ['Description', 'description'],
  ['Hostname', 'hostname'],
  ['FQDN', 'fqdn'],
  ['Domain', 'domain'],
  ['IP address', 'ipAddress'],
  ['MAC address', 'macAddress'],
  ['OS name', 'osName'],
  ['OS version', 'osVersion'],
  ['Image ID', 'imageId'],
  ['Registry', 'registry'],
  ['Repository', 'repository'],
  ['Tag', 'tag'],
  ['Container ID', 'containerId'],
  ['Image', 'image'],
  ['Runtime', 'runtime'],
  ['Cluster name', 'clusterName'],
  ['Namespace', 'namespace'],
  ['Platform type', 'platformType'],
  ['Version', 'version'],
  ['Account ID', 'accountId'],
  ['Provider', 'provider'],
  ['Region', 'region'],
  ['ARN', 'arn'],
  ['Resource ID', 'resourceId'],
  ['Resource type', 'resourceType'],
  ['Branch', 'branch'],
  ['Commit', 'commit'],
  ['URL', 'url'],
  ['Environment', 'environment'],
  ['Package manager', 'packageManager'],
  ['Package name', 'packageName'],
  ['CIDR', 'cidr'],
  ['Gateway', 'gateway'],
  ['Engine', 'engine'],
  ['Host', 'host'],
  ['Port', 'port'],
  ['Model ID', 'modelId'],
  ['Dataset ID', 'datasetId'],
  ['Owner', 'owner'],
];

function identity(value: unknown): string {
  if (value == null) return '';
  const id = obj(value);
  const type = text(id.type);
  if (type === '') return text(id.identifier);
  return joinNonEmpty(' ', text(id.identifier), `(${type})`);
}

/** A summary table row; `name` is already HTML. */
function summaryRow(name: string, c: StatusCounts): string {
  const cells = [c.passed.total, c.failed.total, c.skipped.total, c.noImpact.total, c.error.total, countTotal(c)]
    .map((n) => `<td>${n}</td>`)
    .join('');
  return `<tr><th scope="row">${name}</th>${cells}<td>${compliance(c)}</td></tr>`;
}

function summaryHead(first: string): string {
  return (
    `<thead><tr><th scope="col">${first}</th><th scope="col">Passed</th><th scope="col">Failed</th>` +
    '<th scope="col">Not Reviewed</th><th scope="col">Not Applicable</th><th scope="col">Error</th>' +
    '<th scope="col">Total</th><th scope="col">Compliance</th></tr></thead>'
  );
}

function sourceId(i: number): string {
  return `source-${i + 1}`;
}

function componentField(c: Json, term: string, key: string): Pair {
  if (key === 'port') return [term, typeof c.port === 'number' ? String(c.port) : ''];
  if (key === 'owner') return [term, identity(c.owner)];
  return [term, text(c[key])];
}

function documentFacts(doc: Json): Pair[] {
  const tool = obj(doc.tool);
  const generator = obj(doc.generator);
  const duration = obj(doc.statistics).duration;
  return [
    ['Tool', joinNonEmpty(' ', text(tool.name), text(tool.version))],
    ['Tool format', text(tool.format)],
    ['Generator', joinNonEmpty(' ', text(generator.name), text(generator.version))],
    ['Assessed', formatTime(doc.timestamp)],
    ['Duration', typeof duration === 'number' ? `${duration.toFixed(2)} s` : ''],
    ['System reference', text(doc.systemRef)],
    ['Plan reference', text(doc.planRef)],
    ['Document ID', text(doc.id)],
    ['External references', referenceCensus(doc)],
  ];
}

function runnerFacts(runner: Json): Pair[] {
  return [
    ['Name', text(runner.name)],
    ['Hostname', text(runner.hostname)],
    ['FQDN', text(runner.fqdn)],
    ['Domain', text(runner.domain)],
    ['Architecture', text(runner.architecture)],
    ['Release', text(runner.release)],
    ['Container image', text(runner.containerImage)],
    ['Container ID', text(runner.containerId)],
    ['Operator', identity(runner.operator)],
  ];
}

const STATUS_PRESENTATION: Record<string, readonly [cls: string, label: string]> = {
  passed: ['passed', 'Passed'],
  failed: ['failed', 'Failed'],
  notReviewed: ['not-reviewed', 'Not Reviewed'],
  notApplicable: ['not-applicable', 'Not Applicable'],
  error: ['error', 'Error'],
};

/** A status with a class drawn from a fixed set, never from the document: one outside the enum is shown as text under one class. */
function statusPresentation(status: string): readonly [cls: string, label: string] {
  return Object.prototype.hasOwnProperty.call(STATUS_PRESENTATION, status)
    ? STATUS_PRESENTATION[status]!
    : ['unknown', status];
}

/**
 * The mark beside the status word. Colour is the least reliable of the three
 * channels — it is lost to colour-vision deficiency and to a greyscale printer —
 * so every status carries a shape and a word as well.
 */
const STATUS_ICON: Record<string, string> = {
  passed: '✓',
  failed: '✗',
  'not-applicable': '–',
  'not-reviewed': '?',
  error: '!',
};

export function statusIcon(cls: string): string {
  return Object.prototype.hasOwnProperty.call(STATUS_ICON, cls) ? STATUS_ICON[cls]! : '·';
}

export function statusBadge(status: string): string {
  const [cls, label] = statusPresentation(status);
  return `<span class="status c-${cls}"><span class="ico" aria-hidden="true">${statusIcon(cls)}</span>${escapeHtml(label)}</span>`;
}

/** The string members of an array-valued tag; a bare string tag is a one-member list. */
export function tagItems(tags: Json, key: string): string[] {
  const value = Object.prototype.hasOwnProperty.call(tags, key) ? tags[key] : undefined;
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  return [];
}

function joinNonEmpty(sep: string, ...parts: string[]): string {
  return parts.filter((p) => p !== '').join(sep);
}

/**
 * Makes text safe as HTML content and inside a double-quoted attribute. A
 * carriage return is written as a character reference because a parser would
 * otherwise fold it into the following newline. Characters HTML cannot carry at
 * all, and unpaired surrogates, become U+FFFD.
 */
export function escapeHtml(value: string): string {
  let out = '';
  for (const ch of value) {
    const c = ch.codePointAt(0)!;
    if (ch === '&') out += '&amp;';
    else if (ch === '<') out += '&lt;';
    else if (ch === '>') out += '&gt;';
    else if (ch === '"') out += '&quot;';
    else if (ch === "'") out += '&#39;';
    else if (ch === '\r') out += '&#13;';
    else if (ch === '\t' || ch === '\n') out += ch;
    else if (c < 0x20 || c === 0x7f || c === 0xfffe || c === 0xffff || (c >= 0xd800 && c <= 0xdfff)) out += '\ufffd';
    else out += ch;
  }
  return out;
}
