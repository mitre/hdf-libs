import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { REPORT_CSS, SCRIPT, SCRIPT_HASH, STYLESHEET } from './assets.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { results as sharedResults } from '@mitre/hdf-fixtures';
import { resultsCorpus } from '../../../shared/typescript/schema-corpus.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import type { SeverityCounts } from '@mitre/hdf-engine';
import { byCodePoint } from '../../../shared/typescript/exportmap.js';
import {
  compliance,
  convertHdfDocumentsToHtml,
  convertHdfToHtml,
  descriptionHeading,
  escapeHtml,
  indentJson,
  isLongText,
  parseReportType,
  severityClass,
  severityLabel,
  sourceLocation,
  statusBadge,
  statusIcon,
  tagItems,
} from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');
const FAR_FUTURE = '2099-12-31T00:00:00Z';
/** The value a Go marshal writes for an unset time, which the legacy converters leave in expiresAt to mean "no expiry". */
const GO_ZERO_TIME = '0001-01-01T00:00:00Z';
const REPORT_TYPES = ['executive', 'manager', 'administrator'] as const;

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

type Doc = Record<string, unknown>;

function render(doc: unknown, reportType?: string): string {
  return convertHdfToHtml(JSON.stringify(doc), { reportType });
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

function richDoc(): Doc {
  const doc = testhdf.doc(
    testhdf.baseline(
      'rhel9-stig',
      testhdf.req('SV-257777', {
        title: 'Vendor support',
        impact: 0.7,
        status: 'failed',
        code: "describe file('/etc/x') do\n  it { should exist }\nend",
        tags: { nist: ['CM-6', 'SI-2'], cci: ['CCI-000366'] },
      }),
      testhdf.req('SV-257778', { title: 'Banner', impact: 0.5, status: 'passed' }),
    ),
  ) as unknown as Doc;
  doc.timestamp = '2020-01-01T00:00:00Z';
  doc.systemRef = 'systems/portal.hdf-system.json';
  doc.planRef = 'plans/q3.hdf-plan.json';
  doc.tool = { name: 'InSpec', version: '5.22.3' };
  doc.generator = { name: 'hdf-converters', version: '3.7.1' };
  doc.runner = { name: 'ci-runner-07', hostname: 'runner07', architecture: 'x86_64' };
  doc.components = [
    {
      name: 'web01',
      type: 'host',
      componentId: '3f2504e0-4f89-11d3-9a0c-0305e82c3301',
      fqdn: 'web01.prod.example.com',
      labels: { system: 'Portal', environment: 'production' },
      externalIds: { cmdb: 'CI0012345', aws: 'i-0abc123def456789' },
    },
    { name: 'db01', type: 'host', componentId: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', externalIds: { emass: '1234' } },
    { name: 'registry.example.com/portal:1.4', type: 'containerImage' },
  ];
  return doc;
}

/** One failed requirement waived to passed, assessed at 2020-01-01. */
function waived(expiresAt: string): Doc {
  const req = testhdf.req('V-1', { title: 'Waived control', impact: 0.7, status: 'failed' }) as unknown as Doc;
  req.statusOverrides = [
    {
      type: 'waiver',
      status: 'passed',
      reason: 'Compensating control in place',
      appliedBy: { type: 'email', identifier: 'issm@example.gov' },
      appliedAt: '2019-06-01T00:00:00Z',
      expiresAt,
    },
  ];
  const doc = testhdf.results(req as never) as unknown as Doc;
  doc.timestamp = '2020-01-01T00:00:00Z';
  return doc;
}

const ELEMENTS_THAT_LOAD = ['<link', '<img', '<iframe', '<object', '<embed', '<video', '<audio', '<source',
  '<form', '<base', '<svg', '<meta http-equiv="refresh"'];
const TAG = /<[^<>]*>/g;
const STYLE_BLOCK = /<style>([\s\S]*?)<\/style>/gi;
// CSS reaches the network through url() and nothing else.
const CSS_URL = /url\(\s*["']?([^"')]*)/g;
const LOADING_ATTRIBUTE = /\s(src|srcset|data|action|formaction|poster|background|on[a-z]+)\s*=/;
const HREF_ATTRIBUTE = /\shref\s*=\s*"([^"]*)"/g;
const STYLE_ATTRIBUTE = /\sstyle\s*=\s*"([^"]*)"/g;
// The only inline styles are the counts and the percentage the stylesheet draws from.
const NUMERIC_STYLE = /^--(n|pct):\d+(\.\d+)?$/;
const SCRIPT_BLOCK = /<script>([\s\S]*?)<\/script>/gi;

/**
 * The report can neither fetch anything nor run anything but its own static
 * script, which the content security policy pins by hash.
 */
function expectSelfContained(out: string, wantScript: boolean): void {
  // <style> and <script> hold raw text rather than markup — the vendored
  // stylesheet carries a "<" in a media query — so the markup checks run on the
  // document with their content removed, and the CSS is checked as CSS.
  const markup = out.replace(STYLE_BLOCK, '<style></style>').replace(SCRIPT_BLOCK, '<script></script>');
  const lower = markup.toLowerCase();
  for (const forbidden of ELEMENTS_THAT_LOAD) {
    expect(lower, `the report must not contain ${forbidden}`).not.toContain(forbidden);
  }
  for (const tag of markup.match(TAG) ?? []) {
    expect(tag.toLowerCase(), 'no tag may load or run anything').not.toMatch(LOADING_ATTRIBUTE);
    for (const m of tag.matchAll(HREF_ATTRIBUTE)) {
      expect(m[1]!.startsWith('#'), `href ${m[1]} must stay inside the page`).toBe(true);
    }
    for (const m of tag.matchAll(STYLE_ATTRIBUTE)) {
      expect(m[1], 'an inline style may only carry a number').toMatch(NUMERIC_STYLE);
    }
  }
  const styles = [...out.matchAll(STYLE_BLOCK)];
  expect(styles, 'exactly one stylesheet, inline').toHaveLength(1);
  expect((out.match(/<style/gi) ?? []).length, 'the stylesheet is inline and attribute-free').toBe(1);
  const css = styles[0]![1]!;
  expect(css).not.toContain('@import');
  expect(css).not.toContain('image-set(');
  for (const m of css.matchAll(CSS_URL)) {
    expect(m[1]!.startsWith('data:'), `url(${m[1]}) must carry its own payload`).toBe(true);
  }

  let policy = "default-src 'none'; style-src 'unsafe-inline'";
  const scripts = [...out.matchAll(SCRIPT_BLOCK)];
  expect(scripts.length, 'every script is inline and attribute-free').toBe((out.match(/<script/gi) ?? []).length);
  if (wantScript) {
    expect(scripts).toHaveLength(1);
    policy += `; script-src 'sha256-${createHash('sha256').update(scripts[0]![1]!, 'utf-8').digest('base64')}'`;
  } else {
    expect(scripts).toHaveLength(0);
  }
  expect(out).toContain(`<meta http-equiv="Content-Security-Policy" content="${policy}" />`);
}

function chip(key: string, value: string): string {
  return `<li><span class="k">${key}</span><span class="v">${value}</span></li>`;
}

function detail(heading: string, value: string): string {
  return `<tr><th scope="row">${heading}</th><td>${value}</td></tr>`;
}

function badge(cls: string, label: string): string {
  return `<span class="status c-${cls}"><span class="ico" aria-hidden="true">${statusIcon(cls)}</span>${label}</span>`;
}

function summaryRow(name: string, ...cells: string[]): string {
  const columns = cells.map((c) => '<td>' + c + '</td>').join('');
  return `<tr><th scope="row">${name}</th>${columns}</tr>`;
}

/** The Status-by-baseline table alone, so a label assertion cannot be satisfied by the same text appearing elsewhere. */
function statusByBaselineTable(html: string): string {
  const start = html.indexOf('<table class="summary" aria-label="Status by baseline">');
  expect(start, 'the report must carry a Status-by-baseline table').toBeGreaterThanOrEqual(0);
  const end = html.indexOf('</table>', start);
  expect(end).toBeGreaterThanOrEqual(0);
  return html.slice(start, end);
}

const SUMMARY_ROW_LABEL = /<tr><th scope="row">(.*?)<\/th>/g;

function summaryRowLabels(table: string): string[] {
  return [...table.matchAll(SUMMARY_ROW_LABEL)].map((m) => m[1]!);
}

const COMPONENT_SUMMARY = /<details class="fold component"[^>]*>\n(<summary>.*?<\/summary>)/g;

function componentSummaries(html: string): string[] {
  return [...html.matchAll(COMPONENT_SUMMARY)].map((m) => m[1]!);
}

describe('hdf-to-html converter', () => {
  it('shows every component with its identity, labels and external ids', () => {
    const doc = richDoc();
    expectValidResults(doc as never);
    const out = render(doc);

    expect(count(out, '<details class="fold component"')).toBe(3);
    for (const want of [
      'web01', 'db01', 'registry.example.com/portal:1.4', 'containerImage',
      '3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', 'web01.prod.example.com',
      chip('environment', 'production'), chip('system', 'Portal'),
      chip('aws', 'i-0abc123def456789'), chip('cmdb', 'CI0012345'), chip('emass', '1234'),
    ]) {
      expect(out).toContain(want);
    }
    expect(out.indexOf('<span class="k">aws</span>')).toBeLessThan(out.indexOf('<span class="k">cmdb</span>'));
  });

  it('shows the document context in every report type', () => {
    const out = render(richDoc(), 'executive');
    for (const want of [
      'systems/portal.hdf-system.json', 'plans/q3.hdf-plan.json', 'InSpec 5.22.3', 'hdf-converters 3.7.1',
      '2020-01-01T00:00:00Z', 'ci-runner-07', 'runner07', 'x86_64',
    ]) {
      expect(out).toContain(want);
    }
  });

  it('adds detail with each report type', () => {
    const doc = richDoc();
    const executive = render(doc, 'executive');
    const manager = render(doc, 'Manager');
    const administrator = render(doc, 'ADMINISTRATOR');

    for (const out of [executive, manager, administrator]) {
      expect(out).toContain('rhel9-stig');
      expect(out).toContain('50.00%');
    }
    expect(executive).not.toContain('SV-257777');
    expect(manager).toContain('SV-257777');
    expect(manager).toContain('Vendor support');
    expect(manager).not.toContain('should exist');
    expect(administrator).toContain('describe file(&#39;/etc/x&#39;) do\n  it { should exist }\nend');

    expect(executive).toContain('Report type: Executive');
    expect(manager).toContain('Report type: Manager');
    expect(administrator).toContain('Report type: Administrator');
    expect(render(doc)).toBe(administrator);
  });

  it('parses report types and rejects unknown ones', () => {
    expect(parseReportType(undefined)).toBe('administrator');
    expect(parseReportType(null)).toBe('administrator');
    expect(parseReportType('')).toBe('administrator');
    expect(parseReportType(' manager ')).toBe('manager');
    expect(parseReportType('Executive')).toBe('executive');
    expect(() => parseReportType('auditor')).toThrow(/"auditor".*executive, manager, administrator/);
    expect(() => convertHdfToHtml('{"baselines":[]}', { reportType: 'auditor' })).toThrow(/^hdf-to-html: unknown report type/);
  });

  it('shows the effective status beside the assessed one, with the override', () => {
    const doc = waived(FAR_FUTURE);
    expectValidResults(doc as never);
    const out = render(doc, 'manager');

    expect(out).toContain(detail('Effective status', badge('passed', 'Passed')));
    expect(out).toContain(detail('Assessed status', badge('failed', 'Failed')));
    for (const want of ['waiver', 'Compensating control in place', 'issm@example.gov', '2019-06-01T00:00:00Z', FAR_FUTURE, 'governing']) {
      expect(out).toContain(want);
    }
    expect(out).toContain('100.00%');
    expect(out).toContain('<span class="lbl">Passed</span><span class="sub">0 individual checks passed</span>');
    expect(out).toContain('Effective status evaluated as of 2020-01-01T00:00:00Z');
  });

  // An override is judged against the document's own assessment time, never the
  // wall clock, so a report rendered next year is the report rendered today.
  it('judges override expiry at the assessment time', () => {
    const expired = render(waived('2019-12-31T00:00:00Z'), 'manager');
    expect(expired).toContain(detail('Effective status', badge('failed', 'Failed')));
    expect(expired).toContain('0.00%');
    expect(expired).toContain('<td>expired</td>');

    // Expired by the wall clock, still in force when the assessment ran.
    const inForceThen = render(waived('2020-06-01T00:00:00Z'), 'manager');
    expect(inForceThen).toContain(detail('Effective status', badge('passed', 'Passed')));
  });

  // Parity: TestConvertHDFToHTML_ImpactOverrideExpiryIsJudgedAtAssessmentTime.
  it('judges an impact override at the assessment time, as it does a status override', () => {
    const adjusted = (expiresAt: string): Doc => {
      const doc = JSON.parse(JSON.stringify(waived(expiresAt))) as Doc;
      const req = ((doc.baselines as Doc[])[0]!.requirements as Doc[])[0]!;
      req.impact = 0.9;
      req.statusOverrides = [
        {
          type: 'riskAdjustment',
          reason: 'Compensating control reduces exposure',
          appliedBy: { type: 'email', identifier: 'issm@example.gov' },
          appliedAt: '2019-06-01T00:00:00Z',
          expiresAt,
          impact: { value: 0.1 },
        },
      ];
      return doc;
    };
    // Expired by the wall clock, in force when the assessment ran.
    expect(render(adjusted('2020-06-01T00:00:00Z'), 'manager')).toContain(detail('Effective impact', '0.10'));
    // Expired before the assessment ran.
    expect(render(adjusted('2019-12-31T00:00:00Z'), 'manager')).toContain(detail('Effective impact', '0.90'));
  });

  it('falls back to the latest result time when the document has no timestamp', () => {
    const doc = waived('2019-12-31T00:00:00Z');
    delete doc.timestamp;
    const out = render(doc, 'manager');
    expect(out).toContain('Effective status evaluated as of 2020-01-01T00:00:00Z');
    expect(out).toContain(detail('Effective status', badge('failed', 'Failed')));
  });

  it('claims no assessment time when the document carries none', () => {
    const out = convertHdfToHtml(
      '{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0.5,"tags":{},"descriptions":[],"results":[]}]}]}',
    );
    expect(out).not.toContain('evaluated as of');
    expect(out).toContain(summaryRow('b', '0', '0', '1', '0', '0', '1', '0.00%'));
  });

  it('is deterministic', () => {
    const input = JSON.stringify(richDoc());
    const first = convertHdfToHtml(input);
    for (let i = 0; i < 5; i++) expect(convertHdfToHtml(input)).toBe(first);
  });

  it('is self-contained in every report type', () => {
    for (const reportType of REPORT_TYPES) expectSelfContained(render(richDoc(), reportType), true);
  });

  it('escapes every rendered field', () => {
    const hostile = `</pre></dd><script>alert(1)</script><img src=x onerror=alert(1)>"'&`;
    const req = testhdf.req(`${hostile}id`, {
      title: `${hostile}title`,
      impact: 0.5,
      status: 'failed',
      desc: `${hostile}desc`,
      addDesc: [[`${hostile}label`, `${hostile}data`]],
      code: `${hostile}code`,
      codeDesc: `${hostile}codeDesc`,
      tags: { nist: [`${hostile}nist`], cci: [`${hostile}cci`] },
    }) as unknown as Doc;
    (req.results as Doc[])[0]!.message = `${hostile}message`;
    req.statusOverrides = [
      {
        type: 'waiver', status: 'passed', reason: `${hostile}reason`,
        appliedBy: { type: 'email', identifier: `${hostile}identifier` },
        appliedAt: '2019-06-01T00:00:00Z', expiresAt: FAR_FUTURE,
      },
    ];
    const baseline = testhdf.baseline(`${hostile}baseline`, req as never) as unknown as Doc;
    baseline.title = `${hostile}baselineTitle`;
    baseline.version = `${hostile}baselineVersion`;
    const doc = testhdf.doc(baseline as never) as unknown as Doc;
    doc.systemRef = `ref${hostile}`;
    doc.tool = { name: `${hostile}tool`, version: `${hostile}toolVersion` };
    doc.generator = { name: `${hostile}generator`, version: `${hostile}generatorVersion` };
    doc.runner = { name: `${hostile}runner`, hostname: `${hostile}runnerHost` };
    doc.components = [
      {
        name: `${hostile}component`, type: 'host', description: `${hostile}componentDescription`,
        labels: { [`${hostile}labelKey`]: `${hostile}labelValue` },
        externalIds: { [`${hostile}scheme`]: `${hostile}externalValue` },
      },
    ];

    const out = render(doc);
    expect(out).not.toContain('<script>alert');
    expect((out.match(/<script/gi) ?? []).length).toBe(1);
    expect(out).not.toContain('<img');
    expect(out).not.toContain(hostile);
    expectSelfContained(out, true);

    const escaped = '&lt;/pre&gt;&lt;/dd&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;';
    for (const field of [
      'id', 'title', 'desc', 'label', 'data', 'code', 'nist', 'cci', 'codeDesc', 'message', 'reason', 'identifier',
      'baseline', 'baselineTitle', 'baselineVersion', 'tool', 'toolVersion', 'generator', 'generatorVersion',
      'runner', 'runnerHost', 'component', 'componentDescription', 'labelKey', 'labelValue', 'scheme', 'externalValue',
    ]) {
      expect(out, `${field} must be rendered, escaped`).toContain(escaped + field);
    }
  });

  // HDF prose is carried verbatim: line structure and edge whitespace reach the
  // report unchanged. A carriage return is written as a reference so the parser
  // cannot fold it away, and the newline after <pre> is the one a parser drops.
  it('carries prose verbatim', () => {
    const prose = '\n  Verify the setting:\r\n\n    $ sysctl kernel.dmesg_restrict\n\tkernel.dmesg_restrict = 1  \n';
    const out = render(testhdf.results(testhdf.req('V-1', { desc: prose, impact: 0.5 })), 'manager');
    expect(out).toContain(`<pre class="prose">\n${prose.split('\r').join('&#13;')}</pre>`);
  });

  it('counts effective statuses per baseline and overall', () => {
    const doc = testhdf.doc(
      testhdf.baseline(
        'one',
        testhdf.req('A', { impact: 0.5, status: 'passed' }),
        testhdf.req('B', { impact: 0.5, status: 'passed' }),
        testhdf.req('C', { impact: 0.5, status: 'failed' }),
        testhdf.req('D', { impact: 0, status: 'passed' }),
      ),
      testhdf.baseline(
        'two',
        testhdf.req('E', { impact: 0.5, status: 'notReviewed' }),
        testhdf.req('F', { impact: 0.5, status: 'error' }),
      ),
    );
    const out = render(doc, 'executive');
    expect(out).toContain(summaryRow('one', '2', '1', '0', '1', '0', '4', '66.67%'));
    expect(out).toContain(summaryRow('two', '0', '0', '1', '0', '1', '2', '0.00%'));
    expect(out).toContain(summaryRow('All baselines', '2', '1', '1', '1', '1', '6', '40.00%'));
  });

  // The report prints the compliance hdf-engine computes, so a report and
  // `hdf validate threshold` never disagree in the last digit. 23 passed out of
  // 160 relevant requirements is 14.37% to the engine; the half-up integer
  // formula the report once carried printed 14.38%.
  it('takes compliance from the engine', () => {
    const baseline = (name: string, passed: number, failed: number) =>
      testhdf.baseline(
        name,
        ...Array.from({ length: passed + failed }, (_, i) =>
          testhdf.req(`${name}-${i}`, { impact: 0.5, status: i < passed ? 'passed' : 'failed' }),
        ),
      );

    const out = render(testhdf.doc(baseline('divergent', 23, 137), baseline('clean', 1, 1)), 'executive');
    expect(out).toContain(summaryRow('divergent', '23', '137', '0', '0', '0', '160', '14.37%'));
    expect(out).toContain(summaryRow('clean', '1', '1', '0', '0', '0', '2', '50.00%'));
    expect(out).toContain(summaryRow('All baselines', '24', '138', '0', '0', '0', '162', '14.81%'));
    expect(out).not.toContain('14.38');

    const gauge = render(testhdf.doc(baseline('divergent', 23, 137)), 'executive');
    expect(gauge).toContain('<div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="14.37" aria-labelledby="compliance-heading" style="--pct:14.37"><span class="pct">14.37%</span></div>');
    expect(gauge).toContain('<div class="panel compliance compliance-low">');
  });

  // Go's zero time is what a typed marshal writes for an override carrying no
  // expiry, so an expiresAt of 0001-01-01T00:00:00Z means absent, not an expiry
  // in the year 1. The Go peer reads the same document the same way.
  it('reads the Go zero time as no expiry', () => {
    const doc = waived(GO_ZERO_TIME);
    expectValidResults(doc as never);
    const out = render(doc, 'manager');

    expect(out).toContain(detail('Effective status', badge('passed', 'Passed')));
    expect(out).toContain(`${badge('passed', 'Passed')}<span class="req-id">V-1</span>`);
    expect(out).toContain('<td>governing</td>');
    expect(out).not.toContain('<td>expired</td>');
    expect(out).toContain('100.00%');
  });

  it('shows the status dashboard', () => {
    const failing = testhdf.req('F', { impact: 0.9, status: 'failed' }) as unknown as Doc;
    (failing.results as Doc[]).push(
      { status: 'passed', codeDesc: 'ok', startTime: '2020-01-01T00:00:00Z' },
      { status: 'failed', codeDesc: 'bad', startTime: '2020-01-01T00:00:00Z' },
    );
    const out = render(
      testhdf.results(
        testhdf.req('P1', { impact: 0.7, status: 'passed' }),
        testhdf.req('P2', { impact: 0.5, status: 'passed' }),
        failing as never,
        testhdf.req('N', { impact: 0, status: 'passed' }),
      ),
      'executive',
    );
    for (const want of [
      '<li class="stat c-passed"><span class="num">2</span><span class="lbl">Passed</span><span class="sub">2 individual checks passed</span></li>',
      '<li class="stat c-failed"><span class="num">1</span><span class="lbl">Failed</span><span class="sub">1 individual check passed, 2 failed out of 6 total checks</span></li>',
      '<li class="stat c-not-applicable"><span class="num">1</span><span class="lbl">Not Applicable</span></li>',
      '<li class="stat stat-total"><span class="num">4</span><span class="lbl">Total</span></li>',
      '<li class="stat c-critical"><span class="num">1</span><span class="lbl">Critical</span></li>',
      '<li class="stat c-none"><span class="num">1</span><span class="lbl">None</span></li>',
      'aria-label="Requirements by status: 2 passed, 1 failed, 1 not applicable, 0 not reviewed, 0 error"',
      'aria-label="Requirements by severity: 1 critical, 1 high, 1 medium, 0 low, 1 none"',
      '<div class="panel compliance compliance-medium">',
      '<div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="66.67" aria-labelledby="compliance-heading" style="--pct:66.67"><span class="pct">66.67%</span></div>',
      '<p class="level">Medium compliance</p>',
    ]) {
      expect(out).toContain(want);
    }
    expect(out).not.toContain('class="seg c-error"');
  });

  it('bands compliance at 90 and 60', () => {
    const reqs = (passed: number, failed: number) =>
      testhdf.results(
        ...Array.from({ length: passed + failed }, (_, i) =>
          testhdf.req(`R-${i}`, { impact: 0.5, status: i < passed ? 'passed' : 'failed' }),
        ),
      );
    expect(render(reqs(9, 1), 'executive')).toContain('compliance-high">');
    expect(render(reqs(6, 4), 'executive')).toContain('compliance-medium">');
    expect(render(reqs(5, 5), 'executive')).toContain('compliance-low">');
  });

  it('is structured for keyboard and screen-reader use', () => {
    const out = render(richDoc());
    for (const want of [
      '<html lang="en">', '<a class="skip" href="#main">Skip to content</a>', '<nav aria-label="Sections">', '<main id="main" class="container">',
      '<section id="status" class="card" aria-labelledby="status-heading">',
      '<table class="summary" aria-label="Status by baseline">',
      '<table aria-label="Test results">', 'aria-label="Filter requirements by ID, title or control"',
      '<span id="filter-count" class="shown" aria-live="polite"></span>', '<span class="vh">Severity: </span>',
      '<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>',
      '<a class="page-top" href="#top">Top</a>',
    ]) {
      expect(out).toContain(want);
    }
    expect(count(out, '<h1')).toBe(1);
    for (const th of out.match(/<th[ >][^>]*>/g) ?? []) expect(th).toContain('scope=');
  });

  // The report is built on semantic elements: landmarks a screen reader can
  // list, one disclosure per requirement inside the article that names it, a
  // measurement element for compliance, and a scheme declared before the
  // stylesheet is read.
  it('is built on semantic elements', () => {
    const out = render(richDoc());
    for (const want of [
      '<meta name="color-scheme" content="light dark" />',
      '<nav aria-label="Sections">\n<ul>\n<li><a href="#status">Status</a></li>',
      '<main id="main" class="container">',
      '<h3 id="compliance-heading">Compliance</h3>',
      '<div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="100" aria-valuenow="50.00" aria-labelledby="compliance-heading" style="--pct:50.00"><span class="pct">50.00%</span></div>',
      '<article class="requirement c-failed" data-status="failed" id="req-1">\n<details>\n<summary>',
    ]) {
      expect(out).toContain(want);
    }
    expect(count(out, '<article class="requirement '), 'one article per requirement').toBe(2);
    expect(count(out, 'role="meter"'), 'one compliance measurement').toBe(1);
    expect(out).not.toContain('<progress');
    expect(out, 'the ring is the measurement; no element duplicates it').not.toContain('<meter');

    // Neither status nor severity may be read by colour alone: each carries a
    // mark or a shape and the word beside it.
    expect(out).toContain(badge('failed', 'Failed'));
    expect(out).toContain('<span class="ico" aria-hidden="true">\u2717</span>Failed');
    expect(out).toContain('<span class="sev c-high"><span class="vh">Severity: </span>High</span>');
    expect(REPORT_CSS).toContain('.sev::before { content: "";');

    for (const [cls, icon] of Object.entries({
      passed: '\u2713', failed: '\u2717', 'not-applicable': '\u2013', 'not-reviewed': '?', error: '!', unknown: '\u00b7',
    })) {
      expect(statusIcon(cls), cls).toBe(icon);
    }
  });

  // Anything longer than two lines or rows sits behind its heading, with a
  // count, and ends with a way back to its own top; a short block is shown.
  it('collapses long blocks and links back to their tops', () => {
    const long = testhdf.req('V-2', { impact: 0.5, status: 'failed', desc: 'one\ntwo\nthree', code: 'a\nb\nc' }) as unknown as Doc;
    (long.results as Doc[]).push(
      { status: 'failed', codeDesc: '2', startTime: '2020-01-01T00:00:00Z' },
      { status: 'failed', codeDesc: '3', startTime: '2020-01-01T00:00:00Z' },
    );
    const out = render(
      testhdf.results(
        testhdf.req('V-1', { impact: 0.5, status: 'failed', desc: 'one line', code: 'a\nb' }),
        long as never,
        testhdf.req('V-3', { impact: 0.5 }),
      ),
    );
    const first = out.slice(out.indexOf('id="req-1"'), out.indexOf('id="req-2"'));
    const second = out.slice(out.indexOf('id="req-2"'), out.indexOf('id="req-3"'));

    expect(first).toMatch(/<details class="fold" id="block-\d+" open="open">\n<summary><h4>Test Results<\/h4><span class="count">1<\/span>/);
    expect(first).not.toContain('<h4>Description</h4>');
    for (const heading of ['Test Results', 'Description', 'Code']) {
      expect(second).toMatch(new RegExp(`<details class="fold" id="block-\\d+">\\n<summary><h4>${heading}</h4><span class="count">3</span>`));
    }
    expect(second).toContain('Back to the top of the test results</a></p>');
    for (const id of ['req-1', 'req-2', 'req-3']) {
      expect(out).toContain(`<p class="to-top"><a href="#${id}">Back to the top of this requirement</a></p>`);
    }
    for (const m of out.matchAll(/href="#([^"]+)"/g)) {
      expect(out, `link target ${m[1]}`).toContain(`id="${m[1]}"`);
    }
  });

  it('offers the theme switch in every report type', () => {
    for (const reportType of REPORT_TYPES) {
      const out = render(richDoc(), reportType);
      expect(out).toContain('<button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch to dark mode">Dark mode</button>');
      expect(out).toContain(`script-src '${SCRIPT_HASH}'`);
      expect(count(out, '<script>')).toBe(1);
      expect(out).toContain('<html lang="en">\n');
    }
    expect(REPORT_CSS).toContain('[data-theme="dark"] {');
    expect(REPORT_CSS).toContain(':root:not([data-theme="dark"]), [data-theme="light"] {');
    expect(REPORT_CSS).toContain(':root:not([data-theme]) {');
  });

    it('renders the optional detail fields', () => {
    const req = testhdf.req('V-1', { impact: 0.7, status: 'failed', tags: { nist: 'AC-1', cci: ['CCI-1', 7, 'CCI-2'] } }) as unknown as Doc;
    req.severity = 'critical';
    // Stored caches left in on purpose: the rows below must come from the ladder,
    // so these are now the evidence that the cache is ignored.
    req.effectiveImpact = 0.3;
    req.disposition = 'waiver';
    req.statusOverrides = [
      { type: 'operationalRequirement', reason: 'documentation only', appliedBy: { type: 'email', identifier: 'a@example.gov' }, appliedAt: '2019-06-01T00:00:00Z' },
    ];
    const doc = testhdf.results(req as never) as unknown as Doc;
    doc.components = [{ name: 'db', type: 'database', port: 5432, provider: 'aws', owner: { type: 'email', identifier: 'dba@example.gov' } }];
    doc.runner = { name: 'r', operator: { identifier: 'ops' } };
    doc.statistics = { duration: 12.345 };

    const out = render(doc);
    for (const want of [
      '<dt>Port</dt><dd>5432</dd>', '<dt>Provider</dt><dd>aws</dd>', '<dt>Owner</dt><dd>dba@example.gov (email)</dd>',
      '<dt>Operator</dt><dd>ops</dd>', '<dt>Duration</dt><dd>12.35 s</dd>',
      detail('Severity', 'critical'), detail('Impact', '0.70'), detail('Effective impact', '0.70'),
      detail('Disposition', 'operationalRequirement'), detail('NIST Controls', 'AC-1'), detail('CCI Controls', 'CCI-1, CCI-2'),
      '<span class="sev c-critical"><span class="vh">Severity: </span>Critical</span>',
      '<span class="tags"><span class="vh">Controls: </span><span class="tag">AC-1</span><span class="tag">CCI-1</span><span class="tag">CCI-2</span></span>',
      '<td>operationalRequirement</td><td></td>',
    ]) {
      expect(out).toContain(want);
    }
    expect(out).not.toContain('governing');
  });

  // Parity: TestConvertHDFToHTML_SeverityAndDispositionFollowTheLadder in go.
  // The badge and the two rows must agree with the summary table, which counts
  // through the shared ladder; severity is left unset so the impact drives the band.
  it('derives the badge, effective impact and disposition through the ladder', () => {
    const req = testhdf.req('V-RESCORED', { impact: 0.9, status: 'failed' });
    req.statusOverrides = [
      {
        type: 'riskAdjustment', reason: 'compensating control in place',
        appliedBy: { type: 'email', identifier: 'a@example.gov' },
        appliedAt: '2020-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
        impact: { value: 0.1 },
      },
    ];
    const out = render(testhdf.results(req as never) as unknown as Doc);
    expect(out, 'the badge must follow the re-scored impact').toContain('<span class="sev c-low">');
    expect(out, 'and must not keep the raw band').not.toContain('<span class="sev c-critical">');
    expect(out, 'computed through the ladder, not a cache the document does not carry').toContain(detail('Effective impact', '0.10'));
    expect(out, "the governing override's type, not a stored field").toContain(detail('Disposition', 'riskAdjustment'));
  });

  it('rejects what is not a results document', () => {
    for (const input of ['', 'not json', '{"generator":{"name":"t","version":"0"}}', '{"baselines":null}', '[]']) {
      expect(() => convertHdfToHtml(input), input).toThrow();
    }
  });

  // The legacy converters write Go's zero time when a source has no start time.
  // It is not a time, so it is neither shown nor taken as the assessment time.
  it('treats the zero time as absent', () => {
    const out = convertHdfToHtml(
      '{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0.5,"tags":{},' +
        '"descriptions":[{"label":"default","data":"d"}],"results":[{"status":"failed","codeDesc":"c","startTime":"0001-01-01T00:00:00Z"}]}]}]}',
    );
    expect(out).not.toContain('0001-01-01');
    expect(out).not.toContain('evaluated as of');
  });

  it('counts references that state no kind', () => {
    const doc = testhdf.results(testhdf.req('V-1', { impact: 0.5 })) as unknown as Doc;
    doc.externalReferences = [{ sourceName: 'cve', externalId: 'CVE-2021-44228' }];
    const out = render(doc, 'executive');
    expect(out).toContain('<dt>External references</dt><dd>1</dd>');
    expect(out).toContain('<td>cve</td><td>CVE-2021-44228</td>');
    expect(out).not.toContain('Embedded document');
  });

    it('skips empty optional finding fields', () => {
    const req = testhdf.req('V-1', { impact: 0.5, status: 'failed' }) as unknown as Doc;
    req.epss = { score: 0.1, percentile: 0.2 };
    req.kev = { inKev: false };
    req.cvss = [{}];
    req.affectedPackages = [{}];
    req.evidence = [{}];
    req.refs = [{ ref: '' }, { ref: [{ url: '' }] }];
    req.tags = { empty: [], n: 1 };
    const out = convertHdfToHtml(JSON.stringify(testhdf.results(req as never)));
    expect(out).toContain(detail('EPSS', 'score 0.10000, percentile 0.20000'));
    expect(out).toContain(detail('KEV', 'Not listed'));
    for (const absent of ['CVSS', 'Affected packages', 'Evidence', 'References']) {
      expect(out).not.toContain(`<th scope="row">${absent}</th>`);
    }
    expect(out).not.toContain('<h4>Tags</h4>');
  });

    it('reports on a document with no baselines', () => {
    const out = convertHdfToHtml('{"baselines":[]}');
    expect(out).toContain(summaryRow('All baselines', '0', '0', '0', '0', '0', '0', '0.00%'));
    expect(out).not.toContain('evaluated as of');
    expect(out).toContain('The document carries no assessment metadata.');
    expect(out).toContain('The document names no components.');
  });

  // Go's typed decode turns a null array member into a zero-value struct, so
  // the two languages must both render it as an empty entry.
  it('reads null array members as empty rather than throwing', () => {
    const out = convertHdfToHtml(
      JSON.stringify({
        baselines: [null, { name: 'b', requirements: [null, { id: 'V-1', results: [null], descriptions: [null], statusOverrides: [null] }] }],
        components: [null, { name: 'c', type: 'host' }],
      }),
    );
    expect(count(out, '<article class="requirement ')).toBe(2);
    expect(count(out, '<details class="fold component"')).toBe(2);
    expect(out).not.toContain('undefined');
    expect(out).not.toContain('[object');
  });
});

describe('hdf-to-html baseline labels and component attribution', () => {
  // Real Prisma Cloud output names all 16 of its baselines "Prisma Cloud Scan"
  // and carries the host each one scanned in the title alone, so a report that
  // prints the name shows 16 rows a reader cannot tell apart.
  it('labels baselines by title, reading the shared Prisma fixture', () => {
    const input = sharedResults.duplicateBaselines.read();
    const doc = JSON.parse(input) as { baselines: { name: string; title: string }[]; components: unknown[] };
    expect(doc.baselines).toHaveLength(16);

    const out = convertHdfToHtml(input);
    const table = statusByBaselineTable(out);
    const labels = summaryRowLabels(table);
    expect(labels).toHaveLength(17);
    expect(labels[16]).toBe('All baselines');
    expect(table).toContain('<th scope="row">Prisma Cloud Scan (my-fake-host-1.somewhere.cloud)</th>');

    const seen = new Set<string>();
    labels.slice(0, 16).forEach((label, i) => {
      expect(doc.baselines[i]!.name, 'every baseline carries the same name').toBe('Prisma Cloud Scan');
      expect(label, "the row is labelled by the baseline's own title").toBe(doc.baselines[i]!.title);
      expect(seen.has(label), `label ${label} repeats`).toBe(false);
      expect(label, 'every title is already distinct, so no row needs an ordinal').not.toContain(' #');
      expect(out, 'the baseline fold carries the same label as its row').toContain(`<summary><h3>${label}</h3>`);
      seen.add(label);
    });
    // The label is the title, so the details fold states the name: it is the key
    // `hdf query --baseline` selects on.
    expect(count(out, '<dt>Name</dt><dd>Prisma Cloud Scan</dd>')).toBe(16);

    // Nothing in the document ties a requirement to a component, so the cards
    // are an inventory and carry no number.
    const summaries = componentSummaries(out);
    expect(summaries).toHaveLength(doc.components.length);
    for (const summary of summaries) expect(summary).not.toContain('<span class="count">');
  });

  // Two baselines a document gives the same label are told apart by their 1-based
  // document position (baselineIndex + 1), so the report never shows one row twice.
  const titled = (title: string, reqId: string): Doc => {
    const b = testhdf.baseline('scan', testhdf.req(reqId, { impact: 0.5, status: 'failed' })) as unknown as Doc;
    if (title !== '') b.title = title;
    return b;
  };

  it.each([
    ['a repeated title takes each ordinal', [titled('Nightly scan', 'A'), titled('Nightly scan', 'B'), titled('Weekly scan', 'C')],
      ['Nightly scan #1', 'Nightly scan #2', 'Weekly scan']],
    ['no title falls back to the name', [titled('', 'A'), titled('Nightly scan', 'B')], ['scan', 'Nightly scan']],
    ['two untitled baselines take the ordinal on their shared name', [titled('', 'A'), titled('', 'B')], ['scan #1', 'scan #2']],
    // The ordinal is appended, not substituted, so a title that already reads
    // like one still ends up with a label of its own.
    ['a title already ending in another ordinal keeps its own label',
      [titled('Nightly scan #2', 'A'), titled('Nightly scan', 'B'), titled('Nightly scan', 'C')],
      ['Nightly scan #2', 'Nightly scan #2 #2', 'Nightly scan #3']],
  ] as const)('disambiguates repeated baseline labels: %s', (_name, baselines, want) => {
    const doc = testhdf.doc(...(baselines as unknown as never[])) as unknown as Doc;
    expectValidResults(doc as never);
    const out = render(doc, 'manager');
    const labels = summaryRowLabels(statusByBaselineTable(out));
    expect(labels).toHaveLength(want.length + 1);
    expect(labels.slice(0, want.length)).toEqual([...want]);
    expect(new Set(want).size, 'every label must be its own').toBe(want.length);
    for (const label of want) expect(out).toContain(`<summary><h3>${label}</h3>`);
  });

  // The count on a component card describes the component's own facts, which
  // says nothing about coverage unless the document says which component a
  // baseline's requirements were assessed against.
  it('states a component count only where results are attributed', () => {
    const base = (): Doc => {
      const doc = testhdf.results(testhdf.req('V-1', { impact: 0.5, status: 'failed' })) as unknown as Doc;
      doc.components = [{ name: 'web01', type: 'host', hostname: 'web01.example.gov' }];
      return doc;
    };

    const unattributed = base();
    expectValidResults(unattributed as never);
    let summaries = componentSummaries(render(unattributed, 'executive'));
    expect(summaries).toHaveLength(1);
    expect(summaries[0], 'no baseline names a component').not.toContain('<span class="count">');

    const labelled = base();
    (labelled.baselines as Doc[])[0]!.labels = { component: 'web01' };
    expectValidResults(labelled as never);
    summaries = componentSummaries(render(labelled, 'executive'));
    expect(summaries).toHaveLength(1);
    expect(summaries[0], 'the baseline names the component it was assessed against').toContain('<span class="count">1</span>');

    const referenced = base();
    (referenced.components as Doc[])[0]!.baselineRefs = ['example'];
    expectValidResults(referenced as never);
    summaries = componentSummaries(render(referenced, 'executive'));
    expect(summaries).toHaveLength(1);
    expect(summaries[0], 'the component names the baseline that applies to it').toContain('<span class="count">1</span>');
  });
});

describe('hdf-to-html aggregated report', () => {
  // Each document's overrides are judged at that document's own assessment
  // time, so the same waiver can be in force in one source and expired in another.
  it('judges each source at its own assessment time', () => {
    const early = waived('2020-06-01T00:00:00Z');
    const late = waived('2020-06-01T00:00:00Z');
    late.timestamp = '2021-01-01T00:00:00Z';
    const out = convertHdfDocumentsToHtml([
      { name: 'early.json', content: JSON.stringify(early) },
      { name: 'late.json', content: JSON.stringify(late) },
    ]);
    expect(out).toContain('<a href="#source-1">early.json</a></th><td>1</td><td>0</td>');
    expect(out).toContain('<a href="#source-2">late.json</a></th><td>0</td><td>1</td>');
    expect(out).toContain('<td>governing</td>');
    expect(out).toContain('<td>expired</td>');
  });

  it('refuses no documents, a non-results document by name, and an unknown report type', () => {
    expect(() => convertHdfDocumentsToHtml([])).toThrow(/no documents/);
    expect(() =>
      convertHdfDocumentsToHtml([
        { name: 'ok.json', content: '{"baselines":[]}' },
        { name: 'bad.json', content: '{"overrides":[]}' },
      ]),
    ).toThrow(/bad\.json/);
    expect(() => convertHdfDocumentsToHtml([{ name: 'a.json', content: '{"baselines":[]}' }], { reportType: 'auditor' })).toThrow(
      /unknown report type/,
    );
  });

  it('uses the aggregated layout for one named document', () => {
    const out = convertHdfDocumentsToHtml([{ name: 'only.json', content: '{"baselines":[]}' }]);
    expect(out).toContain('<h2 id="sources-heading">Sources (1)</h2>');
    expect(out).toContain('The documents name no components.');
    expect(out).not.toContain('evaluated for each source');
  });
});

describe('hdf-to-html helpers', () => {
  it('takes compliance from the engine', () => {
    const bucket = (total: number): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, informational: total, total });
    const c = (passed: number, failed = 0, notReviewed = 0, errored = 0, notApplicable = 0) =>
      compliance({
        passed: bucket(passed),
        failed: bucket(failed),
        skipped: bucket(notReviewed),
        error: bucket(errored),
        noImpact: bucket(notApplicable),
      });
    expect(c(0)).toBe('0.00%');
    expect(c(0, 0, 0, 0, 4)).toBe('0.00%');
    expect(c(1)).toBe('100.00%');
    expect(c(1, 2)).toBe('33.33%');
    expect(c(2, 1)).toBe('66.67%');
    expect(c(1, 7)).toBe('12.50%');
    expect(c(1, 0, 1, 1, 9)).toBe('33.33%');
    // The pair the integer half-up formula rounded the other way.
    expect(c(23, 137)).toBe('14.37%');
  });

  it('renders a status with a class from a fixed set', () => {
    expect(statusBadge('passed')).toBe(badge('passed', 'Passed'));
    expect(statusBadge('failed')).toBe(badge('failed', 'Failed'));
    expect(statusBadge('notReviewed')).toBe(badge('not-reviewed', 'Not Reviewed'));
    expect(statusBadge('notApplicable')).toBe(badge('not-applicable', 'Not Applicable'));
    expect(statusBadge('error')).toBe(badge('error', 'Error'));
    expect(statusBadge('"><script>')).toBe(badge('unknown', '&quot;&gt;&lt;script&gt;'));
    expect(statusBadge('constructor')).toBe(badge('unknown', 'constructor'));
  });

  it('reads nist and cci tags', () => {
    expect(tagItems({}, 'nist')).toEqual([]);
    expect(tagItems({ nist: 7 }, 'nist')).toEqual([]);
    expect(tagItems({ nist: 'AC-1' }, 'nist')).toEqual(['AC-1']);
    expect(tagItems({ nist: ['AC-1', null, 'AC-2'] }, 'nist')).toEqual(['AC-1', 'AC-2']);
    expect(tagItems({}, 'constructor')).toEqual([]);
  });

  it('maps severities onto a fixed set', () => {
    for (const [severity, cls, label] of [
      ['critical', 'critical', 'Critical'], ['high', 'high', 'High'], ['medium', 'medium', 'Medium'], ['low', 'low', 'Low'],
      ['informational', 'none', 'None'], ['none', 'none', 'None'], ['', 'none', 'None'], ['Sev<1>', 'none', 'Sev<1>'],
    ] as const) {
      expect(severityClass(severity)).toBe(cls);
      expect(severityLabel(severity)).toBe(label);
    }
  });

  it('names descriptions as the Heimdall report does', () => {
    expect(descriptionHeading('default')).toBe('Description');
    expect(descriptionHeading('check')).toBe('Check Text');
    expect(descriptionHeading('fix')).toBe('Fix Text');
    expect(descriptionHeading('rationale')).toBe('Rationale');
    expect(descriptionHeading('caveat')).toBe('Caveat');
    expect(descriptionHeading('solution')).toBe('solution');
  });

  it('pins the script by the hash the policy carries', () => {
    // The element's content is the newline after <script> plus the script itself.
    const digest = createHash('sha256').update('\n' + SCRIPT, 'utf-8').digest('base64');
    expect(`sha256-${digest}`).toBe(SCRIPT_HASH);
    expect(SCRIPT).not.toMatch(/[<&]/);
    // A raw-text element ends only at its own closing tag, so the stylesheet's
    // "<" is safe; what would break out of it is not.
    expect(STYLESHEET.toLowerCase()).not.toContain('</style');
  });

  it('describes a source location', () => {
    expect(sourceLocation(undefined)).toBe('');
    expect(sourceLocation({})).toBe('');
    expect(sourceLocation({ ref: 'a.rb' })).toBe('a.rb');
    expect(sourceLocation({ line: 12 })).toBe('line 12');
    expect(sourceLocation({ ref: 'a.rb', line: 12 })).toBe('a.rb:12');
  });

    it('indents compact JSON without touching its values', () => {
    expect(indentJson('{}')).toBe('{}');
    expect(indentJson('[]')).toBe('[]');
    expect(indentJson('{"a":[1,"x,{}[]:\\"y"],"b":{}}')).toBe('{\n  "a": [\n    1,\n    "x,{}[]:\\"y"\n  ],\n  "b": {}\n}');
    expect(indentJson('"a\\\\"')).toBe('"a\\\\"');
    // A string that never closes, or ends on an escape, is carried to the end.
    expect(indentJson('"open')).toBe('"open');
    expect(indentJson('"open\\')).toBe('"open\\');
  });

    it('recognizes text that takes more than two lines', () => {
    expect(isLongText('')).toBe(false);
    expect(isLongText('one\ntwo')).toBe(false);
    expect(isLongText('one\ntwo\nthree')).toBe(true);
    expect(isLongText('\u{1F600}'.repeat(240))).toBe(false);
    expect(isLongText('\u{1F600}'.repeat(241))).toBe(true);
  });

    it('replaces characters HTML cannot carry', () => {
    expect(escapeHtml('a\u0000b\u000bc\u007fd\te\nf')).toBe('a�b�c�d\te\nf');
    expect(escapeHtml('x\ud800y')).toBe('x�y');
    expect(escapeHtml('￾￿')).toBe('��');
    expect(escapeHtml('\u{1F600}')).toBe('\u{1F600}');
  });

  it('orders strings by code point, as Go does', () => {
    // U+FF5E sorts before U+1F600 by code point but after it by UTF-16 unit.
    expect(['\u{1F600}', '～', 'b', 'a', 'ab'].sort(byCodePoint)).toEqual(['a', 'ab', 'b', '～', '\u{1F600}']);
    expect(byCodePoint('a', 'a')).toBe(0);
  });
});

// The two languages are compared against one another rather than each against
// its own expectations. Go owns the goldens
// (go test ./converters/hdf-to-html/go/ -update); this side only verifies.
describe('hdf-to-html parity with the Go peer', () => {
  const rich = loadFixture('input', 'rich.json');

  it('holds rich.json to the HDF schema', () => {
    expect(() => expectValidResults(JSON.parse(rich))).not.toThrow();
  });

  it.each(REPORT_TYPES)('emits the Go golden for rich.json as %s', (reportType) => {
    const out = convertHdfToHtml(rich, { reportType });
    expectSelfContained(out, true);
    expect(out).toBe(loadFixture('expected', `rich.${reportType}.html`));
  });

  // Every optional field the report renders beyond the basics, on the same
  // bytes the Go peer rendered.
  it('emits the Go golden for finding-detail.json', () => {
    const input = loadFixture('input', 'finding-detail.json');
    expectValidResults(JSON.parse(input));
    const out = convertHdfToHtml(input);
    expectSelfContained(out, true);
    expect(out).toBe(loadFixture('expected', 'finding-detail.administrator.html'));
    // Enrichment: external references at every level, and an embedded STIX object shown whole.
    expect(out).toContain('<dt>External references</dt><dd>6 (annotation 1, threat-intel 1)</dd>');
    expect(out).toContain('<span class="tag enriched">Enriched (3)</span>');
    expect(out).toContain('<details class="doc"><summary>Embedded document</summary>');
    expect(out).not.toContain('<role>');
    expect(out).toContain(
      '<p class="location"><span class="k">Location</span><code>app/controllers/attestations_controller.rb:35</code></p>',
    );
  });

    // Several documents in one report, on the same bytes and names the Go peer used.
  const aggregateInputs = () => [
    { name: 'rich.json', content: rich },
    { name: 'finding-detail.json', content: loadFixture('input', 'finding-detail.json') },
  ];

  it.each(REPORT_TYPES)('emits the Go golden for the aggregated report as %s', (reportType) => {
    const out = convertHdfDocumentsToHtml(aggregateInputs(), { reportType });
    expectSelfContained(out, true);
    expect(out).toBe(loadFixture('expected', `aggregate.${reportType}.html`));
  });

  it('aggregates across sources', () => {
    const out = convertHdfDocumentsToHtml(aggregateInputs());
    for (const want of [
      '<h2 id="sources-heading">Sources (2)</h2>',
      '<table class="summary" aria-label="Status by source">',
      '<tr><th scope="row"><a href="#source-1">rich.json</a></th><td>1</td><td>3</td>',
      summaryRow('All sources', '1', '3', '0', '1', '0', '5', '25.00%'),
      '<dt>Source</dt><dd>rich.json</dd>',
      '<summary><h3>finding-detail.json</h3><span class="count">1</span></summary>',
      '<summary><h4>Static analysis</h4><span class="count">1</span></summary>',
      '<h5>Result Details</h5>',
    ]) {
      expect(out).toContain(want);
    }
    expect(out).not.toContain('id="assessment"');
    expect(count(out, '<article class="requirement ')).toBe(5);
  });

    const corpusGolden = JSON.parse(loadFixture('expected', 'corpus-outputs.json')) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(corpusGolden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))('emits what the Go peer emits for %s', (name, c) => {
    let actual: string;
    try {
      const out = convertHdfToHtml(c.input);
      actual = out.slice(out.indexOf('<body>'));
    } catch {
      actual = 'REJECTED';
    }
    expect(actual, `TypeScript and Go diverged on corpus case ${name}`).toBe(corpusGolden[name]);
  });

  const digests = JSON.parse(loadFixture('expected', 'real-digests.json')) as Record<string, string>;

  // The enrich pass's own golden: results carrying STIX objects from a real bundle.
  it('emits the Go digest for the enriched results document', () => {
    const enriched = readFileSync(
      join(__dirname, '..', '..', '..', 'shared', 'enrich-fixtures', 'results-enriched.golden.json'),
      'utf-8',
    );
    const out = convertHdfToHtml(enriched);
    expectSelfContained(out, true);
    expect(out).toContain('<details class="doc"><summary>Embedded document</summary>');
    expect(createHash('sha256').update(out, 'utf-8').digest('hex')).toBe(digests['results-enriched.administrator']);

    // The two real documents reported together.
    const combined = convertHdfDocumentsToHtml([
      { name: 'merge-zap.json', content: sharedResults.mergeZap.read() },
      { name: 'results-enriched.golden.json', content: enriched },
    ]);
    expectSelfContained(combined, true);
    expect(createHash('sha256').update(combined, 'utf-8').digest('hex')).toBe(digests['aggregate.administrator']);
  });

    it.each(REPORT_TYPES)('emits the Go digest for the real ZAP document as %s', (reportType) => {
    const out = convertHdfToHtml(sharedResults.mergeZap.read(), { reportType });
    expectSelfContained(out, true);
    expect(createHash('sha256').update(out, 'utf-8').digest('hex')).toBe(digests[`merge-zap.${reportType}`]);
  });
});
