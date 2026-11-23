import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertXccdfBenchmarkToHdf, convertXccdfResultsToHdf } from './converter.js';
import type { HDFBaseline, HDFResults, Description } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const inputDir = join(__dirname, '..', 'fixtures', 'input');

interface SourceProse {
  vulnDiscussion: string;
  fixtext: string;
  checkContent: string[];
}

function decodeEntities(s: string): string {
  const named: Record<string, string> = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&' };
  return s.replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));/g, (_m, dec?: string, hex?: string, name?: string) =>
    dec ? String.fromCodePoint(Number(dec)) : hex ? String.fromCodePoint(Number.parseInt(hex, 16)) : named[name!]!);
}

// Each Rule's prose read straight from the document text, independently of the
// converter's parser: entities decoded, and line endings folded to LF, which
// XML 1.0 §2.11 requires of every conforming parser, so LF-normalized text is
// the most any reader can recover. Neither fixture carries CDATA or comments in
// these elements, which is what makes a text-level read exact.
function readSourceProse(doc: string): Map<string, SourceProse> {
  const lf = doc.replace(/\r\n?/g, '\n');
  const out = new Map<string, SourceProse>();
  for (const m of lf.matchAll(/<(?:\w+:)?Rule\s[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/(?:\w+:)?Rule>/g)) {
    const id = /SV-\d+/.exec(m[1]!)?.[0] ?? m[1]!;
    const body = m[2]!;
    const field = (tag: string): string[] =>
      [...body.matchAll(new RegExp(`<(?:\\w+:)?${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:\\w+:)?${tag}>`, 'g'))].map((f) => decodeEntities(f[1]!));
    const description = field('description')[0] ?? '';
    out.set(id, {
      vulnDiscussion: /<VulnDiscussion>([\s\S]*?)<\/VulnDiscussion>/.exec(description)?.[1] ?? '',
      fixtext: field('fixtext')[0] ?? '',
      checkContent: field('check-content'),
    });
  }
  return out;
}

// Compares default, check and fix byte-for-byte with the source and returns how
// many multi-line values were compared, so a fixture that loses its line breaks
// fails instead of passing vacuously.
function assertProseReadback(src: Map<string, SourceProse>, id: string, descs: Description[]): number {
  const rule = src.get(id);
  expect(rule, `requirement ${id} has no source Rule`).toBeDefined();
  let multiline = 0;
  const check = (label: string, want: string): void => {
    if (!want) return;
    const got = descs.find((d) => d.label === label)?.data;
    expect(got, `${id}: "${label}" description is not the source text`).toBe(want);
    if (want.includes('\n')) multiline++;
  };
  check('default', rule!.vulnDiscussion);
  check('fix', rule!.fixtext);
  if (rule!.checkContent.length === 1) check('check', rule!.checkContent[0]!);
  return multiline;
}

describe('XCCDF prose carries the source line breaks', () => {
  it('benchmark path: the real Cisco IOS XE Router NDM STIG', async () => {
    const doc = readFileSync(join(inputDir, 'benchmark-stig-cisco-iosxe-router-ndm.xml'), 'utf-8');
    const src = readSourceProse(doc);

    const rule = src.get('SV-215812');
    expect(rule, 'the fixture must keep SV-215812').toBeDefined();
    expect(rule!.checkContent[0], "the fixture's check-content lost its line breaks").toContain('line vty 0 1\n access-class MANAGEMENT_NET in\n');
    expect(rule!.fixtext, "the fixture's fixtext lost its trailing spaces or line breaks").toContain('MANAGEMENT_NET \nSW2(config-std-nacl)#permit');
    expect(src.get('SV-215844')!.fixtext.endsWith('\n'), "the fixture's trailing-newline fixtext was trimmed").toBe(true);

    const baseline = JSON.parse(await convertXccdfBenchmarkToHdf(doc)) as HDFBaseline;
    expect(baseline.requirements).toHaveLength(src.size);
    let multiline = 0;
    for (const req of baseline.requirements) {
      multiline += assertProseReadback(src, req.id, req.descriptions);
    }
    expect(multiline, 'expected multi-line check and fix text on every rule').toBeGreaterThanOrEqual(2 * src.size);
  });

  it('results path: the real SCC RHEL 8 run', async () => {
    const doc = readFileSync(join(inputDir, 'xccdf-results-scc-rhel8.xml'), 'utf-8');
    const src = readSourceProse(doc);

    const results = JSON.parse(await convertXccdfResultsToHdf(doc)) as HDFResults;
    let multiline = 0;
    let compared = 0;
    for (const b of results.baselines) {
      for (const req of b.requirements) {
        multiline += assertProseReadback(src, req.id, req.descriptions);
        compared++;
      }
    }
    expect(compared).toBeGreaterThan(0);
    expect(multiline, 'the fixture no longer carries multi-line prose').toBeGreaterThan(0);
  });
});
