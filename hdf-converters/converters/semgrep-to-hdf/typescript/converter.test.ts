import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertSemgrepToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { ResultStatus } from '@mitre/hdf-schema';
import type { HDFResults, EvaluatedRequirement } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

async function convert(name: string): Promise<HDFResults> {
  return JSON.parse(await convertSemgrepToHdf(loadFixture(name))) as HDFResults;
}

function findReq(hdf: HDFResults, idFragment: string): EvaluatedRequirement | undefined {
  return hdf.baselines[0]!.requirements.find((r) => r.id.includes(idFragment));
}

runConverterContractTests({
  converterName: 'semgrep-to-hdf',
  convertFn: convertSemgrepToHdf,
  minimalFixture: 'minimal.json',
});

describe('semgrep to HDF converter', () => {
  it('rejects input that is not a Semgrep report', async () => {
    await expect(convertSemgrepToHdf('{"foo":1}')).rejects.toThrow(
      'does not look like a Semgrep report',
    );
  });

  describe('real fixture', () => {
    it('produces a schema-valid, correctly-shaped document', async () => {
      const hdf = await convert('real.json');
      expectValidResults(hdf);

      const bl = hdf.baselines[0]!;
      expect(bl.name).toBe('Semgrep Scan');
      expect(hdf.tool?.name).toBe('Semgrep');
      expect(hdf.tool?.version).toBe('1.174.0');
      expect(hdf.generator?.name).toBe('semgrep-to-hdf');
    });

    it('groups findings into one requirement per rule', async () => {
      const hdf = await convert('real.json');
      const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
      expect(new Set(ids).size).toBe(ids.length);
      // Two rules plus the always-present coverage record.
      expect(ids).toHaveLength(3);
      expect(ids[ids.length - 1]).toBe('semgrep-scan-coverage');
    });

    it('maps semgrep severity onto impact', async () => {
      const hdf = await convert('real.json');
      // ERROR severity
      expect(findReq(hdf, 'subprocess-shell-true')?.impact).toBe(0.7);
      // WARNING severity
      expect(findReq(hdf, 'dynamic-urllib-use-detected')?.impact).toBe(0.5);
    });

    it('resolves NIST tags from the rule CWE', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true');
      expect(req?.tags?.nist).toBeDefined();
      expect(Array.isArray(req?.tags?.nist)).toBe(true);
      expect((req?.tags?.nist as string[]).length).toBeGreaterThan(0);
    });

    it('derives CCI tags from the resolved NIST controls', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true')!;
      expect(Array.isArray(req.tags?.cci)).toBe(true);
      expect((req.tags?.cci as string[]).length).toBeGreaterThan(0);
      for (const cci of req.tags?.cci as string[]) {
        expect(cci).toMatch(/^CCI-\d+$/);
      }
    });

    it('normalizes owasp whether the rule supplies a string or an array', async () => {
      const hdf = await convert('real.json');
      for (const req of hdf.baselines[0]!.requirements) {
        if (req.id === 'semgrep-scan-coverage') continue;
        expect(Array.isArray(req.tags?.owasp)).toBe(true);
      }
      // real.json deliberately carries one of each form
      expect((findReq(hdf, 'subprocess-shell-true')?.tags?.owasp as string[]).length).toBe(3);
      expect((findReq(hdf, 'dynamic-urllib-use-detected')?.tags?.owasp as string[]).length).toBe(1);
    });

    it('does not let semgrep metadata impact shadow the HDF impact float', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'subprocess-shell-true')!;
      expect(typeof req.impact).toBe('number');
      expect(req.tags?.impact).toBeUndefined();
      expect(req.tags?.semgrepImpact).toBe('LOW');
    });

    it('preserves the cross-framework metadata SARIF drops', async () => {
      const hdf = await convert('real.json');
      const req = findReq(hdf, 'dynamic-urllib-use-detected')!;
      expect(req.tags?.likelihood).toBe('LOW');
      expect(req.tags?.confidence).toBe('LOW');
      expect(req.tags?.asvs).toBeDefined();
      expect(req.tags?.vulnerabilityClass).toBeDefined();
    });

    it('reports every finding as failed, since semgrep omits suppressed findings', async () => {
      const hdf = await convert('real.json');
      for (const req of hdf.baselines[0]!.requirements) {
        if (req.id === 'semgrep-scan-coverage') continue;
        for (const result of req.results) {
          expect(result.status).toBe(ResultStatus.Failed);
        }
      }
    });

    it('never emits the redacted placeholder semgrep uses in unauthenticated scans', async () => {
      const hdf = await convert('real.json');
      expect(JSON.stringify(hdf)).not.toContain('requires login');
    });

    it('records the finding location in codeDesc', async () => {
      const hdf = await convert('real.json');
      const result = findReq(hdf, 'subprocess-shell-true')!.results[0]!;
      expect(result.codeDesc).toContain('app/handlers.py');
      expect(result.codeDesc).toContain('7');
    });
  });

  describe('empty fixture', () => {
    it('produces a no-findings requirement plus the coverage record', async () => {
      const hdf = await convert('empty.json');
      expectValidResults(hdf);
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs).toHaveLength(2);
      expect(reqs[0]!.id).toBe('semgrep-no-findings');
      expect(reqs[0]!.results[0]!.status).toBe(ResultStatus.Passed);
      expect(reqs[1]!.id).toBe('semgrep-scan-coverage');
    });
  });

  describe('errors fixture', () => {
    it('surfaces scan errors as their own requirement, advisory entries notReviewed', async () => {
      const hdf = await convert('errors.json');
      expectValidResults(hdf);
      const req = findReq(hdf, 'semgrep-scan-errors');
      expect(req).toBeDefined();
      expect(req!.results.length).toBe(2);
      // Both entries in errors.json are level "warn" (advisory PartialParsing):
      // partially analyzed files are a genuine non-evaluation of those paths,
      // not a scan failure, so they must not dominate worst-wins rollups.
      for (const result of req!.results) {
        expect(result.status).toBe(ResultStatus.NotReviewed);
        expect(result.message).toContain('warn');
      }
    });

    it('omits the scan-errors requirement when the scan reported none', async () => {
      const hdf = await convert('real.json');
      expect(findReq(hdf, 'semgrep-scan-errors')).toBeUndefined();
    });
  });
});

describe('sparse and malformed rules', () => {
  function scan(results: unknown[], extra: Record<string, unknown> = {}): string {
    return JSON.stringify({
      version: '1.174.0',
      results,
      errors: [],
      paths: { scanned: ['a.py'] },
      engine_requested: 'OSS',
      ...extra,
    });
  }

  it('converts a rule that declares no metadata at all', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(scan([{ check_id: 'bare.rule', path: 'a.py' }])),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]!;
    // Falls back to the static-analysis default tags.
    expect(req.tags?.nist).toEqual(['SA-11', 'RA-5']);
    expect(req.tags?.owasp).toBeUndefined();
    expect(req.tags?.confidence).toBeUndefined();
    expect(req.tags?.likelihood).toBeUndefined();
    expect(req.tags?.semgrepImpact).toBeUndefined();
    expect(req.tags?.category).toBeUndefined();
    expect(req.tags?.banditCode).toBeUndefined();
    expect(req.tags?.asvs).toBeUndefined();
    expect(req.tags?.references).toBeUndefined();
    expect(req.tags?.subcategory).toBeUndefined();
    expect(req.tags?.technology).toBeUndefined();
    expect(req.tags?.vulnerabilityClass).toBeUndefined();
    // No location fields at all.
    expect(req.results[0]!.codeDesc).toBe('Path: a.py');
    expect(req.results[0]!.message).toBe('');
  });

  it('falls back to moderate impact for an unknown or absent severity', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'a', extra: { severity: 'NOVEL' } },
          { check_id: 'b' },
          { check_id: 'c', extra: { severity: 'CRITICAL' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'a')!.impact).toBe(0.5);
    expect(reqs.find((r) => r.id === 'b')!.impact).toBe(0.5);
    expect(reqs.find((r) => r.id === 'c')!.impact).toBe(0.9);
  });

  it('renders a multi-line span and a path-only location', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'span', path: 'a.py', start: { line: 4 }, end: { line: 9 } },
          { check_id: 'single', path: 'a.py', start: { line: 4 }, end: { line: 4 } },
          { check_id: 'nopath' },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'span')!.results[0]!.codeDesc).toBe('Path: a.py, lines 4-9');
    expect(reqs.find((r) => r.id === 'single')!.results[0]!.codeDesc).toBe('Path: a.py, line 4');
    expect(reqs.find((r) => r.id === 'nopath')!.results[0]!.codeDesc).toBe('Path: unknown');
  });

  it('drops redacted fields but keeps real ones', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'redacted', extra: { lines: 'requires login', fingerprint: 'requires login' } },
          { check_id: 'real', extra: { lines: 'x = 1' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'redacted')!.results[0]!.message).toBe('');
    expect(reqs.find((r) => r.id === 'real')!.results[0]!.message).toContain('Matched code:');
  });

  it('skips findings with no check_id and falls back to the no-findings placeholder', async () => {
    const hdf = JSON.parse(await convertSemgrepToHdf(scan([{ path: 'a.py' }]))) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('semgrep-no-findings');
  });

  it('skips a finding whose check_id is the empty string, matching Go', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(scan([{ check_id: '', path: 'a.py', start: { line: 1 } }])),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.id).toBe('semgrep-no-findings');
  });

  it('collapses repeated occurrences of one rule into a single requirement', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'dup', path: 'a.py', start: { line: 1 }, end: { line: 1 } },
          { check_id: 'dup', path: 'b.py', start: { line: 2 }, end: { line: 2 } },
        ]),
      ),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements).toHaveLength(2);
    expect(hdf.baselines[0]!.requirements[0]!.results).toHaveLength(2);
  });

  it('deduplicates reference urls drawn from several metadata fields', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          {
            check_id: 'refs',
            extra: {
              metadata: {
                references: ['https://a', 'https://a'],
                source: 'https://a',
                shortlink: 'https://b',
                'source-rule-url': '',
                asvs: { control_url: 'https://c' },
              },
            },
          },
        ]),
      ),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements[0]!;
    expect(req.refs?.map((r) => r.url)).toEqual(['https://a', 'https://b', 'https://c']);
    expect(req.tags?.references).toBeUndefined();
  });

  it('ignores a CWE entry that carries no parsable id', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([{ check_id: 'badcwe', extra: { metadata: { cwe: ['not a cwe reference'] } } }]),
      ),
    ) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.tags?.nist).toEqual(['SA-11', 'RA-5']);
  });

  it('handles scan errors whose type is a bare string or absent', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        JSON.stringify({
          version: '1.174.0',
          results: [],
          errors: [
            { message: 'a', type: 'PlainString', path: 'x.yml' },
            { message: 'b' },
          ],
          paths: { scanned: [] },
        }),
      ),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'semgrep-scan-errors')!;
    expect(req.results[0]!.message).toContain('PlainString');
    expect(req.results[1]!.message).toContain('Unknown');
    expect(req.results[1]!.codeDesc).toBe('Path: unknown');
  });

  it('derives a title from a single-segment rule id', async () => {
    const hdf = JSON.parse(await convertSemgrepToHdf(scan([{ check_id: 'rule' }]))) as HDFResults;
    expect(hdf.baselines[0]!.requirements[0]!.title).toBe('Rule');
  });
});

describe('remediation: robustness, parity, and field homes', () => {
  function scan(results: unknown[], extra: Record<string, unknown> = {}): string {
    return JSON.stringify({
      version: '1.174.0',
      results,
      errors: [],
      paths: { scanned: ['a.py'] },
      ...extra,
    });
  }

  it('survives prototype-named severity tokens with a numeric default, matching Go', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'a.proto', path: 'a.py', start: { line: 1 }, extra: { severity: 'constructor' } },
          { check_id: 'b.proto', path: 'a.py', start: { line: 2 }, extra: { severity: '__proto__' } },
        ]),
      ),
    ) as HDFResults;
    for (const id of ['a.proto', 'b.proto']) {
      const req = hdf.baselines[0]!.requirements.find((r) => r.id === id)!;
      expect(typeof req.impact).toBe('number');
      expect(req.impact).toBe(0.5);
    }
  });

  it('maps the native three-level scale through the shared alias table', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'e', extra: { severity: 'ERROR' } },
          { check_id: 'w', extra: { severity: 'WARNING' } },
          { check_id: 'i', extra: { severity: 'INFO' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'e')!.impact).toBe(0.7);
    expect(reqs.find((r) => r.id === 'w')!.impact).toBe(0.5);
    expect(reqs.find((r) => r.id === 'i')!.impact).toBe(0.3);
  });

  it('marks an absent or redacted severity with the shared unrated marker', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'a.unrated', extra: { message: 'm' } },
          { check_id: 'a.redacted', extra: { message: 'm', severity: 'requires login' } },
          { check_id: 'a.novel', extra: { message: 'm', severity: 'NOVEL' } },
          { check_id: 'a.rated', extra: { message: 'm', severity: 'HIGH' } },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'a.unrated')!.tags?.severity_rating).toBe('unrated');
    expect(reqs.find((r) => r.id === 'a.redacted')!.tags?.severity_rating).toBe('unrated');
    expect(reqs.find((r) => r.id === 'a.novel')!.tags?.severity_rating).toBeUndefined();
    expect(reqs.find((r) => r.id === 'a.rated')!.tags?.severity_rating).toBeUndefined();
  });

  it('tolerates wrong-typed freeform metadata per-field, like Go', async () => {
    const inputs = [
      scan([{ check_id: 'a.b', path: 'a.py', start: { line: 1 }, extra: { message: 'm', severity: 'ERROR', metadata: { confidence: 3 } } }]),
      scan([{ check_id: 'a.b', path: 'a.py', start: { line: 1 }, extra: { message: 'm', severity: 'ERROR', metadata: { asvs: [] } } }]),
      scan([{ check_id: 'a.b', path: 'a.py', start: { line: 1 }, extra: { message: 'm', severity: 'ERROR', metadata: 'oops' } }]),
      scan([{ check_id: 'a.b', path: 'a.py', start: { line: '7' }, extra: { message: 'm', severity: 'ERROR' } }]),
    ];
    for (const input of inputs) {
      const hdf = JSON.parse(await convertSemgrepToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements.find((r) => r.id === 'a.b')).toBeDefined();
    }
  });

  it('filters string entries out of mixed-type metadata arrays, keeping the CWE mapping', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          {
            check_id: 'a.b',
            path: 'a.py',
            start: { line: 1 },
            extra: {
              message: 'm',
              severity: 'ERROR',
              metadata: { cwe: ['CWE-89: SQL Injection', 5], references: ['https://x', 7] },
            },
          },
        ]),
      ),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'a.b')!;
    expect(req.tags?.cwe).toEqual(['CWE-89: SQL Injection']);
    expect(req.tags?.nist).toContain('SI-10');
    expect(req.tags?.nist).not.toContain('SA-11');
    expect(req.refs?.map((r) => r.url)).toEqual(['https://x']);
  });

  it('omits tags.cwe entirely when the rule has no CWE metadata', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(scan([{ check_id: 'local.rule', extra: { severity: 'WARNING' } }])),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'local.rule')!;
    expect('cwe' in (req.tags ?? {})).toBe(false);
  });

  it('populates cwe[], sourceLocation, and code on real findings', async () => {
    const hdf = await convert('real.json');
    const req = findReq(hdf, 'subprocess-shell-true')!;
    expect(req.cwe).toBeDefined();
    for (const entry of req.cwe!) {
      expect(entry).toMatch(/^CWE-[1-9]\d*$/);
    }
    expect(req.sourceLocation?.ref).toBe('app/handlers.py');
    expect(req.sourceLocation?.line).toBe(7);
    expect(req.code).toContain('subprocess-shell-true');
    expect(req.code).toContain('"check_id"');
    expect(req.refs?.length).toBeGreaterThan(0);
    expect(req.tags?.references).toBeUndefined();
  });

  it('always appends the notApplicable coverage record', async () => {
    for (const fixture of ['minimal.json', 'real.json', 'errors.json', 'empty.json']) {
      const hdf = await convert(fixture);
      const req = findReq(hdf, 'semgrep-scan-coverage');
      expect(req, fixture).toBeDefined();
      expect(req!.impact).toBe(0);
      expect(req!.results[0]!.status).toBe(ResultStatus.NotApplicable);
      expect(req!.results[0]!.codeDesc).toContain('violations only');
    }
  });

  it('keeps the clean-scan statement when a zero-findings scan has errors', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        JSON.stringify({
          version: '1.174.0',
          results: [],
          errors: [{ message: 'partial', level: 'warn', type: ['PartialParsing', []], path: 'a.py' }],
          paths: { scanned: ['a.py', 'b.py'] },
        }),
      ),
    ) as HDFResults;
    const ids = hdf.baselines[0]!.requirements.map((r) => r.id);
    expect(ids).toEqual(['semgrep-no-findings', 'semgrep-scan-errors', 'semgrep-scan-coverage']);
  });

  it('maps error levels onto statuses: error stays error, warn becomes notReviewed', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        JSON.stringify({
          results: [],
          errors: [
            { message: 'fatal', level: 'error', type: 'SemgrepError' },
            { message: 'advisory', level: 'warn', type: ['PartialParsing', []] },
            { message: 'unlabeled', type: 'SemgrepError' },
          ],
          paths: { scanned: [] },
        }),
      ),
    ) as HDFResults;
    const req = hdf.baselines[0]!.requirements.find((r) => r.id === 'semgrep-scan-errors')!;
    expect(req.results[0]!.status).toBe(ResultStatus.Error);
    expect(req.results[1]!.status).toBe(ResultStatus.NotReviewed);
    expect(req.results[2]!.status).toBe(ResultStatus.Error);
    expect(req.tags?.severity_rating).toBe('unrated');
  });

  it('rejects null results/errors containers, agreeing with both fingerprints', async () => {
    for (const input of [
      '{"results":null,"errors":[],"paths":{"scanned":[]}}',
      '{"results":[],"errors":null,"paths":{"scanned":[]}}',
    ]) {
      await expect(convertSemgrepToHdf(input)).rejects.toThrow('does not look like a Semgrep report');
    }
  });

  it('rejects a top-level JSON null with the clean format error, not a TypeError', async () => {
    await expect(convertSemgrepToHdf('null')).rejects.toThrow('does not look like a Semgrep report');
  });

  it('derives titles identically to Go on separator runs and non-word characters', async () => {
    const hdf = JSON.parse(
      await convertSemgrepToHdf(
        scan([
          { check_id: 'python.lang.foo--bar_-baz' },
          { check_id: 'rules.eval/exec-check' },
        ]),
      ),
    ) as HDFResults;
    const reqs = hdf.baselines[0]!.requirements;
    expect(reqs.find((r) => r.id === 'python.lang.foo--bar_-baz')!.title).toBe('Foo Bar Baz');
    expect(reqs.find((r) => r.id === 'rules.eval/exec-check')!.title).toBe('Eval/exec Check');
  });

  it('omits tool.format: JSON is an encoding, not a format specification', async () => {
    const hdf = await convert('minimal.json');
    expect(hdf.tool?.format).toBeUndefined();
  });

  it('delegates SARIF input to the SARIF converter', async () => {
    const sarifInput = readFileSync(
      join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', 'semgrep.sarif'),
      'utf-8',
    );
    const hdf = JSON.parse(await convertSemgrepToHdf(sarifInput)) as HDFResults;
    expect(hdf.baselines[0]!.name).toBe('Semgrep OSS');
  });

  it('does not route native input to the SARIF converter', async () => {
    const hdf = await convert('real.json');
    expect(hdf.baselines[0]!.name).toBe('Semgrep Scan');
  });
});

describe('semgrep fingerprint scoring', () => {
  it('scores real semgrep output 1.0 and rejects non-semgrep shapes', async () => {
    const { semgrepFingerprint } = await import('./fingerprint.js');
    const real = JSON.parse(loadFixture('real.json')) as unknown;
    expect(semgrepFingerprint.fingerprint(real)).toBe(1.0);
    expect(semgrepFingerprint.fingerprint(JSON.parse(loadFixture('empty.json')))).toBeGreaterThan(0.5);
    for (const bad of [
      null,
      [],
      { results: null, errors: [] },
      { results: [], errors: null },
      { results: [], errors: [] }, // no paths.scanned
      { foo: 1 },
    ]) {
      expect(semgrepFingerprint.fingerprint(bad)).toBe(0);
    }
  });

  it('reads the version marker', async () => {
    const { semgrepFingerprint } = await import('./fingerprint.js');
    expect(semgrepFingerprint.detectVersion?.(JSON.parse(loadFixture('real.json')))).toBe('1.174.0');
    expect(semgrepFingerprint.detectVersion?.({ version: 5 })).toBe('');
  });
});
