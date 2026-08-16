import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { convertGosecToHdf } from './converter.js';
import { runConverterContractTests } from '../../../shared/typescript/converter-contract.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';
import { assertRequirementCount } from '../../../shared/typescript/anchor.js';
import type { HDFResults } from '@mitre/hdf-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, 'input', name), 'utf-8');
}

// countDistinctGosecRules parses raw gosec JSON generically — NOT via the
// converter's parser — and returns the number of distinct rule_id values.
// gosec's emission unit is the distinct rule (issues sharing a rule_id collapse
// into one requirement with many results), so a plain Issues count would
// overshoot.
function countDistinctGosecRules(input: string): number {
  const doc = JSON.parse(input) as { Issues?: Array<{ rule_id?: string }> };
  const distinct = new Set((doc.Issues ?? []).map((i) => i.rule_id));
  return distinct.size;
}

runConverterContractTests({
  converterName: 'gosec-to-hdf',
  convertFn: convertGosecToHdf,
  minimalFixture: 'ethereum.json',
});

// Ground-truth anchor (input-derived count; see shared/typescript/anchor.ts):
// one requirement per DISTINCT rule_id, counted independently of the converter's
// parser so a silent under-extraction fails even when Go/TS agree. ethereum.json's
// 173 issues collapse to 5 rules.
describe('gosec-to-hdf ground-truth anchor', () => {
  it('emits one requirement per distinct rule_id', async () => {
    const input = loadFixture('ethereum.json');
    assertRequirementCount(
      await convertGosecToHdf(input),
      countDistinctGosecRules(input),
      'ethereum.json: one requirement per distinct rule_id',
    );
  });
});

describe('gosec to HDF converter', async () => {
  describe('convertGosecToHdf', async () => {
    it('should throw when Issues field is missing', async () => {
      await expect(convertGosecToHdf(JSON.stringify({ GosecVersion: '2.18.0' }))).rejects.toThrow(
        'missing or invalid Issues field'
      );
    });

    it('should produce valid HDF structure from Go Ethereum fixture', async () => {
      const output = await convertGosecToHdf(loadFixture('ethereum.json'));
      const hdf = JSON.parse(output) as HDFResults;
      expectValidResults(hdf);

      expect(hdf.timestamp).toBeTruthy();
      expect(hdf.generator?.name).toBe('gosec-to-hdf');
      expect(hdf.generator?.version).toBe('1.0.0');
      expect(hdf.tool?.name).toBe('gosec');
      expect(hdf.tool?.version).toBe('dev');
      expect(hdf.tool?.format).toBeUndefined();
      expect(hdf.baselines).toHaveLength(1);
    });

    it('should use "gosec Scan" as the baseline name', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      expect(hdf.baselines[0]!.name).toBe('gosec Scan');
    });

    it('should include a sha256 checksum', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const checksum = hdf.baselines[0]!.resultsChecksum;
      expect(checksum?.algorithm).toBe('sha256');
      expect(checksum?.value).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should group issues by rule_id', async () => {
      // ethereum.json has G104, G301, G302, G304, G404 → 5 requirements
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;

      expect(reqs).toHaveLength(5);
      const ids = reqs.map(r => r.id).sort();
      expect(ids).toEqual(['G104', 'G301', 'G302', 'G304', 'G404']);
    });

    it('should create multiple results for repeated rule_id', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.results).toHaveLength(6);
    });

    it('should map HIGH severity to 0.7', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.impact).toBe(0.7);
    });

    it('should map MEDIUM severity to 0.5', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.impact).toBe(0.5);
    });

    it('should map LOW severity to 0.3', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g104 = hdf.baselines[0]!.requirements.find(r => r.id === 'G104');
      expect(g104?.impact).toBe(0.3);
    });

    it('should mark non-suppressed issues as failed', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      for (const result of g304!.results) {
        expect(result.status).toBe('failed');
      }
    });

    it('should mark externally suppressed issues as notReviewed', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      // G301 has 2 issues, both with external suppression
      const g301 = hdf.baselines[0]!.requirements.find(r => r.id === 'G301');
      expect(g301?.results).toHaveLength(2);
      for (const result of g301!.results) {
        expect(result.status).toBe('notReviewed');
      }
    });

    it('should include justification in skip message', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g301 = hdf.baselines[0]!.requirements.find(r => r.id === 'G301');
      expect(g301?.results[0]?.message).toContain('Globally suppressed.');
      expect(g301?.results[0]?.message).toContain('external');
    });

    it('should include code_desc with rule, file, and line', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const codeDesc = g304?.results[0]?.codeDesc ?? '';
      expect(codeDesc).toContain('G304');
      expect(codeDesc).toContain('go-ethereum-master');
    });

    it('should set requirement.code to the first issue\'s literal source (CODE tab)', async () => {
      const input = loadFixture('ethereum.json');
      const doc = JSON.parse(input) as { Issues: Array<{ rule_id: string; code: string }> };
      const firstCode = new Map<string, string>();
      for (const iss of doc.Issues) {
        if (!firstCode.has(iss.rule_id)) firstCode.set(iss.rule_id, iss.code);
      }

      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      for (const req of hdf.baselines[0]!.requirements) {
        expect(req.code, `requirement ${req.id} missing code`).toBe(firstCode.get(req.id));
      }
    });

    it('should include a default description with rule details text', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const defaultDesc = g304?.descriptions?.find(d => d.label === 'default');
      expect(defaultDesc?.data).toBe('Potential file inclusion via variable');
    });

    it('should include a check description with CWE reference', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      const checkDesc = g304?.descriptions?.find(d => d.label === 'check');
      expect(checkDesc?.data).toContain('CWE-22');
      expect(checkDesc?.data).toContain('cwe.mitre.org');
    });

    it('should tag the gosec confidence rating (G304 → HIGH)', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.tags?.['confidence']).toBe('HIGH');
    });

    it('should omit the confidence tag when source confidence is empty', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'MEDIUM', confidence: '',
          cwe: { id: '22', url: 'https://cwe.mitre.org/data/definitions/22.html' },
          rule_id: 'G304', details: 'File inclusion',
          file: '/app/main.go', code: 'f, _ := os.Open(x)\n',
          line: '5', column: '2', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 10, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['confidence']).toBeUndefined();
    });

    it('should promote the finding locus into structured sourceLocation (G304 → bloom.go:86)', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.sourceLocation?.ref).toBe(
        'C:\\Users\\chu\\Downloads\\go-ethereum-master\\core\\state\\pruner\\bloom.go',
      );
      expect(g304?.sourceLocation?.line).toBe(86);
    });

    it('should use the start line of a range for sourceLocation.line', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'MEDIUM', confidence: 'HIGH',
          cwe: { id: '22', url: 'https://cwe.mitre.org/data/definitions/22.html' },
          rule_id: 'G304', details: 'File inclusion',
          file: '/app/main.go', code: 'os.Open(x)\n',
          line: '108-110', column: '2', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 10, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.sourceLocation?.ref).toBe('/app/main.go');
      expect(req.sourceLocation?.line).toBe(108);
    });

    it('should omit sourceLocation when the issue carries no file', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'MEDIUM', confidence: 'HIGH',
          cwe: { id: '22', url: 'https://cwe.mitre.org/data/definitions/22.html' },
          rule_id: 'G304', details: 'File inclusion',
          file: '', code: 'f, _ := os.Open(x)\n',
          line: '5', column: '2', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 10, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.sourceLocation).toBeUndefined();
    });

    it('should look up NIST tags from CWE (CWE-338 → SC-13)', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g404 = hdf.baselines[0]!.requirements.find(r => r.id === 'G404');
      expect(g404?.tags?.['nist']).toContain('SC-13');
    });

    it('should fall back to ["SI-2", "RA-5"] for unknown CWE', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'MEDIUM', confidence: 'HIGH',
          cwe: { id: '99999', url: '' },
          rule_id: 'G999', details: 'Unknown',
          file: '/app/main.go', code: 'x()\n',
          line: '1', column: '1', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 5, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.tags?.['nist']).toEqual(['SI-2', 'RA-5']);
    });

    it('should populate first-class cwe[] and drop the cwe tag', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const g304 = hdf.baselines[0]!.requirements.find(r => r.id === 'G304');
      expect(g304?.cwe).toEqual(['CWE-22']);
      // Legacy tags.cwe object is removed; tags.nist stays.
      expect(g304?.tags?.['cwe']).toBeUndefined();
      expect(g304?.tags?.['nist']).toBeDefined();
    });

    it('should omit cwe[] when the issue carries no CWE id', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [{
          severity: 'LOW', confidence: 'HIGH',
          cwe: { id: '', url: '' },
          rule_id: 'G000', details: 'No CWE',
          file: '/app/main.go', code: 'x()\n',
          line: '1', column: '1', nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 5, nosec: 0, found: 1 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.cwe).toBeUndefined();
    });

    it('should synthesize a passed placeholder for empty Issues array', async () => {
      const input = JSON.stringify({
        'Golang errors': {},
        Issues: [],
        Stats: { files: 0, lines: 0, nosec: 0, found: 0 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('gosec-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('gosec');
      expect(req.results[0]!.codeDesc).toContain('Go codebase');
    });

    it('should synthesize a passed placeholder for the empty fixture', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('empty.json'))) as HDFResults;
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.requirements).toHaveLength(1);
      const req = hdf.baselines[0]!.requirements[0]!;
      expect(req.id).toBe('gosec-no-findings');
      expect(req.results[0]!.status).toBe('passed');
      expect(req.results[0]!.codeDesc).toContain('gosec');
      expect(req.results[0]!.codeDesc).toContain('Go codebase');
    });

    it('should handle real fixture without errors', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('real.json'))) as HDFResults;
      const reqs = hdf.baselines[0]!.requirements;
      expect(reqs.length).toBeGreaterThan(0);
      for (const req of reqs) {
        expect(req.id).toBeTruthy();
        expect(req.results.length).toBeGreaterThan(0);
      }
    });
  });

  describe('auxiliary scan metadata (baseline.extensions.gosec)', async () => {
    it('should route Stats into baseline.extensions.gosec.stats', async () => {
      // ethereum.json carries Stats={files:156,lines:46219,nosec:0,found:171}.
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;
      const ext = hdf.baselines[0]!.extensions as { gosec?: { stats?: unknown; goErrors?: unknown } } | undefined;
      expect(ext?.gosec?.stats).toEqual({ files: 156, lines: 46219, nosec: 0, found: 171 });
      // Empty "Golang errors" → goErrors omitted.
      expect(ext?.gosec?.goErrors).toBeUndefined();
    });

    it('should flatten non-empty Golang errors into goErrors, sorted by file', async () => {
      const input = JSON.stringify({
        'Golang errors': {
          '/app/z.go': [{ line: 3, column: 1, error: "expected ';', found 'EOF'" }],
          '/app/a.go': [
            { line: 10, column: 5, error: 'undefined: Foo' },
            { line: 12, column: 2, error: 'undefined: Bar' },
          ],
        },
        Issues: [],
        Stats: { files: 2, lines: 40, nosec: 0, found: 0 },
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      const ext = hdf.baselines[0]!.extensions as { gosec?: { stats?: unknown; goErrors?: unknown } } | undefined;
      expect(ext?.gosec?.goErrors).toEqual([
        { file: '/app/a.go', line: 10, column: 5, error: 'undefined: Foo' },
        { file: '/app/a.go', line: 12, column: 2, error: 'undefined: Bar' },
        { file: '/app/z.go', line: 3, column: 1, error: "expected ';', found 'EOF'" },
      ]);
      expect(ext?.gosec?.stats).toEqual({ files: 2, lines: 40, nosec: 0, found: 0 });
    });

    it('should omit extensions entirely when neither Stats nor Golang errors is present', async () => {
      const input = JSON.stringify({
        Issues: [{
          severity: 'LOW', confidence: 'HIGH',
          cwe: { id: '703', url: 'https://cwe.mitre.org/data/definitions/703.html' },
          rule_id: 'G104', details: 'Errors unhandled.',
          file: '/app/main.go', code: 'defer f.Close()\n',
          line: '5', column: '2', nosec: false, suppressions: null,
        }],
        GosecVersion: '2.18.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.extensions).toBeUndefined();
    });
  });

  describe('SARIF format routing', async () => {
    function loadSarifFixture(name: string): string {
      return readFileSync(join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'input', name), 'utf-8');
    }

    it('should detect SARIF input and delegate to SARIF converter', async () => {
      const input = loadSarifFixture('gosec.sarif');
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;

      // SARIF converter uses tool driver name as baseline name
      expect(hdf.baselines).toHaveLength(1);
      expect(hdf.baselines[0]!.name).toBe('gosec');
      expect(hdf.baselines[0]!.requirements.length).toBeGreaterThan(0);

      // Verify enriched SARIF data — CWE from relationships
      const g201 = hdf.baselines[0]!.requirements.find(r => r.id === 'G201');
      expect(g201).toBeDefined();
      expect(g201!.tags.cwe).toContain('CWE-89');
    });

    it('should not route native gosec JSON to SARIF converter', async () => {
      const hdf = JSON.parse(await convertGosecToHdf(loadFixture('ethereum.json'))) as HDFResults;

      // Native output uses "gosec Scan" baseline name
      expect(hdf.baselines[0]!.name).toBe('gosec Scan');
    });
  });

  describe('edge cases: missing fields and suppressed issues', async () => {
    it('should handle suppressed issue via nosec flag', async () => {
      const input = JSON.stringify({
        Issues: [{
          severity: 'HIGH', confidence: 'HIGH',
          cwe: { id: '123', url: 'https://cwe.mitre.org/data/definitions/123.html' },
          rule_id: 'G101', details: 'Suppressed issue',
          file: 'main.go', code: 'code', line: '10', column: '5',
          nosec: true, suppressions: null,
        }],
        Stats: { files: 1, lines: 100, nosec: 1, found: 1 },
        GosecVersion: '2.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
    });

    it('should handle issue with suppressions list', async () => {
      const input = JSON.stringify({
        Issues: [{
          severity: 'MEDIUM', confidence: 'LOW',
          cwe: { id: '456', url: 'https://example.com' },
          rule_id: 'G102', details: 'With suppressions',
          file: 'util.go', code: 'code', line: '20', column: '1',
          nosec: false, suppressions: [{ kind: 'inSource', justification: 'false positive' }],
        }],
        Stats: { files: 1, lines: 100, nosec: 0, found: 1 },
        GosecVersion: '',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.status).toBe('notReviewed');
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toContain('false positive');
      // No GosecVersion → no version on tool
      expect(hdf.tool?.version).toBeUndefined();
    });

    it('should handle empty suppressions list', async () => {
      const input = JSON.stringify({
        Issues: [{
          severity: 'LOW', confidence: 'HIGH',
          cwe: { id: '789', url: 'https://example.com' },
          rule_id: 'G103', details: 'Empty suppressions',
          file: 'main.go', code: 'code', line: '30', column: '1',
          nosec: false, suppressions: [],
        }],
        Stats: { files: 1, lines: 100, nosec: 0, found: 1 },
        GosecVersion: '2.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.results[0]!.message).toContain('No justification');
    });

    it('should handle unknown severity', async () => {
      const input = JSON.stringify({
        Issues: [{
          severity: 'UNKNOWN', confidence: 'HIGH',
          cwe: { id: '100', url: 'https://example.com' },
          rule_id: 'G104', details: 'Unknown sev',
          file: 'main.go', code: 'code', line: '1', column: '1',
          nosec: false, suppressions: null,
        }],
        Stats: { files: 1, lines: 100, nosec: 0, found: 1 },
        GosecVersion: '2.0',
      });
      const hdf = JSON.parse(await convertGosecToHdf(input)) as HDFResults;
      expect(hdf.baselines[0]!.requirements[0]!.impact).toBe(0.5);
    });
  });
});
