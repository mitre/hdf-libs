import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
// The suppression pass is a pure function exported by the generator so its
// failure modes are testable without fetching the AWS sources.
import { applySuppressions } from '../scripts/generate-awsconfig-mappings.mjs';
// Import via the package ROOT: this is the surface real consumers get.
import { awsConfigSuppressions } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA = join(__dirname, '..', 'src', 'data');

interface MappingRow {
  AwsConfigRuleSourceIdentifier: string;
  AwsConfigRuleName: string;
  'NIST-ID': string;
  Rev: number;
  Source: string;
}
interface Suppression {
  rule: string;
  control: string;
  revisions: number[];
}

const mappings = JSON.parse(readFileSync(join(DATA, 'awsconfig-mappings.json'), 'utf-8')) as MappingRow[];
const suppressions = JSON.parse(readFileSync(join(DATA, 'awsconfig-suppressions.json'), 'utf-8')) as Suppression[];

const controlsFor = (rule: string, rev: number): string[] =>
  mappings.find((r) => r.AwsConfigRuleName === rule && r.Rev === rev)?.['NIST-ID'].split('|') ?? [];

describe('awsconfig-suppressions.json', () => {
  it('a suppressed pair is absent after generation', () => {
    // The reviewed removal for mq-no-public-access: SC-7(4) must be gone at
    // both revisions in the committed (generated) table.
    expect(controlsFor('mq-no-public-access', 4)).not.toContain('SC-7(4)');
    expect(controlsFor('mq-no-public-access', 5)).not.toContain('SC-7(4)');
  });

  it('every listed pair is absent from the committed table at its listed revisions', () => {
    for (const s of suppressions) {
      for (const rev of s.revisions) {
        expect(controlsFor(s.rule, rev), `${s.rule} ${s.control} rev ${rev}`).not.toContain(s.control);
      }
    }
  });

  it('carries the 37 reviewed pairs and nothing else in the schema', () => {
    expect(suppressions).toHaveLength(37);
    for (const s of suppressions) {
      expect(Object.keys(s).sort()).toEqual(['control', 'revisions', 'rule']);
      expect(s.revisions.length).toBeGreaterThan(0);
      for (const rev of s.revisions) expect([4, 5]).toContain(rev);
    }
  });

  it('is exposed through the package index so consumers can see reviewed removals', () => {
    expect(awsConfigSuppressions).toHaveLength(37);
    expect(awsConfigSuppressions[0]).toHaveProperty('rule');
    expect(awsConfigSuppressions[0]).toHaveProperty('control');
    expect(awsConfigSuppressions[0]).toHaveProperty('revisions');
  });

  it('no suppressed rule lost all of its controls', () => {
    for (const s of suppressions) {
      for (const rev of s.revisions) {
        expect(controlsFor(s.rule, rev).filter(Boolean).length, `${s.rule} rev ${rev}`).toBeGreaterThan(0);
      }
    }
  });
});

describe('applySuppressions (generator pass)', () => {
  const row = (rule: string, controls: string[], rev: number): MappingRow => ({
    AwsConfigRuleSourceIdentifier: rule.toUpperCase().replace(/-/g, '_'),
    AwsConfigRuleName: rule,
    'NIST-ID': controls.join('|'),
    Rev: rev,
    Source: 'config-pack',
  });

  it('removes the pair at each listed revision only', () => {
    const rows = [row('r1', ['AC-1', 'AC-2'], 4), row('r1', ['AC-1', 'AC-2'], 5)];
    applySuppressions(rows, [{ rule: 'r1', control: 'AC-2', revisions: [5] }]);
    expect(rows[0]!['NIST-ID']).toBe('AC-1|AC-2'); // rev 4 untouched
    expect(rows[1]!['NIST-ID']).toBe('AC-1');
  });

  it('rebuild-from-source makes the output idempotent; re-applying to suppressed rows throws', () => {
    const rows = [row('r1', ['AC-1', 'AC-2'], 5)];
    const sup = [{ rule: 'r1', control: 'AC-2', revisions: [5] }];
    applySuppressions(rows, sup);
    const once = rows[0]!['NIST-ID'];
    // A second pass over already-suppressed output must fail loudly (the pair
    // no longer exists) rather than silently doing nothing — same contract as
    // any stale entry. Idempotence of the OUTPUT is achieved because the
    // generator always rebuilds from sources before the pass runs.
    expect(() => applySuppressions(rows, sup)).toThrow(/never produced|not present/i);
    expect(rows[0]!['NIST-ID']).toBe(once);
  });

  it('fails loudly on a suppression the sources never produced', () => {
    const rows = [row('r1', ['AC-1'], 5)];
    expect(() => applySuppressions(rows, [{ rule: 'ghost-rule', control: 'AC-1', revisions: [5] }])).toThrow(
      /never produced|not present/i
    );
    expect(() => applySuppressions(rows, [{ rule: 'r1', control: 'ZZ-99', revisions: [5] }])).toThrow(
      /never produced|not present/i
    );
    expect(() => applySuppressions(rows, [{ rule: 'r1', control: 'AC-1', revisions: [4] }])).toThrow(
      /never produced|not present/i
    );
  });

  it('fails loudly when a suppression would empty a rule', () => {
    const rows = [row('r1', ['AC-1'], 5)];
    expect(() => applySuppressions(rows, [{ rule: 'r1', control: 'AC-1', revisions: [5] }])).toThrow(
      /every control|all controls|empty/i
    );
  });

  it('leaves pre-existing empty marker rows alone', () => {
    // Tier-4 emits explicit empty-NIST-ID marker rows; the pass must not
    // trip its emptiness check on rows it never touched.
    const rows = [row('marker', [], 4), row('r1', ['AC-1', 'AC-2'], 5)];
    rows[0]!['NIST-ID'] = '';
    expect(() => applySuppressions(rows, [{ rule: 'r1', control: 'AC-2', revisions: [5] }])).not.toThrow();
    expect(rows[0]!['NIST-ID']).toBe('');
  });
});
