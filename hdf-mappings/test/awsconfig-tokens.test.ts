import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
// Exported by the generator so token handling is testable without fetching
// the AWS sources.
import { expandCollapsed } from '../scripts/generate-awsconfig-mappings.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA = join(__dirname, '..', 'src', 'data');

interface MappingRow {
  AwsConfigRuleName: string;
  'NIST-ID': string;
  Rev: number;
  Source: string;
}

const mappings = JSON.parse(readFileSync(join(DATA, 'awsconfig-mappings.json'), 'utf-8')) as MappingRow[];
const crosswalk = JSON.parse(readFileSync(join(DATA, 'nist-revision-crosswalk.json'), 'utf-8')) as {
  rosters: Record<string, string[]>;
};

const controlsFor = (rule: string, rev: number): string[] =>
  mappings.find((r) => r.AwsConfigRuleName === rule && r.Rev === rev)?.['NIST-ID'].split('|').filter(Boolean) ?? [];

describe('expandCollapsed (stem-tracking)', () => {
  it("keeps an enhancement's own statement part intact", () => {
    expect(expandCollapsed('AC-2(12)(a)')).toEqual(['AC-2(12)(a)']);
  });

  // Every distinct multi-group token AWS publishes today (both revision
  // pages), with its expansion under the normative stem rule: a numeric group
  // emits BASE(n) and resets the stem; a letter group emits STEM(x); a numeric
  // stem that gained letter children is subsumed by them.
  const conformance: Array<[string, string[]]> = [
    ['AC-2(12)(a)', ['AC-2(12)(a)']],
    ['AU-12(a)(c)', ['AU-12(a)', 'AU-12(c)']],
    ['AU-2(a)(d)', ['AU-2(a)', 'AU-2(d)']],
    ['AU-6(1)(3)', ['AU-6(1)', 'AU-6(3)']],
    ['CA-7(a)(b)', ['CA-7(a)', 'CA-7(b)']],
    ['CM-8(3)(a)', ['CM-8(3)(a)']],
    ['IA-2(1)(11)', ['IA-2(1)', 'IA-2(11)']],
    ['IA-2(1)(2)(11)', ['IA-2(1)', 'IA-2(2)', 'IA-2(11)']],
    ['IA-5(1)(a)(d)(e)', ['IA-5(1)(a)', 'IA-5(1)(d)', 'IA-5(1)(e)']],
    ['SI-4(a)(b)(c)', ['SI-4(a)', 'SI-4(b)', 'SI-4(c)']],
  ];
  it.each(conformance)('%s expands per the stem rule', (token, expected) => {
    expect(expandCollapsed(token)).toEqual(expected);
  });

  it('passes single-group and bare tokens through untouched', () => {
    expect(expandCollapsed('AC-2(1)')).toEqual(['AC-2(1)']);
    expect(expandCollapsed('AC-2(j)')).toEqual(['AC-2(j)']);
    expect(expandCollapsed('SA-13')).toEqual(['SA-13']);
  });

  it('throws on a numeric group after a letter group (genuinely ambiguous)', () => {
    // NIST defines numbered sub-parts under statement parts, so this shape
    // cannot be parsed by rule; AWS publishes none today and a future one
    // must fail loudly rather than guess.
    expect(() => expandCollapsed('AC-2(a)(1)')).toThrow(/ambiguous/i);
    expect(() => expandCollapsed('IA-5(1)(a)(2)')).toThrow(/ambiguous/i);
  });
});

describe('generated table validity', () => {
  it('the six mis-expanded config-pack rows carry the corrected values', () => {
    expect(controlsFor('iam-password-policy', 4)).toEqual(
      expect.arrayContaining(['IA-5(1)(a)', 'IA-5(1)(d)', 'IA-5(1)(e)'])
    );
    expect(controlsFor('iam-password-policy', 4)).not.toContain('IA-5(a)');
    expect(controlsFor('iam-password-policy', 4)).not.toContain('IA-5(1)');
    for (const rule of ['guardduty-enabled-centralized', 'securityhub-enabled']) {
      expect(controlsFor(rule, 4), rule).toContain('AC-2(12)(a)');
      expect(controlsFor(rule, 4), rule).not.toContain('AC-2(a)');
      expect(controlsFor(rule, 4), rule).not.toContain('AC-2(12)');
    }
    for (const rule of [
      'ec2-instance-managed-by-systems-manager',
      'ec2-managedinstance-association-compliance-status-check',
      'ec2-managedinstance-patch-compliance-status-check',
    ]) {
      expect(controlsFor(rule, 4), rule).toContain('CM-8(3)(a)');
      expect(controlsFor(rule, 4), rule).not.toContain('CM-8(a)');
      expect(controlsFor(rule, 4), rule).not.toContain('CM-8(3)');
    }
  });

  it('AC-5(c) appears on no Rev 5 row (Rev 5 ac-5 has parts a and b only)', () => {
    for (const r of mappings) {
      if (r.Rev === 5) expect(r['NIST-ID'].split('|'), r.AwsConfigRuleName).not.toContain('AC-5(c)');
    }
  });

  it('SA-13 (withdrawn at Rev 5) appears on no Rev 5 row', () => {
    for (const r of mappings) {
      if (r.Rev === 5) expect(r['NIST-ID'].split('|'), r.AwsConfigRuleName).not.toContain('SA-13');
    }
  });

  it('using-service-linked-roles is absent (not an AWS Config managed rule)', () => {
    expect(mappings.filter((r) => r.AwsConfigRuleName === 'using-service-linked-roles')).toHaveLength(0);
  });

  it('every emitted identifier resolves in the NIST roster for its revision', () => {
    // Rosters hold controls and enhancements (statement letters are not
    // roster-listed, so a lettered token resolves via its letterless stem).
    const rosters: Record<number, Set<string>> = {
      4: new Set(crosswalk.rosters['4']),
      5: new Set(crosswalk.rosters['5']),
    };
    const letterless = (tok: string): string => tok.replace(/\(([a-z])\)$/, '');
    for (const r of mappings) {
      for (const tok of r['NIST-ID'].split('|').filter(Boolean)) {
        expect(
          rosters[r.Rev]!.has(letterless(tok)),
          `${r.AwsConfigRuleName} Rev ${r.Rev}: ${tok} (${letterless(tok)}) not in roster`
        ).toBe(true);
      }
    }
  });
});
