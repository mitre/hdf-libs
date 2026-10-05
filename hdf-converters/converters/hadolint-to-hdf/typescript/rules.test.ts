import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseJSON } from '@mitre/hdf-utilities';
import type { HDFResults } from '@mitre/hdf-schema';
import { convertHadolintToHdf } from './converter.js';
import { ruleReferenceUrl } from './rules.js';

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'input');

function requirementById(result: HDFResults, id: string) {
  for (const baseline of result.baselines) {
    const req = baseline.requirements.find((r) => r.id === id);
    if (req) return req;
  }
  throw new Error(`no requirement with id ${id}`);
}

// Twin of go/rules_test.go.
describe('hadolint rule documentation links', () => {
  it('points each rule family at its own project', () => {
    expect(ruleReferenceUrl('DL3002')).toBe('https://github.com/hadolint/hadolint/wiki/DL3002');
    expect(ruleReferenceUrl('SC2154')).toBe('https://github.com/koalaman/shellcheck/wiki/SC2154');
  });

  // The rule code reaches a URL, so a report carrying a crafted code must not
  // be able to steer the link. Anything that is not a rule code yields no link.
  it('rejects anything that is not a rule code', () => {
    for (const code of [
      '',
      'DL1000x',
      'E501',
      '../../../../attacker/evilrepo/main/payload',
      '..%2f..%2fadmin',
      '//evil.example.com/x',
      '@evil.example.com/x',
      'http://169.254.169.254/latest/meta-data',
      'DL3002?x=1',
      'DL3002#frag',
    ]) {
      expect(ruleReferenceUrl(code), code).toBe('');
    }
  });

  it('links the rule documentation on each requirement', async () => {
    const input = readFileSync(join(FIXTURES_DIR, 'shellcheck.json'), 'utf-8');
    const result = parseJSON<HDFResults>(await convertHadolintToHdf(input));
    expect(requirementById(result, 'DL3002').refs).toEqual([{url: 'https://github.com/hadolint/hadolint/wiki/DL3002'}]);
    expect(requirementById(result, 'SC2154').refs).toEqual([{url: 'https://github.com/koalaman/shellcheck/wiki/SC2154'}]);
  });

  it('still converts a rule the link pattern does not cover', async () => {
    const input = '[{"code":"E501","column":1,"file":"Dockerfile","level":"warning","line":1,"message":"m"}]';
    const result = parseJSON<HDFResults>(await convertHadolintToHdf(input));
    expect(requirementById(result, 'E501').refs).toBeUndefined();
  });
});
