import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { isValidXml } from '@mitre/hdf-utilities';
import { xmlElementName } from './converter.js';
import { convertHdfToXml } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface ElementNameCase {
  key: string;
  name: string;
  rewritten: boolean;
  why: string;
}

const CASES = (
  JSON.parse(
    readFileSync(join(__dirname, '..', '..', '..', 'shared', 'xml-element-name-cases.json'), 'utf-8'),
  ) as { cases: ElementNameCase[] }
).cases;

// The encoder is implemented twice, so the expectations live in one shared file
// both languages read rather than in two hand-kept copies.
describe('xmlElementName', () => {
  it('has a populated shared table', () => {
    expect(CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(CASES.map((c) => [c.key, c] as const))('encodes %j like the Go peer', (_key, c) => {
    expect(xmlElementName(c.key), c.why).toEqual([c.name, c.rewritten]);
  });
});

// Real converter output already carries keys that are not XML Names —
// sonarqube-to-hdf emits "sonarqube/hash", ionchannel-to-hdf emits
// "ionchannel/trigger" — so this asserts the document parses at all, which is a
// stronger property than schema validity.
describe('hdf-to-xml tag keys', () => {
  it.each(['sonarqube/hash', 'sonarqube/quick_fix_available', 'ionchannel/trigger_author'])(
    'emits parseable XML for the real key %s',
    (key) => {
      const input = JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'r',
                impact: 0,
                tags: { [key]: 'v' },
                descriptions: [{ label: 'default', data: 'd' }],
                results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
              },
            ],
          },
        ],
      });

      const out = convertHdfToXml(input);
      expect(isValidXml(out), `a tag key must not produce XML that fails to parse:\n${out}`).toBe(
        true,
      );
      // The exact element the Go peer must also emit, byte for byte.
      const [name] = xmlElementName(key);
      expect(out).toContain(`<${name} name="${key}">v</${name}>`);
    },
  );
});
