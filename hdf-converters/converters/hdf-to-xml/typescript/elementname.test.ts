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

interface ElementNameCollision {
  name: string;
  keys: string[];
  between?: string;
  why: string;
}

const TABLE = JSON.parse(
  readFileSync(join(__dirname, '..', '..', '..', 'shared', 'xml-element-name-cases.json'), 'utf-8'),
) as { cases: ElementNameCase[]; collisions: ElementNameCollision[] };

const CASES = TABLE.cases;
const COLLISIONS = TABLE.collisions;

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

/** The (element name, name attribute) of every start tag inside the first <tags>, in document order. */
function tagSequence(xml: string): [string, string][] {
  const block = /<tags>([\s\S]*?)<\/tags>/.exec(xml)?.[1] ?? '';
  return [...block.matchAll(/<([\w.\-]+)(?:\s+name="([^"]*)")?\s*>/g)].map((m) => [
    m[1] as string,
    m[2] ?? '',
  ]);
}

// Two keys encoding to one element name must yield two elements, each at its own
// source position. Building into a plain object could do neither: the second key
// overwrote the first, and a merged sibling could only render at the first key's
// position.
describe('hdf-to-xml colliding tag keys', () => {
  it('has a populated collision table', () => {
    expect(COLLISIONS.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(COLLISIONS.map((c) => [`${c.name}/${c.between ?? 'adjacent'}`, c] as const))(
    'emits every key colliding on %s in source order',
    (_label, c) => {
      expect(c.keys.length, 'a collision needs at least two keys').toBeGreaterThan(1);

      for (const k of c.keys) {
        expect(
          xmlElementName(k)[0],
          `the table says ${k} collides onto ${c.name}; if it no longer does, this row tests nothing`,
        ).toBe(c.name);
      }

      const keys = c.between ? [c.keys[0] as string, c.between, ...c.keys.slice(1)] : c.keys;
      const tags = Object.fromEntries(keys.map((k, i) => [k, `v${i}`]));
      expect(Object.keys(tags), 'a duplicate key would not survive the object').toHaveLength(
        keys.length,
      );

      const xml = convertHdfToXml(
        JSON.stringify({
          baselines: [
            {
              name: 'b',
              requirements: [
                {
                  id: 'r',
                  impact: 0,
                  tags,
                  descriptions: [{ label: 'default', data: 'd' }],
                  results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
                },
              ],
            },
          ],
        }),
      );
      expect(isValidXml(xml), c.why).toBe(true);

      expect(tagSequence(xml), c.why).toEqual(
        keys.map((k): [string, string] => {
          const [name, rewritten] = xmlElementName(k);
          return [name, rewritten ? k : ''];
        }),
      );
    },
  );
});
