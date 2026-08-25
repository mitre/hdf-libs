import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { convertHdfToXccdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface GroupIdCase {
  gid: string;
  id: string;
  passthrough: boolean;
  why: string;
}

const CASES = (
  JSON.parse(
    readFileSync(join(__dirname, '..', '..', '..', 'shared', 'xccdf-group-id-cases.json'), 'utf-8'),
  ) as { cases: GroupIdCase[] }
).cases;

function hdfWithGid(gid: string): string {
  return JSON.stringify({
    timestamp: '2020-01-01T00:00:00Z',
    baselines: [
      {
        name: 'b',
        requirements: [
          {
            id: 'r',
            impact: 0,
            tags: { gid },
            descriptions: [{ label: 'default', data: 'd' }],
            results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
          },
        ],
      },
    ],
  });
}

// The encoding is implemented twice, so the expectations live in one shared file
// both languages read. Asserted through the converter rather than against the
// helper directly, so this also pins that the encoder is actually wired up.
describe('hdf-to-xccdf Group/@id', () => {
  it('has a populated shared table', () => {
    expect(CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(CASES.filter((c) => c.gid !== '').map((c) => [c.gid, c] as const))(
    'encodes %j like the Go peer',
    (_gid, c) => {
      expect(convertHdfToXccdf(hdfWithGid(c.gid)), c.why).toContain(`id="${c.id}"`);
    },
  );

  // XCCDF types Group/@id as an NCName that must also match this pattern
  // (xccdf_1.2.xsd:821). Asserted against the XSD's own pattern rather than
  // against the encoder's idea of it; the Go peer gates on the real XSD.
  it.each(CASES.filter((c) => c.gid !== '').map((c) => [c.gid, c] as const))(
    'emits a groupIdType for %j',
    (_gid, c) => {
      const id = /<(?:cdf:)?Group[^>]*\bid="([^"]*)"/.exec(convertHdfToXccdf(hdfWithGid(c.gid)))?.[1];
      expect(id, 'no Group element was emitted').toBeDefined();
      expect(id).toMatch(/^xccdf_[^_]+_group_.+$/);
      expect(id).toMatch(/^[A-Za-z_][A-Za-z0-9._-]*$/);
    },
  );
});

// benchmarkIdType and profileIdType require a trailing name segment via their
// .+ (xccdf_1.2.xsd:799, :843). A baseline with an empty name is valid HDF but
// produced "xccdf_hdf_benchmark_", which the XSD rejects. The Go peer gates the
// same input on the real XSD.
describe('hdf-to-xccdf empty baseline name', () => {
  it('still emits ids with a trailing name segment', () => {
    const out = convertHdfToXccdf(
      JSON.stringify({
        timestamp: '2020-01-01T00:00:00Z',
        baselines: [
          {
            name: '',
            requirements: [
              {
                id: 'r',
                impact: 0,
                tags: {},
                descriptions: [{ label: 'default', data: 'd' }],
                results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
              },
            ],
          },
        ],
      }),
    );
    expect(out).toContain('id="xccdf_hdf_benchmark_unnamed"');
    expect(out).toContain('id="xccdf_hdf_profile_unnamed"');
    expect(out).toMatch(/id="xccdf_[^_"]+_benchmark_[^"]+"/);
  });
});

// Every timestamp this converter emits is HDF's canonical form: RFC3339 in UTC
// with trailing fractional zeros trimmed. This side used to pass the source
// string through, so a result time of ".500Z" emitted ".500Z" here and ".5Z" in
// Go — a divergence no fixture happened to carry. Asserts the exact strings the
// Go peer asserts.
describe('hdf-to-xccdf timestamps', () => {
  it('emits canonical trimmed-fraction times', () => {
    const out = convertHdfToXccdf(
      JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'r',
                impact: 0,
                tags: {},
                descriptions: [{ label: 'default', data: 'd' }],
                results: [
                  { status: 'passed', codeDesc: 'c', startTime: '2020-01-02T09:00:00.500Z' },
                  { status: 'failed', codeDesc: 'c2', startTime: '2020-01-02T03:04:05.120Z' },
                  { status: 'passed', codeDesc: 'c3', startTime: '2020-01-02T07:30:00.000Z' },
                ],
              },
            ],
          },
        ],
      }),
    );

    expect(out).toContain('start-time="2020-01-02T03:04:05.12Z"');
    expect(out).toContain('end-time="2020-01-02T09:00:00.5Z"');
    expect(out).toContain('time="2020-01-02T07:30:00Z"');
    expect(out).not.toContain('.500Z');
    expect(out).not.toContain('.120Z');
    expect(out).not.toContain('.000Z');
  });
});

// The two languages guarded the InSpec <check> differently: Go emitted one
// whenever code was non-nil, so an empty string produced an empty check element,
// while this side's truthy test skipped it. Both now use the shared
// non-empty-text helper. Mirrors the Go peer case for case.
describe('hdf-to-xccdf InSpec check', () => {
  const INSPEC = 'system="http://inspec.io/"';

  it.each([
    ['absent', undefined, false],
    ['empty', '', false],
    ['whitespace only', '   ', false],
    ['real code', "describe file('/etc/passwd') do\n end", true],
  ])('emits a check for %s: %s', (_label, code, want) => {
    const out = convertHdfToXccdf(
      JSON.stringify({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'r',
                impact: 0,
                tags: {},
                ...(code === undefined ? {} : { code }),
                descriptions: [{ label: 'default', data: 'd' }],
                results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
              },
            ],
          },
        ],
      }),
    );
    expect(out.includes(INSPEC), 'a check is emitted only for code that carries text').toBe(want);
  });
});
