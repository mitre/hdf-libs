import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { isV1Format, normalizeToV2 } from '../src/normalize.js';
import { diffHdf } from '../src/diff.js';
import { inspec } from '@mitre/hdf-fixtures';
import { validateResults } from '@mitre/hdf-validators';

describe('isV1Format', () => {
  it('returns true for v1 documents with profiles array', () => {
    expect(isV1Format({ profiles: [], platform: {}, statistics: {} })).toBe(true);
  });

  it('returns false for v2 documents with baselines array', () => {
    expect(isV1Format({ baselines: [] })).toBe(false);
  });

  it('returns false for documents with both profiles and baselines', () => {
    // v2 takes precedence
    expect(isV1Format({ profiles: [], baselines: [] })).toBe(false);
  });

  it('returns false for empty documents', () => {
    expect(isV1Format({})).toBe(false);
  });
});

describe('normalizeToV2', () => {
  it('passes through v2 documents unchanged', () => {
    const v2 = { baselines: [{ name: 'test', requirements: [] }] };
    expect(normalizeToV2(v2)).toBe(v2); // Same reference
  });

  it('converts v1 profiles to v2 baselines', () => {
    const v1: Record<string, unknown> = {
      profiles: [
        {
          name: 'nginx-baseline',
          title: 'NGINX Baseline',
          version: '2.0.0',
          sha256: 'abc123',
          controls: [],
          groups: [],
          supports: [],
          inputs: [],
        },
      ],
      statistics: { duration: 1.5 },
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];

    expect(baselines).toHaveLength(1);
    expect(baselines[0]!['name']).toBe('nginx-baseline');
    expect(baselines[0]!['title']).toBe('NGINX Baseline');
    expect(baselines[0]!['version']).toBe('2.0.0');
  });

  it('converts v1 controls to v2 requirements with camelCase fields', () => {
    const v1: Record<string, unknown> = {
      profiles: [
        {
          name: 'test',
          controls: [
            {
              id: 'V-13613',
              title: 'Test Control',
              desc: 'A test description',
              impact: 0.5,
              tags: { cci: ['CCI-000366'] },
              refs: [],
              source_location: { ref: 'controls/test.rb', line: 1 },
              results: [
                {
                  status: 'passed',
                  code_desc: 'File /etc/nginx should exist',
                  run_time: 0.05,
                  start_time: '2024-01-01T00:00:00Z',
                },
              ],
            },
          ],
          groups: [],
          supports: [],
        },
      ],
      statistics: { duration: 0.05 },
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];

    expect(reqs).toHaveLength(1);
    const req = reqs[0]!;
    expect(req['id']).toBe('V-13613');
    expect(req['title']).toBe('Test Control');
    expect(req['impact']).toBe(0.5);

    // Descriptions converted from desc string
    const descriptions = req['descriptions'] as { label: string; data: string }[];
    expect(descriptions).toHaveLength(1);
    expect(descriptions[0]!.label).toBe('default');
    expect(descriptions[0]!.data).toBe('A test description');

    // Results with camelCase
    const results = req['results'] as Record<string, unknown>[];
    expect(results[0]!['codeDesc']).toBe('File /etc/nginx should exist');
    expect(results[0]!['runTime']).toBe(0.05);
    expect(results[0]!['startTime']).toBe('2024-01-01T00:00:00Z');

    // Source location
    expect(req['sourceLocation']).toEqual({ ref: 'controls/test.rb', line: 1 });
  });

  it('handles controls with no results', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as unknown[];
    expect(results).toEqual([]);
  });

  // Was `expect(descriptions).toEqual([])`, which pinned output the results
  // schema rejects: descriptions has minItems 1 and must contain a 'default'.
  // An empty array also made the differ blind to description changes, since
  // descriptions is one of the fields it tracks.
  it('synthesizes a default description when the control has no desc', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const descriptions = reqs[0]!['descriptions'] as unknown[];
    expect(descriptions).toEqual([{ label: 'default', data: '' }]);
  });

  it('preserves timestamp if present', () => {
    const v1: Record<string, unknown> = {
      profiles: [{ name: 'test', controls: [] }],
      timestamp: '2024-01-01T00:00:00Z',
    };

    const v2 = normalizeToV2(v1);
    expect(v2['timestamp']).toBe('2024-01-01T00:00:00Z');
  });

  it('handles profile with no controls property', () => {
    const v1: Record<string, unknown> = {
      profiles: [{ name: 'empty-profile' }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as unknown[];
    expect(reqs).toEqual([]);
  });

  it('handles controls with no tags or refs', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          results: [{ status: 'passed', code_desc: 'test', start_time: '2024-01-01T00:00:00Z' }],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    expect(reqs[0]!['tags']).toEqual({});
    expect(reqs[0]!['refs']).toEqual([]);
  });

  it('handles v2-style camelCase result fields in v1 document', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.5,
          tags: {},
          results: [{
            status: 'failed',
            codeDesc: 'already camelCase',
            runTime: 0.1,
            startTime: '2024-01-01T00:00:00Z',
          }],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['codeDesc']).toBe('already camelCase');
    expect(results[0]!['runTime']).toBe(0.1);
    expect(results[0]!['startTime']).toBe('2024-01-01T00:00:00Z');
  });

  it('handles result with camelCase startTime only (no snake_case start_time)', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.5,
          tags: {},
          results: [{
            status: 'passed',
            codeDesc: 'already camelCase desc',
            startTime: '2024-06-01T00:00:00Z',
            // Note: no code_desc or start_time — only camelCase versions
          }],
        }],
      }],
    };
    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['startTime']).toBe('2024-06-01T00:00:00Z');
    expect(results[0]!['codeDesc']).toBe('already camelCase desc');
  });

  it('handles result with empty start_time string', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [{
            status: 'passed',
            code_desc: 'test',
            start_time: '',
          }],
        }],
      }],
    };
    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['startTime']).toBe('');
  });

  it('handles result with no start_time or startTime at all', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [{
            status: 'passed',
            code_desc: 'test',
          }],
        }],
      }],
    };
    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['startTime']).toBe('');
  });

  it('handles result with neither code_desc nor codeDesc', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [{
            status: 'passed',
            start_time: '2024-01-01T00:00:00Z',
            // Neither code_desc nor codeDesc — should default to ''
          }],
        }],
      }],
    };
    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['codeDesc']).toBe('');
  });

  it('handles v1 control with sourceLocation (camelCase)', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.5,
          tags: {},
          sourceLocation: { ref: 'controls/test.rb', line: 5 },
          results: [],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    expect(reqs[0]!['sourceLocation']).toEqual({ ref: 'controls/test.rb', line: 5 });
  });

  it('handles profile without sha256', () => {
    const v1: Record<string, unknown> = {
      profiles: [{ name: 'no-hash', controls: [] }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    expect(baselines[0]!['checksum']).toBeUndefined();
  });

  it('maps v1 "skipped" status to v2 "notReviewed"', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [
            { status: 'skipped', code_desc: 'skipped test', start_time: '2024-01-01T00:00:00Z' },
          ],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['status']).toBe('notReviewed');
  });

  it('normalizes non-ISO timestamp format to ISO 8601', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [
            { status: 'passed', code_desc: 'test', start_time: '2017-09-22 14:12:15 -0400' },
          ],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    const startTime = results[0]!['startTime'] as string;
    // Should contain 'T' indicating ISO format
    expect(startTime).toContain('T');
    // Should be parseable as a Date
    expect(new Date(startTime).toISOString()).toBe(startTime);
  });

  it('preserves already-valid ISO 8601 timestamps', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [
            { status: 'passed', code_desc: 'test', start_time: '2024-01-01T00:00:00Z' },
          ],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['startTime']).toBe('2024-01-01T00:00:00Z');
  });

  it('passes through unparseable timestamps as-is', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [
            { status: 'passed', code_desc: 'test', start_time: 'not-a-date' },
          ],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    expect(results[0]!['startTime']).toBe('not-a-date');
  });

  it('omits optional result fields when undefined', () => {
    const v1: Record<string, unknown> = {
      profiles: [{
        name: 'test',
        controls: [{
          id: 'V-001',
          impact: 0.7,
          tags: {},
          results: [
            { status: 'passed', code_desc: 'test', start_time: '2024-01-01T00:00:00Z' },
          ],
        }],
      }],
    };

    const v2 = normalizeToV2(v1);
    const baselines = v2['baselines'] as Record<string, unknown>[];
    const reqs = baselines[0]!['requirements'] as Record<string, unknown>[];
    const results = reqs[0]!['results'] as Record<string, unknown>[];
    // runTime and message should not be present (not just undefined)
    expect('runTime' in results[0]!).toBe(false);
    expect('message' in results[0]!).toBe(false);
  });
});

// ── The normalized baseline must be the shape the results schema declares ──
// The normalizer is exported publicly and the README advertises it as format
// conversion, so its output is a contract, not just an internal convenience.
describe('normalizeToV2 emits the declared baseline shape', () => {
  const legacyProfile = {
    name: 'nginx-baseline',
    title: 'NGINX Baseline',
    version: '2.0.0',
    sha256: 'abc123',
    supports: [{'platform-family': 'linux', 'platform-name': 'ubuntu', release: '22.04', platform: 'unix'}],
    attributes: [{name: 'max_age', options: {type: 'numeric', default: 90}}],
    groups: [{id: 'controls/V-1.rb', title: 'Group One', controls: ['V-1', 'V-2']}],
    controls: [
      {id: 'V-1', title: 't1', impact: 0.5, tags: {}, desc: 'd1',
       results: [{status: 'passed', code_desc: 'c', start_time: '2026-01-02T03:04:05Z'}]},
      {id: 'V-2', title: 't2', impact: 0.5, tags: {}, desc: 'd2',
       results: [{status: 'passed', code_desc: 'c', start_time: '2026-01-02T03:04:05Z'}]},
    ],
  };
  const doc = () => ({profiles: [structuredClone(legacyProfile)], statistics: {duration: 1.5}});

  function baseline(): Record<string, any> {
    return (normalizeToV2(doc()) as any).baselines[0];
  }

  it('carries group membership under requirements, not controls', () => {
    const groups = baseline().groups;
    expect(groups).toEqual([{id: 'controls/V-1.rb', title: 'Group One', requirements: ['V-1', 'V-2']}]);
  });

  it('uses the declared integrity shape rather than a checksum object', () => {
    const b = baseline();
    expect(b.integrity).toEqual({algorithm: 'sha256', checksum: 'abc123'});
    expect(b).not.toHaveProperty('checksum');
  });

  it('converts supports to the declared camelCase property names', () => {
    expect(baseline().supports).toEqual([
      {platform: 'unix', platformFamily: 'linux', platformName: 'ubuntu', release: '22.04'},
    ]);
  });

  it('does not land raw legacy attributes in inputs', () => {
    const b = baseline();
    expect(b).not.toHaveProperty('inputs');
    expect(b.extensions?.passthrough?.legacyAttributes).toEqual(legacyProfile.attributes);
  });

  it('projects statistics to the declared shape', () => {
    const out = normalizeToV2({profiles: [structuredClone(legacyProfile)], statistics: {duration: 1.5, controls: {passed: {total: 2}}}}) as any;
    expect(out.statistics).toEqual({duration: 1.5});
  });

  it('projects sourceLocation rather than passing the legacy object through', () => {
    const withNulls = structuredClone(legacyProfile) as any;
    withNulls.controls[0].source_location = {ref: null, line: null};
    const out = normalizeToV2({profiles: [withNulls], statistics: {}}) as any;
    expect(out.baselines[0].requirements[0].sourceLocation).toEqual({});
  });
});

// ── Descriptions drive the differ, so dropping them hides real changes ─────
describe('normalizeToV2 carries legacy descriptions', () => {
  function reqFrom(control: Record<string, unknown>): Record<string, any> {
    const out = normalizeToV2({
      profiles: [{name: 'p', controls: [{impact: 0.5, tags: {}, ...control}]}],
      statistics: {},
    }) as any;
    return out.baselines[0].requirements[0];
  }

  it('always emits a default-labelled description, even with no desc', () => {
    expect(reqFrom({id: 'V-1'}).descriptions).toEqual([{label: 'default', data: ''}]);
  });

  it('emits a default-labelled description with empty data when desc is null', () => {
    expect(reqFrom({id: 'V-1', desc: null}).descriptions).toEqual([{label: 'default', data: ''}]);
  });

  it('carries legacy descriptions entries alongside the default', () => {
    const descriptions = reqFrom({
      id: 'V-1',
      desc: 'the requirement',
      descriptions: [{label: 'check', data: 'run this'}, {label: 'fix', data: 'do that'}],
    }).descriptions;
    expect(descriptions).toEqual([
      {label: 'default', data: 'the requirement'},
      {label: 'check', data: 'run this'},
      {label: 'fix', data: 'do that'},
    ]);
  });

  it('carries legacy descriptions when desc itself is absent', () => {
    expect(reqFrom({id: 'V-1', descriptions: [{label: 'check', data: 'run this'}]}).descriptions).toEqual([
      {label: 'default', data: ''},
      {label: 'check', data: 'run this'},
    ]);
  });
});

// ── Cross-language parity, pinned by one shared vector ────────────────────
// These diverged badly — TypeScript emitted groups[].controls while Go emitted
// requirements: null and lost membership entirely. Single-language tests could
// not catch that, so the expectations live in one file Go reads too.
const VECTORS = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'legacy-normalize-vectors.json'), 'utf-8'),
) as {
  legacy: Record<string, unknown>;
  expected: Record<string, any>;
  refCases: {cases: {name: string; refs: unknown[]; want: Record<string, unknown>[]}[]};
  malformed: {legacy: Record<string, unknown>; expected: Record<string, any>};
};

describe('normalizeToV2 matches the shared cross-language vector', () => {
  it('has a populated vector', () => {
    expect(Object.keys(VECTORS.expected).length).toBeGreaterThan(0);
    expect(VECTORS.expected.groups.length).toBeGreaterThan(0);
  });

  const out = normalizeToV2(structuredClone(VECTORS.legacy)) as any;
  const baseline = out.baselines[0];

  it('projects statistics as the vector declares', () => {
    expect(out.statistics).toEqual(VECTORS.expected.statistics);
  });

  it('emits the groups the vector declares, membership included', () => {
    expect(baseline.groups).toEqual(VECTORS.expected.groups);
  });

  it('emits the supports the vector declares', () => {
    expect(baseline.supports).toEqual(VECTORS.expected.supports);
  });

  it('emits the integrity the vector declares', () => {
    expect(baseline.integrity).toEqual(VECTORS.expected.integrity);
  });

  it('parks the legacy attributes where the vector declares', () => {
    expect(baseline.extensions.passthrough.legacyAttributes).toEqual(VECTORS.expected.legacyAttributes);
  });

  it('emits the descriptions the vector declares, per requirement', () => {
    for (const req of baseline.requirements) {
      expect(req.descriptions, req.id).toEqual(VECTORS.expected.descriptionsById[req.id]);
    }
  });

  it('emits the refs the vector declares, dropping those carrying nothing', () => {
    for (const req of baseline.requirements) {
      expect(req.refs, req.id).toEqual(VECTORS.expected.refsById[req.id]);
    }
  });

  it('emits the sourceLocation the vector declares', () => {
    for (const req of baseline.requirements) {
      expect(req.sourceLocation, req.id).toEqual(VECTORS.expected.sourceLocationById[req.id]);
    }
  });
});

// ── Reference normalization, pinned by the same shared vector ─────────────
// The declared Reference requires one of ref/url/uri, so an entry carrying
// nothing must be dropped. These cases lived only in the Go suite, which is how
// the empty-ref defect came to be fixed in one language and not the other.
describe('normalizeRefs matches the shared reference cases', () => {
  function refsOf(refs: unknown[]): {refs: unknown; valid: boolean; errors: string} {
    const out = normalizeToV2({
      statistics: {},
      profiles: [{name: 'p', controls: [{
        id: 'V-1', impact: 0.5, tags: {}, refs,
        results: [{status: 'passed', code_desc: 'c', start_time: '2026-01-02T03:04:05Z'}],
      }]}],
    }) as any;
    const v = validateResults(JSON.parse(JSON.stringify(out)));
    return {refs: out.baselines[0].requirements[0].refs, valid: v.valid, errors: v.valid ? '' : v.getErrorMessage()};
  }

  it('has a populated table', () => {
    expect(VECTORS.refCases.cases.length).toBeGreaterThan(0);
  });

  for (const tc of VECTORS.refCases.cases) {
    it(tc.name, () => {
      const got = refsOf(tc.refs);
      expect(got.refs).toEqual(tc.want);
      expect(got.valid, got.errors).toBe(true);
    });
  }
});

// ── Malformed input, pinned by the same shared vector ─────────────────────
// normalizeToV2 takes arbitrary JSON and nothing schema-validates the input
// first, so every guard is reachable. A guard that silently keeps garbage in one
// language is the same class of divergence as the group and supports defects.
describe('normalizeToV2 drops what the shared malformed vector declares', () => {
  const {legacy, expected} = VECTORS.malformed;
  const out = normalizeToV2(structuredClone(legacy)) as any;
  const baseline = out.baselines[0];

  it('has a populated vector', () => {
    expect(expected.groups.length).toBeGreaterThan(0);
  });

  it('drops a statistics value it cannot type', () => {
    expect(out.statistics).toEqual(expected.statistics);
  });

  it('keeps only the groups and the members the vector declares', () => {
    expect(baseline.groups).toEqual(expected.groups);
  });

  it('keeps only the supports the vector declares', () => {
    expect(baseline.supports).toEqual(expected.supports);
  });

  it('keeps only the descriptions the vector declares', () => {
    for (const r of baseline.requirements) {
      expect(r.descriptions, r.id).toEqual(expected.descriptionsById[r.id]);
    }
  });

  // A null in the vector means the key is omitted entirely. Go emitted an empty
  // object where this omits, and a scalar under source_location used to shadow a
  // usable sourceLocation sibling that Go read.
  it('projects the sourceLocation the vector declares, omitting it where null', () => {
    for (const r of baseline.requirements) {
      expect(r.sourceLocation ?? null, r.id).toEqual(expected.sourceLocationById[r.id]);
    }
  });
});

// ── The functional half: a dropped descriptions[] hid real changes ─────────
// `descriptions` is one of the fields the differ compares, so never reading the
// legacy descriptions[] array did not merely omit data from the output — it made
// a check or fix text change between two legacy scans invisible, because both
// sides normalized to the same single default entry.
describe('the differ sees a legacy descriptions change', () => {
  function legacyScan(check: string): Record<string, unknown> {
    return {
      profiles: [{
        name: 'p', sha256: 'abc', supports: [], attributes: [], groups: [],
        controls: [{
          id: 'V-1', title: 't', impact: 0.5, tags: {}, desc: 'the requirement',
          descriptions: [{label: 'check', data: check}],
          results: [{status: 'passed', code_desc: 'c', start_time: '2026-01-02T03:04:05Z'}],
        }],
      }],
      statistics: {duration: 0.1},
    };
  }

  it('reports metadataChanged when only the check text differs', () => {
    const cmp = diffHdf(legacyScan('run the old check'), legacyScan('run the NEW check'), {
      trackedFields: ['descriptions'],
    }) as any;
    expect(cmp.requirementDiffs[0].changeReasons).toContain('metadataChanged');
  });

  it('reports no metadata change when the check text is identical', () => {
    const cmp = diffHdf(legacyScan('run the check'), legacyScan('run the check'), {
      trackedFields: ['descriptions'],
    }) as any;
    expect(cmp.requirementDiffs[0].changeReasons ?? []).not.toContain('metadataChanged');
  });
});

// ── Conformance: the normalizer's output must be valid HDF ─────────────────
// Overlay documents still carry resultless requirements because this normalizer
// does not flatten overlays — a carded decision, since every fix changes what
// the differ reports. So this pins the achieved state and fails if an overlay
// gains any error class beyond the carded ones.
describe('normalizeToV2 output conforms to the results schema', () => {
  const RESULTLESS = 'results: must NOT have fewer than 1 items';

  for (const [name, fixture] of Object.entries(inspec)) {
    const doc = JSON.parse(readFileSync(fixture.path, 'utf-8')) as Record<string, unknown>;
    const isOverlay = (doc.profiles as unknown[]).length > 1;

    it(`${name}${isOverlay ? ' (overlay)' : ''} normalizes to ${isOverlay ? 'only resultless errors' : 'valid HDF'}`, () => {
      const out = normalizeToV2(doc);
      const v = validateResults(JSON.parse(JSON.stringify(out)));

      if (!isOverlay) {
        expect(v.valid, v.valid ? '' : v.getErrorMessage().split('; ').slice(0, 5).join('; ')).toBe(true);
        return;
      }

      expect(v.valid).toBe(false);
      const unexpected = v
        .getErrorMessage()
        .split('; ')
        .filter((e) => !e.includes(RESULTLESS) && !e.includes('requirements: must NOT have fewer than 1 items'));
      expect(unexpected, 'an overlay document gained an error class beyond the carded resultless one').toEqual([]);
    });
  }
});

// A legacy `default` entry inside descriptions[] is the source's own prose, and
// every real fixture carries one. Overwriting it from `desc` lost that prose
// whenever the two differed, which no fixture happens to exercise.
describe('a legacy default description wins over desc', () => {
  function descriptionsOf(control: Record<string, unknown>): unknown {
    const out = normalizeToV2({
      profiles: [{name: 'p', controls: [{id: 'V-1', impact: 0.5, tags: {}, ...control}]}],
      statistics: {},
    }) as any;
    return out.baselines[0].requirements[0].descriptions;
  }

  it('keeps the legacy default prose when desc is null', () => {
    expect(descriptionsOf({
      desc: null,
      descriptions: [{label: 'default', data: 'the real prose'}, {label: 'check', data: 'chk'}],
    })).toEqual([{label: 'default', data: 'the real prose'}, {label: 'check', data: 'chk'}]);
  });

  it('keeps the legacy default prose even when desc disagrees', () => {
    expect(descriptionsOf({
      desc: 'the stale desc',
      descriptions: [{label: 'default', data: 'the real prose'}],
    })).toEqual([{label: 'default', data: 'the real prose'}]);
  });

  it('preserves the source order of legacy entries', () => {
    expect(descriptionsOf({
      descriptions: [{label: 'check', data: 'chk'}, {label: 'default', data: 'd'}, {label: 'fix', data: 'f'}],
    })).toEqual([{label: 'check', data: 'chk'}, {label: 'default', data: 'd'}, {label: 'fix', data: 'f'}]);
  });

  it('synthesizes a default only when the legacy array has none', () => {
    expect(descriptionsOf({desc: 'from desc', descriptions: [{label: 'check', data: 'chk'}]}))
      .toEqual([{label: 'default', data: 'from desc'}, {label: 'check', data: 'chk'}]);
  });
});
