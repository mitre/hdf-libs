import { describe, it, expect } from 'vitest';
import { isV1Format, normalizeToV2 } from '../src/normalize.js';

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

  it('handles controls with no desc', () => {
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
    expect(descriptions).toEqual([]);
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
