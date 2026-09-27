import { readFileSync } from 'fs';
import { join } from 'path';
import { describe, expect, it } from 'vitest';
import { validateLegacyV2 } from './index.js';

const GO_LEGACY = join(__dirname, '..', 'go', 'legacy');

describe('validateLegacyV2 (HDF v2 / InSpec exec-json)', () => {
  it('validates a real InSpec exec-json document as valid', () => {
    const doc = JSON.parse(
      readFileSync(join(GO_LEGACY, 'testdata', 'inspec-exec-json-valid.json'), 'utf-8'),
    );
    const res = validateLegacyV2(doc);
    expect(res.valid, res.getErrorMessage()).toBe(true);
  });

  it('rejects a malformed v2 document with field-level errors', () => {
    const res = validateLegacyV2({ profiles: 'not-an-array' });
    expect(res.valid).toBe(false);
    expect(res.errors.length).toBeGreaterThan(0);
  });

  // The four documented deviations from Heimdall's stale schema (PROVENANCE.md):
  // omitted impact, empty {} ref, string source_location, object resource_id.
  it('accepts real-world Heimdall/InSpec deviations', () => {
    const doc = {
      platform: { name: 't', release: '1' },
      version: '5.22.0',
      statistics: { duration: 0.1 },
      profiles: [{
        name: 'p', version: '1.0.0', supports: [], groups: [], attributes: [], sha256: '',
        controls: [{
          id: 'c1', tags: {}, refs: [{}], source_location: '/etc/passwd',
          results: [{ status: 'passed', code_desc: 'ok', start_time: '2020-01-01T00:00:00Z',
                      resource_id: { minimum_password_length: 12 } }],
        }],
      }],
    };
    const res = validateLegacyV2(doc);
    expect(res.valid, res.getErrorMessage()).toBe(true);
  });

  it('accepts a v2 doc carrying top-level target/passthrough', () => {
    const doc = {
      platform: { name: 't', release: '1' },
      version: '5.22.0',
      statistics: { duration: 0.1 },
      target: { id: 'prod', type: 'cloudAccount' },
      passthrough: { audit: { runId: 'r1' } },
      profiles: [{ name: 'p', version: '1.0.0', supports: [], controls: [], groups: [], attributes: [], sha256: '' }],
    };
    const res = validateLegacyV2(doc);
    expect(res.valid, res.getErrorMessage()).toBe(true);
  });

  // Go embeds ../go/legacy/exec-json.schema.json; TS bundles its own copy. They
  // must be byte-identical so the two engines validate against the same schema.
  it('pins the TS schema copy byte-identical to the Go-embedded copy', () => {
    const tsCopy = readFileSync(join(__dirname, 'legacy-exec-json.schema.json'), 'utf-8');
    const goCopy = readFileSync(join(GO_LEGACY, 'exec-json.schema.json'), 'utf-8');
    expect(tsCopy).toBe(goCopy);
  });
});
