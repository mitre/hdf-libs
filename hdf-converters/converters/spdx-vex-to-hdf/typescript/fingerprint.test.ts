import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  _resetRegistry,
  getFingerprint,
} from '../../../shared/typescript/registry.js';
import { register, spdxVexFingerprint } from './fingerprint.js';

function loadInput(name: string): unknown {
  return JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8'));
}

describe('spdxVexFingerprint', () => {
  it('has the expected metadata', () => {
    expect(spdxVexFingerprint.id).toBe('spdx-vex-to-hdf');
    expect(spdxVexFingerprint.outputType).toBe('amendments');
    expect(spdxVexFingerprint.direction).toBe('ingest');
  });

  it('matches an SPDX-3 security/VEX document', () => {
    expect(spdxVexFingerprint.fingerprint(loadInput('sample.spdx.json'))).toBe(1.0);
  });

  it('does not match SPDX-3 AI/dataset, SPDX 2.x, or non-map input', () => {
    expect(
      spdxVexFingerprint.fingerprint({ '@context': 'x', '@graph': [{ type: 'ai_AIPackage' }] }),
    ).toBe(0);
    expect(spdxVexFingerprint.fingerprint({ spdxVersion: 'SPDX-2.3' })).toBe(0);
    expect(spdxVexFingerprint.fingerprint('not-a-map')).toBe(0);
  });
});

describe('register', () => {
  afterEach(() => _resetRegistry());

  it('registers the fingerprint and is idempotent', () => {
    _resetRegistry();
    expect(getFingerprint('spdx-vex-to-hdf')).toBeUndefined();
    register();
    expect(getFingerprint('spdx-vex-to-hdf')?.id).toBe('spdx-vex-to-hdf');
    // Second call takes the already-registered branch (no throw, no duplicate).
    register();
    expect(getFingerprint('spdx-vex-to-hdf')?.id).toBe('spdx-vex-to-hdf');
  });
});
