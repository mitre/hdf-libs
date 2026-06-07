import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { csafVexFingerprint } from './fingerprint.js';

describe('csaf-vex-to-hdf fingerprint', () => {
  it('matches a real CSAF VEX document', () => {
    const data = JSON.parse(
      readFileSync(
        join(__dirname, '..', 'fixtures', 'input', 'sec-vex-2022-0001.json'),
        'utf-8',
      ),
    );
    expect(csafVexFingerprint.fingerprint(data)).toBe(1.0);
  });

  it('rejects non-CSAF and non-VEX documents', () => {
    expect(csafVexFingerprint.fingerprint({ foo: 'bar' })).toBe(0);
    expect(
      csafVexFingerprint.fingerprint({
        document: { category: 'csaf_security_advisory', csaf_version: '2.0' },
      }),
    ).toBe(0);
    expect(csafVexFingerprint.fingerprint({ document: { category: 'csaf_vex' } })).toBe(0);
    expect(csafVexFingerprint.fingerprint('not-an-object')).toBe(0);
    expect(csafVexFingerprint.fingerprint(null)).toBe(0);
  });

  it('declares amendments output and ingest direction', () => {
    expect(csafVexFingerprint.outputType).toBe('amendments');
    expect(csafVexFingerprint.direction).toBe('ingest');
  });
});
