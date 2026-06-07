import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openvexFingerprint } from './fingerprint.js';

describe('openvex-to-hdf fingerprint', () => {
  it('matches a real OpenVEX document', () => {
    const data = JSON.parse(
      readFileSync(
        join(__dirname, '..', 'fixtures', 'input', 'spring-boot-log4j.openvex.json'),
        'utf-8',
      ),
    );
    expect(openvexFingerprint.fingerprint(data)).toBe(1.0);
  });

  it('rejects non-OpenVEX inputs', () => {
    expect(openvexFingerprint.fingerprint({ foo: 'bar' })).toBe(0);
    expect(
      openvexFingerprint.fingerprint({
        '@context': 'https://cyclonedx.org/schema',
        statements: [],
      }),
    ).toBe(0);
    expect(
      openvexFingerprint.fingerprint({ '@context': 'https://openvex.dev/ns/v0.2.0' }),
    ).toBe(0);
    expect(openvexFingerprint.fingerprint('not-an-object')).toBe(0);
    expect(openvexFingerprint.fingerprint(null)).toBe(0);
  });

  it('declares amendments output and ingest direction', () => {
    expect(openvexFingerprint.outputType).toBe('amendments');
    expect(openvexFingerprint.direction).toBe('ingest');
  });
});
