import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'input');

// Twin of go/fingerprint_test.go.
describe('hadolint fingerprint', () => {
  registerAllFingerprints();

  it('detects the recorded reports', () => {
    for (const name of ['real.json', 'shellcheck.json']) {
      const detected = detectConverter(readFileSync(join(FIXTURES_DIR, name), 'utf-8'));
      expect(detected?.fingerprint.id, name).toBe('hadolint-to-hdf');
      expect(detected?.confidence, name).toBe(1.0);
    }
  });

  it('scores a foreign rule code lower than a hadolint one', () => {
    const input = '[{"code":"E501","column":1,"file":"a.py","level":"warning","line":3,"message":"line too long"}]';
    const detected = detectConverter(input);
    if (detected?.fingerprint.id === 'hadolint-to-hdf') {
      expect(detected.confidence).toBeLessThan(1.0);
    }
  });

  it('does not claim other documents', () => {
    for (const input of [
      '{"code":"DL3002"}',
      '[]',
      '{"Issues":[],"GosecVersion":"2.0"}',
      '[{"code":"DL3002","column":1,"file":"D","level":"critical","line":1,"message":"m"}]',
      '[{"code":"DL3002","column":1,"file":"D","level":"warning","line":"1","message":"m"}]',
      '[{"code":"DL3002","column":1,"file":"D","level":"warning","line":1}]',
    ]) {
      const detected = detectConverter(input);
      if (detected) expect(detected.fingerprint.id, input).not.toBe('hadolint-to-hdf');
    }
  });
});
