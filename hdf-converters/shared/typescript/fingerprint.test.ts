import { describe, it, expect, beforeEach } from 'vitest';
import { detectConverter, detectConverterAll, detectFamily } from './fingerprint.js';
import { registerFingerprint, _resetRegistry, type ConverterFingerprint } from './registry.js';

const SARIF_INPUT = JSON.stringify({
  version: '2.1.0',
  runs: [{ tool: { driver: { name: 'test' } }, results: [] }],
});

const JUNIT_INPUT = '<?xml version="1.0"?><testsuites><testsuite name="s1"><testcase name="t1"/></testsuite></testsuites>';
const XCCDF_INPUT = '<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test"><status>incomplete</status></Benchmark>';

const GOSEC_INPUT = JSON.stringify({
  GosecVersion: '2.18.2',
  Issues: [{ severity: 'HIGH', rule_id: 'G101' }],
  Stats: { files: 1 },
});

const sarifFP: ConverterFingerprint = {
  id: 'sarif-to-hdf',
  label: 'SARIF',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input) => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if (typeof obj.version === 'string' && Array.isArray(obj.runs)) return 0.9;
    return 0;
  },
};

const junitFP: ConverterFingerprint = {
  id: 'junit-to-hdf',
  label: 'JUnit',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input) => {
    if (typeof input !== 'string') return 0;
    return input.match(/<(?:\?[^?]*\?>\s*)?<?(testsuites?)\b/) ? 1.0 : 0;
  },
};

const xccdfFP: ConverterFingerprint = {
  id: 'xccdf-results-to-hdf',
  label: 'XCCDF',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: (input) => {
    if (typeof input !== 'string') return 0;
    return input.match(/<(?:[a-zA-Z_][\w.-]*:)?Benchmark[\s>]/) ? 1.0 : 0;
  },
};

const gosecFP: ConverterFingerprint = {
  id: 'gosec-to-hdf',
  label: 'GoSec',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input) => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    if ('GosecVersion' in obj && Array.isArray(obj.Issues)) return 1.0;
    if (Array.isArray(obj.Issues) && 'Stats' in obj) return 0.6;
    return 0;
  },
};

describe('detectFamily', () => {
  it('detects JSON object', () => expect(detectFamily('{"key": "value"}')).toBe('json'));
  it('detects JSON array', () => expect(detectFamily('[1, 2, 3]')).toBe('json'));
  it('detects XML', () => expect(detectFamily('<?xml version="1.0"?><root/>')).toBe('xml'));
  it('detects XML without declaration', () => expect(detectFamily('<root/>')).toBe('xml'));
  it('handles leading whitespace', () => expect(detectFamily('  \n  {"key": 1}')).toBe('json'));
  it('returns text for plain text', () => expect(detectFamily('hello world')).toBe('text'));
  it('returns undefined for empty input', () => expect(detectFamily('')).toBeUndefined());
  it('returns undefined for whitespace-only', () => expect(detectFamily('   ')).toBeUndefined());
});

describe('detectConverter', () => {
  beforeEach(() => _resetRegistry());

  it('returns undefined when no fingerprints registered', () => {
    expect(detectConverter(SARIF_INPUT)).toBeUndefined();
  });

  it('detects SARIF input', () => {
    registerFingerprint(sarifFP);
    registerFingerprint(gosecFP);
    const result = detectConverter(SARIF_INPUT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('sarif-to-hdf');
    expect(result!.confidence).toBe(0.9);
  });

  it('detects GoSec input (not confused with SARIF)', () => {
    registerFingerprint(sarifFP);
    registerFingerprint(gosecFP);
    const result = detectConverter(GOSEC_INPUT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('gosec-to-hdf');
    expect(result!.confidence).toBe(1.0);
  });

  it('detects JUnit XML', () => {
    registerFingerprint(junitFP);
    registerFingerprint(xccdfFP);
    const result = detectConverter(JUNIT_INPUT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('junit-to-hdf');
  });

  it('detects XCCDF XML', () => {
    registerFingerprint(junitFP);
    registerFingerprint(xccdfFP);
    const result = detectConverter(XCCDF_INPUT);
    expect(result).toBeDefined();
    expect(result!.fingerprint.id).toBe('xccdf-results-to-hdf');
  });

  it('returns undefined for garbage', () => {
    registerFingerprint(sarifFP);
    expect(detectConverter('not valid anything')).toBeUndefined();
  });

  it('returns undefined for empty', () => {
    registerFingerprint(sarifFP);
    expect(detectConverter('')).toBeUndefined();
  });

  it('returns undefined for invalid JSON', () => {
    registerFingerprint(sarifFP);
    expect(detectConverter('{broken')).toBeUndefined();
  });

  it('does not match JSON fingerprint against XML', () => {
    registerFingerprint(sarifFP);
    expect(detectConverter(JUNIT_INPUT)).toBeUndefined();
  });

  it('does not match XML fingerprint against JSON', () => {
    registerFingerprint(junitFP);
    expect(detectConverter(SARIF_INPUT)).toBeUndefined();
  });

  it('skips export fingerprints', () => {
    registerFingerprint({
      id: 'hdf-to-csv', label: 'HDF to CSV', direction: 'export',
      inputFamily: 'json', outputType: 'raw', fingerprint: () => 1.0,
    });
    expect(detectConverter(SARIF_INPUT)).toBeUndefined();
  });

  it('includes outputType in result', () => {
    registerFingerprint(sarifFP);
    const result = detectConverter(SARIF_INPUT);
    expect(result!.fingerprint.outputType).toBe('results');
  });
});

describe('detectConverterAll', () => {
  beforeEach(() => _resetRegistry());

  it('returns empty array when no match', () => {
    registerFingerprint(sarifFP);
    expect(detectConverterAll('plain text')).toHaveLength(0);
  });

  it('returns multiple matches sorted by confidence', () => {
    registerFingerprint({
      id: 'snyk-to-hdf', label: 'Snyk', direction: 'ingest',
      inputFamily: 'json', outputType: 'results',
      fingerprint: (input) => {
        const obj = input as Record<string, unknown>;
        if ('packageManager' in obj && Array.isArray(obj.vulnerabilities)) return 1.0;
        if (Array.isArray(obj.vulnerabilities)) return 0.5;
        return 0;
      },
    });
    registerFingerprint({
      id: 'gitlab-to-hdf', label: 'GitLab', direction: 'ingest',
      inputFamily: 'json', outputType: 'results',
      fingerprint: (input) => {
        const obj = input as Record<string, unknown>;
        if (obj.scan && Array.isArray(obj.vulnerabilities)) return 0.9;
        if (Array.isArray(obj.vulnerabilities)) return 0.4;
        return 0;
      },
    });

    const ambiguous = JSON.stringify({ vulnerabilities: [{ id: 'CVE-2024-1234' }] });
    const results = detectConverterAll(ambiguous);
    expect(results).toHaveLength(2);
    expect(results[0].fingerprint.id).toBe('snyk-to-hdf');
    expect(results[0].confidence).toBe(0.5);
    expect(results[1].fingerprint.id).toBe('gitlab-to-hdf');
    expect(results[1].confidence).toBe(0.4);
  });
});

describe('version detection', () => {
  beforeEach(() => _resetRegistry());

  it('populates version from detectVersion', () => {
    registerFingerprint({
      ...sarifFP,
      detectVersion: (input: unknown): string => {
        if (typeof input !== 'object' || input === null) return '';
        const obj = input as Record<string, unknown>;
        return typeof obj.version === 'string' ? obj.version : '';
      },
    });
    const result = detectConverter(SARIF_INPUT);
    expect(result).toBeDefined();
    expect(result!.version).toBe('2.1.0');
  });

  it('version is empty when detectVersion is undefined', () => {
    registerFingerprint(sarifFP); // no detectVersion
    const result = detectConverter(SARIF_INPUT);
    expect(result).toBeDefined();
    expect(result!.version).toBe('');
  });

  it('version is empty when detectVersion throws', () => {
    registerFingerprint({
      ...sarifFP,
      detectVersion: () => { throw new Error('boom'); },
    });
    const result = detectConverter(SARIF_INPUT);
    expect(result).toBeDefined();
    expect(result!.version).toBe('');
  });

  it('detectConverterAll includes version for each result', () => {
    registerFingerprint({
      ...sarifFP,
      detectVersion: (input: unknown): string => {
        if (typeof input !== 'object' || input === null) return '';
        const obj = input as Record<string, unknown>;
        return typeof obj.version === 'string' ? obj.version : '';
      },
    });
    const results = detectConverterAll(SARIF_INPUT);
    expect(results).toHaveLength(1);
    expect(results[0].version).toBe('2.1.0');
  });
});
