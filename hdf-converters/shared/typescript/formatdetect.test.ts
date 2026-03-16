import { describe, it, expect } from 'vitest';
import { detectFormat } from './formatdetect.js';

describe('detectFormat', () => {
  it('detects SARIF with version and runs', () => {
    const input = '{"version": "2.1.0", "runs": [{"tool": {}, "results": []}]}';
    expect(detectFormat(input)).toBe('sarif');
  });

  it('detects SARIF with schema field', () => {
    const input = JSON.stringify({
      $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json',
      version: '2.1.0',
      runs: [],
    });
    expect(detectFormat(input)).toBe('sarif');
  });

  it('returns unknown for gosec native JSON', () => {
    const input = JSON.stringify({
      GosecVersion: '2.18.2',
      Issues: [],
      Stats: { files: 1 },
    });
    expect(detectFormat(input)).toBe('unknown');
  });

  it('returns unknown for empty input', () => {
    expect(detectFormat('')).toBe('unknown');
  });

  it('returns unknown for non-JUnit XML', () => {
    expect(detectFormat('<?xml version="1.0"?><root/>')).toBe('unknown');
  });

  it('returns unknown for invalid JSON', () => {
    expect(detectFormat('not json')).toBe('unknown');
  });

  it('returns unknown for JSON array', () => {
    expect(detectFormat('[1, 2, 3]')).toBe('unknown');
  });

  it('returns unknown when version is number', () => {
    expect(detectFormat('{"version": 2, "runs": []}')).toBe('unknown');
  });

  it('returns unknown when runs is object', () => {
    expect(detectFormat('{"version": "2.1.0", "runs": {}}')).toBe('unknown');
  });

  it('returns unknown when version missing', () => {
    expect(detectFormat('{"runs": []}')).toBe('unknown');
  });

  it('returns unknown when runs missing', () => {
    expect(detectFormat('{"version": "2.1.0"}')).toBe('unknown');
  });

  // JUnit XML detection tests
  it('detects JUnit XML with testsuites root', () => {
    expect(detectFormat('<?xml version="1.0"?><testsuites><testsuite/></testsuites>')).toBe(
      'junit'
    );
  });

  it('detects JUnit XML with testsuite root', () => {
    expect(
      detectFormat('<testsuite name="test" tests="1"><testcase name="t1"/></testsuite>')
    ).toBe('junit');
  });

  it('detects JUnit XML with whitespace before', () => {
    expect(detectFormat('  <?xml version="1.0"?><testsuites/>')).toBe('junit');
  });

  it('returns unknown for non-JUnit XML root', () => {
    expect(detectFormat('<?xml version="1.0"?><root><item/></root>')).toBe('unknown');
  });

  it('returns unknown for invalid XML', () => {
    expect(detectFormat('<unclosed')).toBe('unknown');
  });

  // XCCDF and ARF detection tests
  it('detects XCCDF Benchmark XML', () => {
    const input =
      '<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test"><status>incomplete</status></Benchmark>';
    expect(detectFormat(input)).toBe('xccdf');
  });

  it('detects ARF asset-report-collection XML', () => {
    const input =
      '<?xml version="1.0"?><asset-report-collection xmlns="http://scap.nist.gov/schema/asset-reporting-format/1.1"></asset-report-collection>';
    expect(detectFormat(input)).toBe('arf');
  });

  it('detects ARF with namespace prefix', () => {
    const input =
      '<?xml version="1.0"?><arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"></arf:asset-report-collection>';
    expect(detectFormat(input)).toBe('arf');
  });

  it('detects XCCDF with namespace prefix', () => {
    const input =
      '<?xml version="1.0"?><xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="test"></xccdf:Benchmark>';
    expect(detectFormat(input)).toBe('xccdf');
  });
});
