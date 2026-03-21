import { describe, it, expect, beforeEach } from 'vitest';
import { _resetRegistry, getFingerprint } from '../../../shared/typescript/registry.js';
import { register, prismaFingerprint } from './fingerprint.js';

const PRISMA_CSV_HEADER = 'Hostname,Distro,CVE ID,Compliance ID,Type,Severity,Packages,Description,Cause,Fix Status,Published,Vulnerability Link';
const PRISMA_CSV_FULL = `${PRISMA_CSV_HEADER}
host1,Ubuntu 22.04,CVE-2024-1234,CID-001,image,high,openssl,Vulnerable package found,outdated,Fix available,2024-01-01,https://example.com`;

const PARTIAL_MATCH_CSV = 'Hostname,Severity,Type,Other,Column\nhost1,high,image,foo,bar';
const UNRELATED_CSV = 'Name,Email,Phone\nJohn,john@test.com,555-1234';
const EMPTY_INPUT = '';
const JSON_INPUT = '{"version": "2.1.0", "runs": []}';
const XML_INPUT = '<?xml version="1.0"?><root/>';

describe('prisma-to-hdf fingerprint', () => {
  beforeEach(() => {
    _resetRegistry();
    register();
  });

  it('is registered with correct metadata', () => {
    const fp = getFingerprint('prisma-to-hdf');
    expect(fp).toBeDefined();
    expect(fp!.label).toBe('Prisma Cloud CSV');
    expect(fp!.direction).toBe('ingest');
    expect(fp!.inputFamily).toBe('text');
    expect(fp!.outputType).toBe('results');
  });

  it('exports fingerprint as data (no convert function)', () => {
    expect(prismaFingerprint.id).toBe('prisma-to-hdf');
    expect(prismaFingerprint).not.toHaveProperty('convert');
  });

  it('detects Prisma CSV header at confidence 0.85', () => {
    const confidence = prismaFingerprint.fingerprint(PRISMA_CSV_HEADER);
    expect(confidence).toBe(0.85);
  });

  it('detects full Prisma CSV at confidence 0.85', () => {
    const confidence = prismaFingerprint.fingerprint(PRISMA_CSV_FULL);
    expect(confidence).toBe(0.85);
  });

  it('returns partial confidence 0.4 for CSV with 3 of 5 columns', () => {
    const confidence = prismaFingerprint.fingerprint(PARTIAL_MATCH_CSV);
    expect(confidence).toBe(0.4);
  });

  it('returns 0 for unrelated CSV', () => {
    const confidence = prismaFingerprint.fingerprint(UNRELATED_CSV);
    expect(confidence).toBe(0);
  });

  it('returns 0 for empty input', () => {
    const confidence = prismaFingerprint.fingerprint(EMPTY_INPUT);
    expect(confidence).toBe(0);
  });

  it('returns 0 for non-string input', () => {
    expect(prismaFingerprint.fingerprint({ baselines: [] })).toBe(0);
    expect(prismaFingerprint.fingerprint(42)).toBe(0);
    expect(prismaFingerprint.fingerprint(null)).toBe(0);
  });

  it('returns 0 for JSON input string', () => {
    // JSON starts with '{' so detectFamily returns 'json', but
    // the fingerprint itself should still return 0 since it gets the raw string
    // and there are no Prisma columns in it
    const confidence = prismaFingerprint.fingerprint(JSON_INPUT);
    expect(confidence).toBe(0);
  });

  it('returns 0 for XML input string', () => {
    const confidence = prismaFingerprint.fingerprint(XML_INPUT);
    expect(confidence).toBe(0);
  });

  it('register is idempotent', () => {
    register(); // second call
    expect(getFingerprint('prisma-to-hdf')).toBeDefined();
  });
});
