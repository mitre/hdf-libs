import { describe, it, expect } from 'vitest';
import {
  // CCI exports
  getCCIDescription,
  getCCINistMappings,
  getAllCCIIds,
  cciExists,
  // NIST exports
  getNISTDescription,
  getAllNISTIds,
  nistExists,
  getNISTFamily,
} from '../src/index.js';

describe('Main index exports', () => {
  it('should export CCI functions from main index', () => {
    expect(getCCIDescription).toBeDefined();
    expect(getCCINistMappings).toBeDefined();
    expect(getAllCCIIds).toBeDefined();
    expect(cciExists).toBeDefined();
  });

  it('should export NIST functions from main index', () => {
    expect(getNISTDescription).toBeDefined();
    expect(getAllNISTIds).toBeDefined();
    expect(nistExists).toBeDefined();
    expect(getNISTFamily).toBeDefined();
  });

  it('should have working CCI functions from main export', () => {
    const desc = getCCIDescription('CCI-000001');
    expect(desc).toBeDefined();
    expect(desc).toContain('access control policy');
  });

  it('should have working NIST functions from main export', () => {
    const desc = getNISTDescription('AC-01');
    expect(desc).toBeDefined();
    expect(desc).toBe('Policy and Procedures'); // Rev 5 default
  });
});
