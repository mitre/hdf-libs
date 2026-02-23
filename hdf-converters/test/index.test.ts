import { describe, it, expect } from 'vitest';
import { convertV1ToV2, isHDFV1, convertJunitToHdf, convertXccdfResultsToHdf, convertSnykToHdf } from '../src/index.js';

describe('Main exports', () => {
  it('should export convertV1ToV2 from main index', () => {
    expect(convertV1ToV2).toBeDefined();
    expect(typeof convertV1ToV2).toBe('function');
  });

  it('should export isHDFV1 from main index', () => {
    expect(isHDFV1).toBeDefined();
    expect(typeof isHDFV1).toBe('function');
  });

  it('should have working converter from main export', () => {
    const v1 = {
      version: '1.0.0',
      platform: { name: 'test' },
      profiles: [],
      statistics: {},
    };

    const v2 = convertV1ToV2(v1);
    expect(v2.baselines).toEqual([]);
    expect(v2.targets).toBeDefined();
  });

  it('should export convertJunitToHdf from main index', () => {
    expect(convertJunitToHdf).toBeDefined();
    expect(typeof convertJunitToHdf).toBe('function');
  });

  it('should export convertXccdfResultsToHdf from main index', () => {
    expect(convertXccdfResultsToHdf).toBeDefined();
    expect(typeof convertXccdfResultsToHdf).toBe('function');
  });

  it('should export convertSnykToHdf from main index', () => {
    expect(convertSnykToHdf).toBeDefined();
    expect(typeof convertSnykToHdf).toBe('function');
  });

  it('should have working validator from main export', () => {
    const v1Data = {
      version: '1.0.0',
      platform: { name: 'test' },
      profiles: [],
      statistics: {},
    };

    expect(isHDFV1(v1Data)).toBe(true);

    const v2Data = {
      baselines: [],
      statistics: {},
    };

    expect(isHDFV1(v2Data)).toBe(false);
  });
});
