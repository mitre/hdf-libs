import { describe, it, expect } from 'vitest';
import {
  convertV1ToV2,
  isHDFV1,
  convertJunitToHdf,
  convertXccdfResultsToHdf,
  convertSnykToHdf,
  convertGrypeToHdf,
  convertNessusToHdf,
  convertSonarqubeToHdf,
  convertAwsConfigToHdf,
  convertGosecToHdf,
  convertHdfToCsv,
  convertHdfToXml,
} from '../src/index.js';

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

  it('should export convertGrypeToHdf from main index', () => {
    expect(convertGrypeToHdf).toBeDefined();
    expect(typeof convertGrypeToHdf).toBe('function');
  });

  it('should export convertNessusToHdf from main index', () => {
    expect(convertNessusToHdf).toBeDefined();
    expect(typeof convertNessusToHdf).toBe('function');
  });

  it('should export convertSonarqubeToHdf from main index', () => {
    expect(convertSonarqubeToHdf).toBeDefined();
    expect(typeof convertSonarqubeToHdf).toBe('function');
  });

  it('should export convertAwsConfigToHdf from main index', () => {
    expect(convertAwsConfigToHdf).toBeDefined();
    expect(typeof convertAwsConfigToHdf).toBe('function');
  });

  it('should export convertGosecToHdf from main index', () => {
    expect(convertGosecToHdf).toBeDefined();
    expect(typeof convertGosecToHdf).toBe('function');
  });

  it('should export convertHdfToCsv from main index', () => {
    expect(convertHdfToCsv).toBeDefined();
    expect(typeof convertHdfToCsv).toBe('function');
  });

  it('should export convertHdfToXml from main index', () => {
    expect(convertHdfToXml).toBeDefined();
    expect(typeof convertHdfToXml).toBe('function');
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
