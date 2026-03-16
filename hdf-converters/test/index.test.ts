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
  convertNiktoToHdf,
  convertZapToHdf,
  convertCyclonedxToHdf,
  convertSplunkToHdf,
  convertHdfToCsv,
  convertHdfToXml,
  convertGitlabToHdf,
  convertTrufflehogToHdf,
  convertBurpsuiteToHdf,
  convertDbprotectToHdf,
  convertTwistlockToHdf,
  convertDeptrackToHdf,
  convertJfrogXrayToHdf,
  convertNeuvectorToHdf,
  convertFortifyToHdf,
  convertPrismaToHdf,
  convertNetsparkerToHdf,
  convertScoutsuiteToHdf,
  convertConveyorToHdf,
  convertVeracodeToHdf,
  convertMsftSecureScoreToHdf,
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

  it('should export convertNiktoToHdf from main index', () => {
    expect(convertNiktoToHdf).toBeDefined();
    expect(typeof convertNiktoToHdf).toBe('function');
  });

  it('should export convertZapToHdf from main index', () => {
    expect(convertZapToHdf).toBeDefined();
    expect(typeof convertZapToHdf).toBe('function');
  });

  it('should export convertCyclonedxToHdf from main index', () => {
    expect(convertCyclonedxToHdf).toBeDefined();
    expect(typeof convertCyclonedxToHdf).toBe('function');
  });

  it('should export convertSplunkToHdf from main index', () => {
    expect(convertSplunkToHdf).toBeDefined();
    expect(typeof convertSplunkToHdf).toBe('function');
  });

  it('should export convertHdfToCsv from main index', () => {
    expect(convertHdfToCsv).toBeDefined();
    expect(typeof convertHdfToCsv).toBe('function');
  });

  it('should export convertHdfToXml from main index', () => {
    expect(convertHdfToXml).toBeDefined();
    expect(typeof convertHdfToXml).toBe('function');
  });

  it('should export convertGitlabToHdf from main index', () => {
    expect(convertGitlabToHdf).toBeDefined();
    expect(typeof convertGitlabToHdf).toBe('function');
  });

  it('should export convertTrufflehogToHdf from main index', () => {
    expect(convertTrufflehogToHdf).toBeDefined();
    expect(typeof convertTrufflehogToHdf).toBe('function');
  });

  it('should export convertJfrogXrayToHdf from main index', () => {
    expect(convertJfrogXrayToHdf).toBeDefined();
    expect(typeof convertJfrogXrayToHdf).toBe('function');
  });

  it('should export convertDeptrackToHdf from main index', () => {
    expect(convertDeptrackToHdf).toBeDefined();
    expect(typeof convertDeptrackToHdf).toBe('function');
  });

  it('should export convertTwistlockToHdf from main index', () => {
    expect(convertTwistlockToHdf).toBeDefined();
    expect(typeof convertTwistlockToHdf).toBe('function');
  });

  it('should export convertDbprotectToHdf from main index', () => {
    expect(convertDbprotectToHdf).toBeDefined();
    expect(typeof convertDbprotectToHdf).toBe('function');
  });

  it('should export convertBurpsuiteToHdf from main index', () => {
    expect(convertBurpsuiteToHdf).toBeDefined();
    expect(typeof convertBurpsuiteToHdf).toBe('function');
  });

  it('should export convertMsftSecureScoreToHdf from main index', () => {
    expect(convertMsftSecureScoreToHdf).toBeDefined();
    expect(typeof convertMsftSecureScoreToHdf).toBe('function');
  });

  it('should export convertVeracodeToHdf from main index', () => {
    expect(convertVeracodeToHdf).toBeDefined();
    expect(typeof convertVeracodeToHdf).toBe('function');
  });

  it('should export convertConveyorToHdf from main index', () => {
    expect(convertConveyorToHdf).toBeDefined();
    expect(typeof convertConveyorToHdf).toBe('function');
  });

  it('should export convertScoutsuiteToHdf from main index', () => {
    expect(convertScoutsuiteToHdf).toBeDefined();
    expect(typeof convertScoutsuiteToHdf).toBe('function');
  });

  it('should export convertNetsparkerToHdf from main index', () => {
    expect(convertNetsparkerToHdf).toBeDefined();
    expect(typeof convertNetsparkerToHdf).toBe('function');
  });

  it('should export convertPrismaToHdf from main index', () => {
    expect(convertPrismaToHdf).toBeDefined();
    expect(typeof convertPrismaToHdf).toBe('function');
  });

  it('should export convertFortifyToHdf from main index', () => {
    expect(convertFortifyToHdf).toBeDefined();
    expect(typeof convertFortifyToHdf).toBe('function');
  });

  it('should export convertNeuvectorToHdf from main index', () => {
    expect(convertNeuvectorToHdf).toBeDefined();
    expect(typeof convertNeuvectorToHdf).toBe('function');
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
