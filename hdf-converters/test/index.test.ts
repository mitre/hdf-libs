import { describe, it, expect } from 'vitest';
import {
  convertV1ToV2,
  isHDFV1,
  convertJunitToHdf,
  convertXccdfResultsToHdf,
  convertCklToHdf,
  convertCklbToHdf,
  convertHdfToCkl,
  convertHdfToCklb,
  convertHdfToAsff,
  convertSnykToHdf,
  convertGrypeToHdf,
  convertDefectDojoToHdf,
  convertNessusToHdf,
  convertSonarqubeToHdf,
  convertAwsConfigToHdf,
  convertCheckovToHdf,
  convertGosecToHdf,
  convertNiktoToHdf,
  convertZapToHdf,
  convertCyclonedxToHdf,
  convertSplunkToHdf,
  convertHdfToCsv,
  convertHdfToXml,
  convertGitlabToHdf,
  convertTrivyToHdf,
  convertTrufflehogToHdf,
  convertHipcheckToHdf,
  convertBurpsuiteToHdf,
  convertDbprotectToHdf,
  convertTwistlockToHdf,
  convertDeptrackToHdf,
  convertJfrogXrayToHdf,
  convertNeuvectorToHdf,
  convertOpenVexToHdf,
  convertCsafVexToHdf,
  convertCyclonedxVexToHdf,
  convertSpdxVexToHdf,
  convertHdfToCsafVex,
  convertHdfToCyclonedxVex,
  convertHdfToOpenVex,
  convertFortifyToHdf,
  convertPrismaToHdf,
  convertNetsparkerToHdf,
  convertScoutsuiteToHdf,
  convertConveyorToHdf,
  convertVeracodeToHdf,
  convertMsftSecureScoreToHdf,
  convertMsftDefenderDevopsToHdf,
  convertMsftDefenderCloudToHdf,
  convertMsftDefenderEndpointToHdf,
  convertIonchannelToHdf,
  convertHdfToXccdf,
  convertHdfToOscalSar,
  convertHdfToOscalPoam,
  convertOscalCatalogToHdf,
  convertOscalProfileToHdf,
  convertOscalComponentToHdf,
  convertOscalSspToHdf,
  convertOscalSapToHdf,
  convertOscalPoamToHdf,
  convertOscalSarToHdf,
  detectOscalDocumentType,
  enrichStix,
  detectStixBundle,
  parseStixBundle,
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
    expect(v2.components).toBeDefined();
  });

  it('should export convertJunitToHdf from main index', () => {
    expect(convertJunitToHdf).toBeDefined();
    expect(typeof convertJunitToHdf).toBe('function');
  });

  it('should export convertXccdfResultsToHdf from main index', () => {
    expect(convertXccdfResultsToHdf).toBeDefined();
    expect(typeof convertXccdfResultsToHdf).toBe('function');
  });

  it('should export convertCklToHdf from main index', () => {
    expect(convertCklToHdf).toBeDefined();
    expect(typeof convertCklToHdf).toBe('function');
  });

  it('should export convertCklbToHdf from main index', () => {
    expect(convertCklbToHdf).toBeDefined();
    expect(typeof convertCklbToHdf).toBe('function');
  });

  it('should export convertHdfToCkl from main index', () => {
    expect(convertHdfToCkl).toBeDefined();
    expect(typeof convertHdfToCkl).toBe('function');
  });

  it('should export convertHdfToAsff from main index', () => {
    expect(convertHdfToAsff).toBeDefined();
    expect(typeof convertHdfToAsff).toBe('function');
  });

  it('should export convertHdfToCklb from main index', () => {
    expect(convertHdfToCklb).toBeDefined();
    expect(typeof convertHdfToCklb).toBe('function');
  });

  it('should export convertSnykToHdf from main index', () => {
    expect(convertSnykToHdf).toBeDefined();
    expect(typeof convertSnykToHdf).toBe('function');
  });

  it('should export convertGrypeToHdf from main index', () => {
    expect(convertGrypeToHdf).toBeDefined();
    expect(typeof convertGrypeToHdf).toBe('function');
  });

  it('should export convertDefectDojoToHdf from main index', () => {
    expect(convertDefectDojoToHdf).toBeDefined();
    expect(typeof convertDefectDojoToHdf).toBe('function');
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

  it('should export convertCheckovToHdf from main index', () => {
    expect(convertCheckovToHdf).toBeDefined();
    expect(typeof convertCheckovToHdf).toBe('function');
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

  it('should export convertTrivyToHdf from main index', () => {
    expect(convertTrivyToHdf).toBeDefined();
    expect(typeof convertTrivyToHdf).toBe('function');
  });

  it('should export convertTrufflehogToHdf from main index', () => {
    expect(convertTrufflehogToHdf).toBeDefined();
    expect(typeof convertTrufflehogToHdf).toBe('function');
  });

  it('should export convertHipcheckToHdf from main index', () => {
    expect(convertHipcheckToHdf).toBeDefined();
    expect(typeof convertHipcheckToHdf).toBe('function');
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

  it('should export convertMsftDefenderDevopsToHdf from main index', () => {
    expect(convertMsftDefenderDevopsToHdf).toBeDefined();
    expect(typeof convertMsftDefenderDevopsToHdf).toBe('function');
  });

  it('should export convertMsftDefenderCloudToHdf from main index', () => {
    expect(convertMsftDefenderCloudToHdf).toBeDefined();
    expect(typeof convertMsftDefenderCloudToHdf).toBe('function');
  });

  it('should export convertMsftDefenderEndpointToHdf from main index', () => {
    expect(convertMsftDefenderEndpointToHdf).toBeDefined();
    expect(typeof convertMsftDefenderEndpointToHdf).toBe('function');
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

  it('should export convertOpenVexToHdf from main index', () => {
    expect(convertOpenVexToHdf).toBeDefined();
    expect(typeof convertOpenVexToHdf).toBe('function');
  });

  it('should export convertCsafVexToHdf from main index', () => {
    expect(convertCsafVexToHdf).toBeDefined();
    expect(typeof convertCsafVexToHdf).toBe('function');
  });

  it('should export convertCyclonedxVexToHdf from main index', () => {
    expect(convertCyclonedxVexToHdf).toBeDefined();
    expect(typeof convertCyclonedxVexToHdf).toBe('function');
  });

  it('should export convertSpdxVexToHdf from main index', () => {
    expect(convertSpdxVexToHdf).toBeDefined();
    expect(typeof convertSpdxVexToHdf).toBe('function');
  });

  it('should export convertHdfToCsafVex from main index', () => {
    expect(convertHdfToCsafVex).toBeDefined();
    expect(typeof convertHdfToCsafVex).toBe('function');
  });

  it('should export convertHdfToOpenVex from main index', () => {
    expect(convertHdfToOpenVex).toBeDefined();
    expect(typeof convertHdfToOpenVex).toBe('function');
  });

  it('should export convertHdfToCyclonedxVex from main index', () => {
    expect(convertHdfToCyclonedxVex).toBeDefined();
    expect(typeof convertHdfToCyclonedxVex).toBe('function');
  });

  it('should export convertNeuvectorToHdf from main index', () => {
    expect(convertNeuvectorToHdf).toBeDefined();
    expect(typeof convertNeuvectorToHdf).toBe('function');
  });

  it('should export convertIonchannelToHdf from main index', () => {
    expect(convertIonchannelToHdf).toBeDefined();
    expect(typeof convertIonchannelToHdf).toBe('function');
  });

  it('should export convertHdfToXccdf from main index', () => {
    expect(convertHdfToXccdf).toBeDefined();
    expect(typeof convertHdfToXccdf).toBe('function');
  });

  it('should export convertHdfToOscalSar from main index', () => {
    expect(convertHdfToOscalSar).toBeDefined();
    expect(typeof convertHdfToOscalSar).toBe('function');
  });

  it('should export convertHdfToOscalPoam from main index', () => {
    expect(convertHdfToOscalPoam).toBeDefined();
    expect(typeof convertHdfToOscalPoam).toBe('function');
  });

  it('should export convertOscalCatalogToHdf from main index', () => {
    expect(convertOscalCatalogToHdf).toBeDefined();
    expect(typeof convertOscalCatalogToHdf).toBe('function');
  });

  it('should export convertOscalProfileToHdf from main index', () => {
    expect(convertOscalProfileToHdf).toBeDefined();
    expect(typeof convertOscalProfileToHdf).toBe('function');
  });

  it('should export convertOscalComponentToHdf from main index', () => {
    expect(convertOscalComponentToHdf).toBeDefined();
    expect(typeof convertOscalComponentToHdf).toBe('function');
  });

  it('should export convertOscalSspToHdf from main index', () => {
    expect(convertOscalSspToHdf).toBeDefined();
    expect(typeof convertOscalSspToHdf).toBe('function');
  });

  it('should export convertOscalSapToHdf from main index', () => {
    expect(convertOscalSapToHdf).toBeDefined();
    expect(typeof convertOscalSapToHdf).toBe('function');
  });

  it('should export convertOscalPoamToHdf from main index', () => {
    expect(convertOscalPoamToHdf).toBeDefined();
    expect(typeof convertOscalPoamToHdf).toBe('function');
  });

  it('should export convertOscalSarToHdf from main index', () => {
    expect(convertOscalSarToHdf).toBeDefined();
    expect(typeof convertOscalSarToHdf).toBe('function');
  });

  it('should export detectOscalDocumentType from main index', () => {
    expect(detectOscalDocumentType).toBeDefined();
    expect(typeof detectOscalDocumentType).toBe('function');
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

  it('should export the STIX enrichment helpers from main index', () => {
    expect(typeof enrichStix).toBe('function');
    expect(typeof detectStixBundle).toBe('function');
    expect(typeof parseStixBundle).toBe('function');
  });

  it('enrichStix from the main export attaches a STIX object to a matching finding', () => {
    const results = JSON.stringify({
      baselines: [
        {
          name: 'B',
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [
            {
              id: 'CVE-2021-44228',
              descriptions: [{ label: 'default', data: 'd' }],
              impact: 0.9,
              tags: {},
              results: [{ status: 'failed', codeDesc: 'x', startTime: '2025-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
      components: [],
      statistics: {},
    });
    const bundle = JSON.stringify({
      type: 'bundle',
      id: 'bundle--1',
      objects: [
        {
          type: 'vulnerability',
          spec_version: '2.1',
          id: 'vulnerability--1',
          name: 'CVE-2021-44228',
          external_references: [{ source_name: 'cve', external_id: 'CVE-2021-44228' }],
        },
      ],
    });
    const out = JSON.parse(enrichStix(results, bundle));
    const req = out.baselines[0].requirements[0];
    expect(req.externalReferences).toHaveLength(1);
    expect(req.externalReferences[0].sourceName).toBe('stix');
    expect(req.externalReferences[0].document.id).toBe('vulnerability--1');
    expect(detectStixBundle(bundle)).toBe(true);
  });
});
