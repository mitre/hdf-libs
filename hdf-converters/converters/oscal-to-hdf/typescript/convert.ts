import { convertOscalCatalogToHdf } from './converter-catalog.js';
import { convertOscalComponentToHdf } from './converter-component.js';
import { convertOscalPoamToHdf } from './converter-poam.js';
import { convertOscalSapToHdf } from './converter-sap.js';
import { convertOscalSarToHdf } from './converter-sar.js';
import { convertOscalSspToHdf } from './converter-ssp.js';
import { detectOscalDocumentType } from './detect.js';

/**
 * Domain-level auto-detect entry point: detects the OSCAL document type and
 * dispatches to the matching per-type converter, returning the serialized HDF
 * document (baseline / system / plan / results / amendments). Mirrors the Go
 * ConvertOSCALToHDF seam shared by the CLI auto-detect wrapper and the snapshot
 * harness.
 *
 * Profile resolution requires a separate catalog input, so it cannot be handled
 * from a single document; callers that need it must invoke convertOscalProfileToHdf
 * directly with both inputs.
 */
export async function convertOscalToHdf(input: string): Promise<string> {
  const docType = detectOscalDocumentType(input);
  switch (docType) {
    case 'catalog':
      return convertOscalCatalogToHdf(input);
    case 'component-definition':
      return convertOscalComponentToHdf(input);
    case 'system-security-plan':
      return convertOscalSspToHdf(input);
    case 'assessment-plan':
      return convertOscalSapToHdf(input);
    case 'assessment-results':
      return convertOscalSarToHdf(input);
    case 'plan-of-action-and-milestones':
      return convertOscalPoamToHdf(input);
    case 'profile':
      throw new Error(
        'oscal profile requires a separate catalog input; call convertOscalProfileToHdf with both documents',
      );
    default:
      throw new Error(`unsupported OSCAL document type ${String(docType)}`);
  }
}
