/**
 * OSCAL System Security Plan (SSP) to HDF System converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_ssp.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { inputIntegrity, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HDFSystem } from '@mitre/hdf-schema';
import {
  AuthorizationStatus,
  CategorizationLevel,
  TargetType,
} from '@mitre/hdf-schema';
// Import Component from system types to avoid type incompatibility with results Component
import type { Component as HdfComponent } from '@mitre/hdf-schema/hdf-system';
import type {
  Oscal,
  SystemSecurityPlanSSP,
  SecurityImpactLevel,
  AssessmentAssetsComponent,
  ControlImplementationClass,
} from './types.js';
import { controlIdToNistTag, extractMetadata } from './shared.js';

/**
 * Converts an OSCAL System Security Plan document to HDF System JSON.
 *
 * @param input - Raw JSON string containing an OSCAL SSP
 * @returns HDF System JSON string
 */
export async function convertOscalSspToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-ssp');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc['system-security-plan']) {
    throw new Error(
      "oscal-ssp: input is not a system-security-plan document (root key is not 'system-security-plan')",
    );
  }

  const ssp = doc['system-security-plan'];
  const integrity = await inputIntegrity(input);

  const system: HDFSystem = {
    name: sspSystemName(ssp),
    integrity,
    components: [],
    generator: {
      name: 'hdf-converters',
      version: '1.0.0',
    },
  };

  // Map system characteristics
  const sc = ssp['system-characteristics'];
  if (sc) {
    if (sc.description) {
      let desc = sc.description;
      if (sc['authorization-boundary']?.description) {
        desc += '\n\nAuthorization Boundary: ' + sc['authorization-boundary'].description;
      }
      system.description = desc;
    }

    // Map categorization level from security impact level
    const sil = sc['security-impact-level'];
    if (sil) {
      system.categorizationLevel = sspCategorizationLevel(sil) ?? undefined;
    } else if (sc['security-sensitivity-level']) {
      system.categorizationLevel = mapSensitivityToCategorizationLevel(sc['security-sensitivity-level']) ?? undefined;
    }

    // Map authorization status from system status
    if (sc.status) {
      system.authorizationStatus = sspAuthorizationStatus(sc.status.state) ?? undefined;
    }

    // Map boundary description
    if (sc['authorization-boundary']?.description) {
      system.boundaryDescription = sc['authorization-boundary'].description;
    }

    // Map system identifier
    const systemIds = sc['system-ids'];
    if (systemIds && systemIds.length > 0) {
      system.identifier = systemIds[0]!.id;
      if (systemIds[0]!['identifier-type']) {
        system.identifierScheme = systemIds[0]!['identifier-type'];
      }
    }
  }

  // Map version from metadata
  const meta = extractMetadata(ssp.metadata);
  if (meta.version) {
    system.version = meta.version;
  }

  // Build component-UUID -> control-ID mapping
  const componentControls = buildComponentControlMap(ssp['control-implementation']);

  // Map system-implementation components to HDF Components
  const si = ssp['system-implementation'];
  if (si?.components) {
    for (const comp of si.components) {
      system.components.push(sspComponentToHDFComponent(comp, componentControls));
    }
  }

  return JSON.stringify(system, null, 2);
}

function sspSystemName(ssp: SystemSecurityPlanSSP): string {
  const sc = ssp['system-characteristics'];
  if (sc?.['system-name']) {
    return sc['system-name'];
  }
  if (ssp.metadata.title) {
    return ssp.metadata.title;
  }
  return 'oscal-ssp';
}

function sspCategorizationLevel(
  sil: SecurityImpactLevel,
): CategorizationLevel | null {
  const levels = [
    sil['security-objective-confidentiality'] ?? '',
    sil['security-objective-integrity'] ?? '',
    sil['security-objective-availability'] ?? '',
  ];

  let highest = '';
  for (const l of levels) {
    const normalized = normalizeFIPSLevel(l);
    if (fipsLevelRank(normalized) > fipsLevelRank(highest)) {
      highest = normalized;
    }
  }

  if (!highest) return null;

  switch (highest) {
    case 'high':
      return CategorizationLevel.High;
    case 'moderate':
      return CategorizationLevel.Moderate;
    case 'low':
      return CategorizationLevel.Low;
    default:
      return null;
  }
}

function normalizeFIPSLevel(level: string): string {
  let lower = level.toLowerCase();
  lower = lower.replace(/^fips-199-/, '');
  switch (lower) {
    case 'high':
      return 'high';
    case 'moderate':
    case 'medium':
      return 'moderate';
    case 'low':
      return 'low';
    default:
      return '';
  }
}

function fipsLevelRank(level: string): number {
  switch (level) {
    case 'high':
      return 3;
    case 'moderate':
      return 2;
    case 'low':
      return 1;
    default:
      return 0;
  }
}

function mapSensitivityToCategorizationLevel(
  level: string,
): CategorizationLevel | null {
  const normalized = normalizeFIPSLevel(level);
  if (!normalized) return null;

  switch (normalized) {
    case 'high':
      return CategorizationLevel.High;
    case 'moderate':
      return CategorizationLevel.Moderate;
    case 'low':
      return CategorizationLevel.Low;
    default:
      return null;
  }
}

function sspAuthorizationStatus(state: string): AuthorizationStatus | null {
  switch (state.toLowerCase()) {
    case 'operational':
      return AuthorizationStatus.Authorized;
    case 'under-development':
      return AuthorizationStatus.PendingAuthorization;
    case 'disposition':
      return AuthorizationStatus.Revoked;
    case 'other':
      return AuthorizationStatus.NotYetRequested;
    default:
      return null;
  }
}

function buildComponentControlMap(
  ci: ControlImplementationClass | undefined,
): Map<string, Set<string>> {
  const result = new Map<string, Set<string>>();
  if (!ci) return result;

  for (const ir of ci['implemented-requirements'] ?? []) {
    const controlId = ir['control-id'];

    // Direct by-components on the implemented-requirement
    for (const bc of ir['by-components'] ?? []) {
      addComponentControl(result, bc['component-uuid'], controlId);
    }

    // by-components within statements
    for (const stmt of ir.statements ?? []) {
      for (const bc of stmt['by-components'] ?? []) {
        addComponentControl(result, bc['component-uuid'], controlId);
      }
    }
  }

  return result;
}

function addComponentControl(
  m: Map<string, Set<string>>,
  compUUID: string,
  controlId: string,
): void {
  let controls = m.get(compUUID);
  if (!controls) {
    controls = new Set<string>();
    m.set(compUUID, controls);
  }
  controls.add(controlId);
}

function sspComponentToHDFComponent(
  sc: AssessmentAssetsComponent,
  componentControls: Map<string, Set<string>>,
): HdfComponent {
  const comp: HdfComponent = {
    name: sc.title,
    type: mapOSCALComponentType(sc.type),
  };

  if (sc.description) {
    comp.description = sc.description;
  }

  // Add control IDs as baseline refs (NIST notation)
  const controls = componentControls.get(sc.uuid);
  if (controls && controls.size > 0) {
    const refs: string[] = [];
    for (const controlId of controls) {
      refs.push(controlIdToNistTag(controlId));
    }
    if (refs.length > 0) {
      comp.baselineRefs = refs;
    }
  }

  return comp;
}

function mapOSCALComponentType(oscalType: string): TargetType {
  switch (oscalType.toLowerCase()) {
    case 'software':
    case 'this-system':
      return TargetType.Application;
    case 'service':
      return TargetType.Application;
    case 'hardware':
      return TargetType.Host;
    case 'network':
      return TargetType.Network;
    case 'database':
      return TargetType.Database;
    case 'storage':
      return TargetType.Artifact;
    default:
      return TargetType.Application;
  }
}
