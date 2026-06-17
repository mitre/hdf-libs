/**
 * OSCAL Catalog to HDF Baseline converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_catalog.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { deriveControlTypeFromTags, inputIntegrity, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HDFBaseline, BaselineRequirement } from '@mitre/hdf-schema';
import type { Description, RequirementGroup } from '@mitre/hdf-schema';
import { Applicability } from '@mitre/hdf-schema';
import type { Oscal, Catalog, Control } from './types.js';
import {
  controlIdToNistTag,
  extractPropValue,
  flattenPartsByName,
  extractMetadata,
  toKebabCase,
} from './shared.js';

/**
 * Converts an OSCAL Catalog document to HDF Baseline JSON.
 *
 * @param input - Raw JSON string containing an OSCAL catalog
 * @returns HDF Baseline JSON string
 */
export async function convertOscalCatalogToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-catalog');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc.catalog) {
    throw new Error(
      "oscal-catalog: input is not a catalog document (root key is not 'catalog')",
    );
  }

  const baseline = await catalogToBaseline(doc.catalog, input);
  return JSON.stringify(baseline, null, 2);
}

/**
 * Shared logic: converts a parsed Catalog to HDFBaseline.
 * Also used by the profile converter after resolving.
 */
export async function catalogToBaseline(
  catalog: Catalog,
  rawInput: string,
): Promise<HDFBaseline> {
  const integrity = await inputIntegrity(rawInput);
  const meta = extractMetadata(catalog.metadata);

  const requirements: BaselineRequirement[] = [];
  const groups: RequirementGroup[] = [];

  for (const group of catalog.groups ?? []) {
    const reqIDs: string[] = [];

    for (const ctrl of group.controls ?? []) {
      const req = controlToBaselineRequirement(ctrl);
      requirements.push(req);
      reqIDs.push(req.id);

      // Include control enhancements
      for (const enh of ctrl.controls ?? []) {
        const enhReq = controlToBaselineRequirement(enh);
        requirements.push(enhReq);
        reqIDs.push(enhReq.id);
      }
    }

    if (reqIDs.length > 0) {
      groups.push({
        id: group.id ?? '',
        title: group.title,
        requirements: reqIDs,
      });
    }
  }

  // Top-level controls (outside groups)
  for (const ctrl of catalog.controls ?? []) {
    const req = controlToBaselineRequirement(ctrl);
    requirements.push(req);

    for (const enh of ctrl.controls ?? []) {
      const enhReq = controlToBaselineRequirement(enh);
      requirements.push(enhReq);
    }
  }

  const baseline: HDFBaseline = {
    name: catalogBaselineName(catalog),
    title: meta.title,
    version: meta.version,
    status: 'loaded',
    integrity,
    requirements,
    groups,
    generator: {
      name: 'oscal-catalog-to-hdf',
      version: '1.0.0',
    },
  };

  return baseline;
}

/** Converts a single OSCAL Control to an HDF BaselineRequirement. */
function controlToBaselineRequirement(ctrl: Control): BaselineRequirement {
  const nistTag = controlIdToNistTag(ctrl.id);
  const descriptions = buildCatalogDescriptions(ctrl);
  const tags = buildCatalogTags(ctrl);

  const req: BaselineRequirement = {
    id: nistTag,
    title: ctrl.title,
    impact: 0.5, // default for catalog controls
    descriptions,
    tags,
  };

  const controlType = deriveControlTypeFromTags([nistTag]);
  if (controlType !== undefined) req.controlType = controlType;

  // FedRAMP rev5 marks mandatory controls in a baseline with prop[name=CORE,value=true].
  // Catalogs typically don't carry CORE props, but resolved profiles (distributed
  // by FedRAMP as catalogs) do. When present, map CORE=true to applicability=required.
  // Absence is intentionally left undefined; consumers may interpret omitted as required
  // by convention. We do NOT map non-CORE to "optional" because catalog-only inputs
  // omit the prop entirely on all controls, which would be misleading.
  const coreProp = extractPropValue(ctrl.props, 'CORE');
  if (coreProp === 'true') {
    req.applicability = Applicability.Required;
  }

  return req;
}

/** Creates HDF Description entries from control parts. */
function buildCatalogDescriptions(ctrl: Control): Description[] {
  const descriptions: Description[] = [];

  // Statement -> default description
  const statement = flattenPartsByName(ctrl.parts, 'statement');
  descriptions.push({
    label: 'default',
    data: statement || '',
  });

  // Guidance -> rationale
  const guidance = flattenPartsByName(ctrl.parts, 'guidance');
  if (guidance) {
    descriptions.push({ label: 'rationale', data: guidance });
  }

  // Assessment objective -> check
  const check = flattenPartsByName(ctrl.parts, 'assessment-objective');
  if (check) {
    descriptions.push({ label: 'check', data: check });
  }

  return descriptions;
}

/** Builds the tags map for an OSCAL catalog control. */
function buildCatalogTags(ctrl: Control): Record<string, unknown> {
  const tags: Record<string, unknown> = {};

  const nistTag = controlIdToNistTag(ctrl.id);
  tags['nist'] = [nistTag];

  const label = extractPropValue(ctrl.props, 'label');
  if (label !== undefined) {
    tags['label'] = label;
  }

  const sortId = extractPropValue(ctrl.props, 'sort-id');
  if (sortId !== undefined) {
    tags['sort-id'] = sortId;
  }

  return tags;
}

/** Derives a baseline name from catalog metadata. */
function catalogBaselineName(catalog: Catalog): string {
  return toKebabCase(catalog.metadata.title, 'oscal-catalog');
}
