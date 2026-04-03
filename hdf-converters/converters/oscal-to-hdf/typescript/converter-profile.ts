/**
 * OSCAL Profile to HDF Baseline converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_profile.go.
 *
 * This implements the "simple resolver" -- it handles:
 * - A single catalog import
 * - include-controls with with-ids filtering
 * - set-parameters from modify section
 * - merge as-is (preserve catalog structure)
 *
 * It does NOT handle:
 * - Multiple imports
 * - Nested profile imports
 * - alter directives
 * - Complex merge strategies
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { inputIntegrity, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  Oscal,
  Catalog,
  Control,
  CatalogControlGroup,
  ImportResource,
  Part,
  ParameterSetting,
} from './types.js';
import { catalogToBaseline } from './converter-catalog.js';

/**
 * Converts an OSCAL Profile against a provided catalog to HDF Baseline JSON.
 *
 * @param profileInput - Raw JSON string containing an OSCAL profile
 * @param catalogInput - Raw JSON string containing an OSCAL catalog
 * @returns HDF Baseline JSON string
 */
export async function convertOscalProfileToHdf(
  profileInput: string,
  catalogInput: string,
): Promise<string> {
  validateInputSize(profileInput, 'oscal-profile');

  if (!profileInput || profileInput.trim().length === 0) {
    throw new Error('empty profile input');
  }
  if (!catalogInput || catalogInput.trim().length === 0) {
    throw new Error('empty catalog input');
  }

  // Parse profile
  const profileDoc = parseJSON<Oscal>(profileInput);
  if (!profileDoc.profile) {
    throw new Error(
      "oscal-profile: input is not a profile document (root key is not 'profile')",
    );
  }
  const profile = profileDoc.profile;

  // Parse catalog
  const catalogDoc = parseJSON<Oscal>(catalogInput);
  if (!catalogDoc.catalog) {
    throw new Error(
      "oscal-profile: catalog input is not a catalog document (root key is not 'catalog')",
    );
  }
  const catalog = catalogDoc.catalog;

  // Validate: single import only
  if (!profile.imports || profile.imports.length === 0) {
    throw new Error('oscal-profile: profile has no imports');
  }
  if (profile.imports.length > 1) {
    throw new Error(
      `oscal-profile: profile has ${profile.imports.length} imports -- this converter only supports single-catalog imports. Use NIST's oscal-cli to resolve complex profiles, or use a pre-resolved catalog`,
    );
  }

  // Validate: no alter directives
  if (profile.modify?.alters && profile.modify.alters.length > 0) {
    throw new Error(
      `oscal-profile: profile contains ${profile.modify.alters.length} alter directives -- this converter only supports parameter overrides. Use NIST's oscal-cli to resolve profiles with alter directives, or use a pre-resolved catalog`,
    );
  }

  // Collect included/excluded control IDs
  const imp = profile.imports[0]!;
  const includedIDs = collectIncludedIDs(imp);
  const excludedIDs = collectExcludedIDs(imp);

  // Filter catalog
  const resolvedCatalog = filterCatalog(catalog, includedIDs, excludedIDs);

  // Apply parameter overrides
  if (profile.modify?.['set-parameters']) {
    applyParameterOverrides(resolvedCatalog, profile.modify['set-parameters']);
  }

  // Override metadata from profile
  resolvedCatalog.metadata = profile.metadata;
  resolvedCatalog.uuid = profile.uuid;

  const baseline = await catalogToBaseline(resolvedCatalog, profileInput);

  // Override the integrity to be based on the profile input
  baseline.integrity = await inputIntegrity(profileInput);

  return JSON.stringify(baseline, null, 2);
}

/** Extracts all control IDs from an import's include-controls. Returns null if include all. */
function collectIncludedIDs(imp: ImportResource): Set<string> | null {
  const includeControls = imp['include-controls'];
  if (!includeControls || includeControls.length === 0) {
    return null; // include all
  }

  const ids = new Set<string>();
  for (const ic of includeControls) {
    for (const id of ic['with-ids'] ?? []) {
      ids.add(id);
    }
  }
  return ids;
}

/** Extracts all control IDs from an import's exclude-controls. */
function collectExcludedIDs(imp: ImportResource): Set<string> | null {
  const excludeControls = imp['exclude-controls'];
  if (!excludeControls || excludeControls.length === 0) {
    return null;
  }

  const ids = new Set<string>();
  for (const ec of excludeControls) {
    for (const id of ec['with-ids'] ?? []) {
      ids.add(id);
    }
  }
  return ids;
}

/** Creates a new catalog containing only the controls matching filters. */
function filterCatalog(
  catalog: Catalog,
  includedIDs: Set<string> | null,
  excludedIDs: Set<string> | null,
): Catalog {
  const includeAll = includedIDs === null;

  const result: Catalog = {
    uuid: catalog.uuid,
    metadata: catalog.metadata,
    'back-matter': catalog['back-matter'],
    groups: [],
    controls: [],
  };

  for (const group of catalog.groups ?? []) {
    const filtered = filterGroupControls(group, includedIDs, excludedIDs, includeAll);
    if (filtered.controls && filtered.controls.length > 0) {
      result.groups!.push(filtered);
    }
  }

  for (const ctrl of catalog.controls ?? []) {
    if (shouldIncludeControl(ctrl.id, includedIDs, excludedIDs, includeAll)) {
      const filteredCtrl = filterControlEnhancements(ctrl, includedIDs, excludedIDs, includeAll);
      result.controls!.push(filteredCtrl);
    }
  }

  return result;
}

function filterGroupControls(
  group: CatalogControlGroup,
  includedIDs: Set<string> | null,
  excludedIDs: Set<string> | null,
  includeAll: boolean,
): CatalogControlGroup {
  const filtered: CatalogControlGroup = {
    id: group.id,
    class: group.class,
    title: group.title,
    props: group.props,
    parts: group.parts,
    controls: [],
  };

  for (const ctrl of group.controls ?? []) {
    if (shouldIncludeControl(ctrl.id, includedIDs, excludedIDs, includeAll)) {
      const filteredCtrl = filterControlEnhancements(ctrl, includedIDs, excludedIDs, includeAll);
      filtered.controls!.push(filteredCtrl);
    }
  }

  return filtered;
}

function filterControlEnhancements(
  ctrl: Control,
  includedIDs: Set<string> | null,
  excludedIDs: Set<string> | null,
  includeAll: boolean,
): Control {
  const result: Control = {
    id: ctrl.id,
    class: ctrl.class,
    title: ctrl.title,
    params: ctrl.params,
    props: ctrl.props,
    links: ctrl.links,
    parts: ctrl.parts,
    controls: [],
  };

  for (const enh of ctrl.controls ?? []) {
    if (shouldIncludeControl(enh.id, includedIDs, excludedIDs, includeAll)) {
      result.controls!.push(enh);
    }
  }

  return result;
}

function shouldIncludeControl(
  id: string,
  includedIDs: Set<string> | null,
  excludedIDs: Set<string> | null,
  includeAll: boolean,
): boolean {
  if (excludedIDs !== null && excludedIDs.has(id)) {
    return false;
  }
  if (includeAll) {
    return true;
  }
  return includedIDs !== null && includedIDs.has(id);
}

/** Applies set-parameters from the profile's modify section to the resolved catalog. */
function applyParameterOverrides(
  catalog: Catalog,
  setParams: ParameterSetting[],
): void {
  if (setParams.length === 0) return;

  // Build param-id -> values lookup
  const overrides = new Map<string, string[]>();
  for (const sp of setParams) {
    if (sp['param-id']) {
      overrides.set(sp['param-id'], sp.values ?? []);
    }
  }

  // Apply to all controls in groups
  for (const group of catalog.groups ?? []) {
    for (const ctrl of group.controls ?? []) {
      applyParamOverridesToControl(ctrl, overrides);
      for (const enh of ctrl.controls ?? []) {
        applyParamOverridesToControl(enh, overrides);
      }
    }
  }

  // Apply to top-level controls
  for (const ctrl of catalog.controls ?? []) {
    applyParamOverridesToControl(ctrl, overrides);
    for (const enh of ctrl.controls ?? []) {
      applyParamOverridesToControl(enh, overrides);
    }
  }
}

function applyParamOverridesToControl(
  ctrl: Control,
  overrides: Map<string, string[]>,
): void {
  if (ctrl.params) {
    for (const param of ctrl.params) {
      if (!param.id) continue;
      const values = overrides.get(param.id);
      if (values) {
        param.label = values.join(', ');
      }
    }
  }

  // Replace parameter insertions in prose
  if (ctrl.parts) {
    for (const part of ctrl.parts) {
      replaceParamInsertions(part, overrides);
    }
  }
}

function replaceParamInsertions(part: Part, overrides: Map<string, string[]>): void {
  if (part.prose) {
    part.prose = substituteParams(part.prose, overrides);
  }
  if (part.parts) {
    for (const child of part.parts) {
      replaceParamInsertions(child, overrides);
    }
  }
}

/** Replaces OSCAL parameter insertion patterns: {{ insert: param, <param-id> }} */
function substituteParams(text: string, overrides: Map<string, string[]>): string {
  let result = text;
  for (const [paramId, values] of overrides) {
    const placeholder = `{{ insert: param, ${paramId} }}`;
    const replacement = values.join(', ');
    result = result.split(placeholder).join(replacement);
  }
  return result;
}
