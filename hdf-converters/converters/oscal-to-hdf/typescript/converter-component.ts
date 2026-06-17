/**
 * OSCAL Component Definition to HDF Baseline converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_component.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { inputIntegrity, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HDFBaseline, BaselineRequirement } from '@mitre/hdf-schema';
import type { Description } from '@mitre/hdf-schema';
import type { Oscal, ImplementedRequirementElement, ComponentDefinitionComponent, ComponentDefinition } from './types.js';
import { controlIdToNistTag, extractMetadata, toKebabCase } from './shared.js';

/**
 * Converts an OSCAL Component Definition document to HDF Baseline JSON.
 *
 * @param input - Raw JSON string containing an OSCAL component-definition
 * @returns HDF Baseline JSON string
 */
export async function convertOscalComponentToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-component-definition');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc['component-definition']) {
    throw new Error(
      "oscal-component-definition: input is not a component-definition document (root key is not 'component-definition')",
    );
  }

  const compDef = doc['component-definition'];

  if (!compDef.components || compDef.components.length === 0) {
    throw new Error('oscal-component-definition: document contains no components');
  }

  const integrity = await inputIntegrity(input);
  const meta = extractMetadata(compDef.metadata);

  // Use the first component to build the baseline
  const comp = compDef.components[0]!;

  const requirements: BaselineRequirement[] = [];
  for (const ci of comp['control-implementations'] ?? []) {
    for (const ir of ci['implemented-requirements'] ?? []) {
      requirements.push(implementedRequirementToBaselineRequirement(ir));
    }
  }

  const baseline: HDFBaseline = {
    name: componentBaselineName(comp, compDef),
    title: meta.title,
    version: meta.version,
    status: 'loaded',
    integrity,
    requirements,
    generator: {
      name: 'oscal-component-to-hdf',
      version: '1.0.0',
    },
  };

  return JSON.stringify(baseline, null, 2);
}

/** Converts a single ImplementedRequirement to a BaselineRequirement. */
function implementedRequirementToBaselineRequirement(
  ir: ImplementedRequirementElement,
): BaselineRequirement {
  const nistTag = controlIdToNistTag(ir['control-id']);

  const descriptions: Description[] = [];

  // Primary description
  descriptions.push({
    label: 'default',
    data: ir.description ?? '',
  });

  // Add statement prose as additional descriptions
  for (const stmt of ir.statements ?? []) {
    if (stmt.description) {
      descriptions.push({
        label: stmt['statement-id'],
        data: stmt.description,
      });
    }
    if (stmt.remarks) {
      descriptions.push({
        label: stmt['statement-id'] + '-remarks',
        data: stmt.remarks,
      });
    }
  }

  const tags: Record<string, unknown> = {
    nist: [nistTag],
  };

  return {
    id: nistTag,
    title: nistTag,
    impact: 0.5,
    descriptions,
    tags,
  };
}

/** Derives a baseline name from the component or component-definition metadata. */
function componentBaselineName(
  comp: ComponentDefinitionComponent,
  compDef: ComponentDefinition,
): string {
  const name = comp.title || compDef.metadata.title;
  return toKebabCase(name, 'oscal-component-definition');
}
