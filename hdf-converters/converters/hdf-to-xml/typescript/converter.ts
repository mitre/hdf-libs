import { parseJSON, buildXml } from '@mitre/hdf-utilities';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement, Component, Description, RequirementResult } from '@mitre/hdf-schema';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';

/**
 * Convert HDF JSON to XML format
 * @param input HDF JSON string
 * @returns XML string with proper HDF structure
 */
export function convertHdfToXml(input: string): string {
  validateInputSize(input, 'hdf-to-xml');
  const hdf = parseJSON<HDFResults>(input);

  if (!hdf || typeof hdf !== 'object' || !('baselines' in hdf)) {
    throw new Error('Invalid HDF structure: missing baselines field');
  }

  if (!Array.isArray(hdf.baselines)) {
    throw new Error('Invalid HDF structure: baselines must be an array');
  }

  // Transform HDF structure to XML-friendly format
  const xmlObj = {
    HdfResults: transformHdfToXmlObject(hdf)
  };

  return buildXml(xmlObj);
}

/**
 * Wrap primitive values to force them as nested elements instead of attributes
 */
function wrap(value: string | number | boolean): { '#text': string | number | boolean } {
  return { '#text': value };
}

/**
 * Transform HDF object to XML-compatible structure
 * Converts arrays to repeated singular elements
 */
function transformHdfToXmlObject(hdf: HDFResults): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  // Transform baselines array
  if (hdf.baselines && hdf.baselines.length > 0) {
    result.baselines = {
      baseline: hdf.baselines.map((baseline: EvaluatedBaseline) => ({
        name: wrap(baseline.name),
        ...(baseline.version && { version: wrap(baseline.version) }),
        ...(baseline.title && { title: wrap(baseline.title) }),
        ...(baseline.integrity && {
          integrity: {
            ...(baseline.integrity.algorithm && { algorithm: wrap(baseline.integrity.algorithm) }),
            ...(baseline.integrity.checksum && { checksum: wrap(baseline.integrity.checksum) })
          }
        }),
        ...(baseline.requirements && baseline.requirements.length > 0 && {
          requirements: {
            requirement: baseline.requirements.map((req: EvaluatedRequirement) => transformRequirement(req))
          }
        }),
        ...(baseline.requirements && baseline.requirements.length === 0 && {
          requirements: {}
        })
      }))
    };
  } else {
    result.baselines = {};
  }

  // Transform components array
  if (hdf.components && hdf.components.length > 0) {
    result.components = {
      target: hdf.components.map((target: Component) => ({
        name: wrap(target.name),
        type: wrap(target.type),
        ...(target.hostname && { hostname: wrap(target.hostname) }),
        ...(target.fqdn && { fqdn: wrap(target.fqdn) }),
        ...(target.domain && { domain: wrap(target.domain) }),
        ...(target.ipAddress && { ipAddress: wrap(target.ipAddress) })
      }))
    };
  }

  // Transform statistics
  if (hdf.statistics) {
    result.statistics = {};
    if (hdf.statistics.duration !== undefined) {
      (result.statistics as Record<string, unknown>).duration = wrap(hdf.statistics.duration);
    }
    if (hdf.statistics.requirements) {
      (result.statistics as Record<string, unknown>).requirements = hdf.statistics.requirements;
    }
  }

  // Add other optional fields
  if (hdf.timestamp) {
    result.timestamp = wrap(typeof hdf.timestamp === 'string' ? hdf.timestamp : hdf.timestamp.toISOString());
  }
  if (hdf.generator) {
    result.generator = hdf.generator;
  }

  return result;
}

/**
 * Transform a requirement object for XML output
 */
function transformRequirement(req: EvaluatedRequirement): Record<string, unknown> {
  const result: Record<string, unknown> = {
    id: wrap(req.id),
    ...(req.title && { title: wrap(req.title) }),
    ...(req.descriptions && req.descriptions.length > 0 && {
      descriptions: {
        description: req.descriptions.map((d: Description) => ({
          label: wrap(d.label),
          data: wrap(d.data)
        }))
      }
    }),
    impact: wrap(req.impact)
  };

  // Transform tags (handle arrays within tags object)
  if (req.tags && Object.keys(req.tags).length > 0) {
    const transformedTags: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(req.tags)) {
      if (Array.isArray(value) && value.length > 0) {
        // Repeat the tag name for each array element (wrapped)
        transformedTags[key] = value.map((v: string | number | boolean) => wrap(v));
      } else if (!Array.isArray(value)) {
        transformedTags[key] = wrap(value);
      }
    }
    if (Object.keys(transformedTags).length > 0) {
      result.tags = transformedTags;
    }
  }

  // Transform results array
  if (req.results && req.results.length > 0) {
    result.results = {
      result: req.results.map((r: RequirementResult) => ({
        status: wrap(r.status),
        codeDesc: wrap(r.codeDesc),
        startTime: wrap(typeof r.startTime === 'string' ? r.startTime : r.startTime.toISOString()),
        ...(r.message && { message: wrap(r.message) }),
        ...(r.runTime !== undefined && { runTime: wrap(r.runTime) })
      }))
    };
  }

  return result;
}
