import { parseJSON, buildXml } from '@mitre/hdf-utilities';
import type {
  HDFResults,
  EvaluatedRequirement,
  Description,
} from '@mitre/hdf-schema';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';

/** Attribute prefix used by fast-xml-parser to distinguish attrs from elements. */
const ATTR = '@_';

/** XML build options that enable attribute rendering via @_ prefix. */
const BUILD_OPTIONS = {
  attributeNamePrefix: ATTR,
  textNodeName: '#text',
  ignoreAttributes: false,
  format: true,
  indentBy: '  ',
  suppressEmptyNode: false,
};

/**
 * Convert HDF Results JSON to XCCDF 1.2 Benchmark XML.
 *
 * @param input - HDF Results JSON string
 * @returns XCCDF 1.2 XML string
 */
export function convertHdfToXccdf(input: string): string {
  validateInputSize(input, 'hdf-to-xccdf');

  const hdfData = parseJSON<HDFResults>(input);

  if (!hdfData || typeof hdfData !== 'object' || !('baselines' in hdfData)) {
    throw new Error('Invalid HDF structure: missing baselines field');
  }

  if (!Array.isArray(hdfData.baselines)) {
    throw new Error('Invalid HDF structure: baselines must be an array');
  }

  const xmlObj = { Benchmark: buildBenchmarkObj(hdfData) };

  const xmlBody = buildXml(xmlObj, BUILD_OPTIONS);
  return `<?xml version="1.0" encoding="UTF-8"?>\n${xmlBody}`;
}

/** Wrap a primitive value to force it as a text node in XML output. */
function wrap(
  value: string | number | boolean,
): { '#text': string | number | boolean } {
  return { '#text': value };
}

/** Map HDF impact (0.0-1.0) to XCCDF severity string. */
function impactToSeverity(impact: number): string {
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'medium';
  if (impact >= 0.1) return 'low';
  return 'info';
}

/** Map HDF result status to XCCDF result value. */
function hdfStatusToXccdf(status: string): string {
  const statusMap: Record<string, string> = {
    passed: 'pass',
    failed: 'fail',
    error: 'error',
    notReviewed: 'notchecked',
    notApplicable: 'notapplicable',
  };
  return statusMap[status] ?? 'unknown';
}

/** Find a description by label. */
function findDescription(
  descriptions: Description[] | undefined,
  label: string,
): string | undefined {
  return descriptions?.find((d) => d.label === label)?.data;
}

/** Replace characters not valid in XCCDF IDs with underscores. */
function sanitizeXccdfId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_.\-]/g, '_');
}

/** Build the Benchmark XML object from HDF data. */
function buildBenchmarkObj(hdfData: HDFResults): Record<string, unknown> {
  const benchmark: Record<string, unknown> = {
    [`${ATTR}xmlns`]: 'http://checklists.nist.gov/xccdf/1.2',
    [`${ATTR}resolved`]: '1',
    status: wrap('incomplete'),
  };

  if (!hdfData.baselines || hdfData.baselines.length === 0) {
    benchmark[`${ATTR}id`] = 'xccdf_hdf_benchmark_exported';
    benchmark.title = wrap('HDF Export');
    benchmark.version = wrap('1.0');
    return benchmark;
  }

  const baseline = hdfData.baselines[0]!;

  benchmark[`${ATTR}id`] = sanitizeXccdfId(
    'xccdf_hdf_benchmark_' + baseline.name,
  );
  benchmark.title = wrap(baseline.title ?? baseline.name);
  benchmark.version = wrap(baseline.version ?? '1.0');

  // Profile
  benchmark.Profile = {
    [`${ATTR}id`]: sanitizeXccdfId('xccdf_hdf_profile_' + baseline.name),
    title: wrap(baseline.title ?? baseline.name),
  };

  // Rules
  if (baseline.requirements && baseline.requirements.length > 0) {
    benchmark.Rule = baseline.requirements.map((req: EvaluatedRequirement) => buildRuleObj(req));
  }

  // TestResult
  benchmark.TestResult = buildTestResultObj(hdfData, baseline);

  return benchmark;
}

/** Build an XCCDF Rule object from an HDF EvaluatedRequirement. */
function buildRuleObj(req: EvaluatedRequirement): Record<string, unknown> {
  const ruleId = sanitizeXccdfId('xccdf_hdf_rule_' + req.id + '_rule');

  const rule: Record<string, unknown> = {
    [`${ATTR}id`]: ruleId,
    [`${ATTR}severity`]: impactToSeverity(req.impact),
    [`${ATTR}selected`]: 'true',
    title: wrap(req.title ?? req.id),
  };

  const description = findDescription(req.descriptions, 'default');
  if (description) {
    rule.description = wrap(description);
  }

  const fixtext = findDescription(req.descriptions, 'fix');
  if (fixtext) {
    rule.fixtext = wrap(fixtext);
  }

  // CCI idents
  if (req.tags && Array.isArray(req.tags['cci'])) {
    const ccis = req.tags['cci'] as string[];
    if (ccis.length > 0) {
      rule.ident = ccis.map((cci) => ({
        [`${ATTR}system`]: 'http://cyber.mil/cci',
        '#text': cci,
      }));
    }
  }

  // Check content
  const checkContent = findDescription(req.descriptions, 'check');
  if (checkContent) {
    rule.check = {
      [`${ATTR}system`]: 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
      'check-content': wrap(checkContent),
    };
  }

  return rule;
}

/** Build the XCCDF TestResult object. */
function buildTestResultObj(
  hdfData: HDFResults,
  baseline: HDFResults['baselines'][0],
): Record<string, unknown> {
  const testResult: Record<string, unknown> = {
    [`${ATTR}id`]: 'xccdf_hdf_testresult_1',
    title: wrap('HDF Assessment Results'),
  };

  // Timestamps
  if (hdfData.timestamp) {
    const ts =
      typeof hdfData.timestamp === 'string'
        ? hdfData.timestamp
        : (hdfData.timestamp as Date).toISOString();
    testResult[`${ATTR}start-time`] = ts;
    testResult[`${ATTR}end-time`] = ts;
  }

  // Component
  if (hdfData.components && hdfData.components.length > 0) {
    const target = hdfData.components[0]!;
    testResult.target = wrap(target.name);
    if (target.ipAddress) {
      testResult['target-address'] = wrap(target.ipAddress);
    }
  } else {
    testResult.target = wrap('unknown');
  }

  // Rule results
  const ruleResults: Record<string, unknown>[] = [];
  for (const req of baseline.requirements) {
    const ruleIdRef = sanitizeXccdfId('xccdf_hdf_rule_' + req.id + '_rule');

    for (const result of req.results) {
      const rr: Record<string, unknown> = {
        [`${ATTR}idref`]: ruleIdRef,
        result: wrap(hdfStatusToXccdf(result.status)),
      };

      const startTime =
        typeof result.startTime === 'string'
          ? result.startTime
          : (result.startTime as Date).toISOString();
      rr[`${ATTR}time`] = startTime;

      if (result.message) {
        rr.message = wrap(result.message);
      }

      if (result.codeDesc) {
        rr.check = {
          [`${ATTR}system`]:
            'http://oval.mitre.org/XMLSchema/oval-definitions-5',
          'check-content': wrap(result.codeDesc),
        };
      }

      ruleResults.push(rr);
    }
  }

  testResult['rule-result'] = ruleResults;

  return testResult;
}
