import { buildXml } from '@mitre/hdf-utilities';
import type {
  HDFResults,
  EvaluatedRequirement,
  Description,
} from '@mitre/hdf-schema';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';

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
  // Without this, fast-xml-parser renders selected="true" as a bare `selected`,
  // which is not valid XML — and diverges from the Go serializer.
  suppressBooleanAttributes: false,
};

/**
 * Convert HDF Results JSON to XCCDF 1.2 Benchmark XML.
 *
 * @param input - HDF Results JSON string
 * @returns XCCDF 1.2 XML string
 */
export function convertHdfToXccdf(input: string): string {
  validateInputSize(input, 'hdf-to-xccdf');

  const hdfData = parseHdf<HDFResults>(input);

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
  const empty = !hdfData.baselines || hdfData.baselines.length === 0;

  // Attribute order (id before resolved) and element order mirror the Go
  // serializer's struct field order — the two assert the same golden.
  const benchmark: Record<string, unknown> = {
    [`${ATTR}xmlns`]: 'http://checklists.nist.gov/xccdf/1.2',
    [`${ATTR}id`]: empty
      ? 'xccdf_hdf_benchmark_exported'
      : sanitizeXccdfId('xccdf_hdf_benchmark_' + hdfData.baselines[0]!.name),
    [`${ATTR}resolved`]: '1',
    status: wrap('incomplete'),
  };

  if (empty) {
    benchmark.title = wrap('HDF Export');
    benchmark.version = wrap('1.0');
    return benchmark;
  }

  const baseline = hdfData.baselines[0]!;

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

  // References: url/uri -> <reference href>, plain string -> <reference>text
  if (Array.isArray(req.refs) && req.refs.length > 0) {
    const refs = req.refs
      .map((r): Record<string, unknown> | undefined => {
        const o = r as { url?: unknown; uri?: unknown; ref?: unknown };
        if (typeof o.url === 'string') return { [`${ATTR}href`]: o.url };
        if (typeof o.uri === 'string') return { [`${ATTR}href`]: o.uri };
        if (typeof o.ref === 'string') return { '#text': o.ref };
        return undefined;
      })
      .filter((x): x is Record<string, unknown> => x !== undefined);
    if (refs.length > 0) {
      rule.reference = refs;
    }
  }

  const rationale = findDescription(req.descriptions, 'rationale');
  if (rationale) {
    rule.rationale = wrap(rationale);
  }

  // XCCDF Rule is an ordered sequence: ident precedes fixtext/fix/check.
  // Idents: CCI and NIST 800-53 controls
  const idents: Record<string, unknown>[] = [];
  if (req.tags && Array.isArray(req.tags['cci'])) {
    for (const cci of req.tags['cci'] as string[]) {
      idents.push({ [`${ATTR}system`]: 'http://cyber.mil/cci', '#text': cci });
    }
  }
  if (req.tags && Array.isArray(req.tags['nist'])) {
    for (const n of req.tags['nist'] as string[]) {
      idents.push({ [`${ATTR}system`]: 'https://csrc.nist.gov/projects/risk-management/sp800-53-controls', '#text': n });
    }
  }
  if (idents.length > 0) {
    rule.ident = idents;
  }

  const fixtext = findDescription(req.descriptions, 'fix');
  if (fixtext) {
    rule.fixtext = wrap(fixtext);
  }

  // Checks: the check-description (OVAL) and the InSpec source code, each its own <check>.
  const checks: Record<string, unknown>[] = [];
  const checkContent = findDescription(req.descriptions, 'check');
  if (checkContent) {
    checks.push({
      [`${ATTR}system`]: 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
      'check-content': wrap(checkContent),
    });
  }
  if (req.code) {
    checks.push({
      [`${ATTR}system`]: 'http://inspec.io/',
      'check-content': wrap(req.code),
    });
  }
  if (checks.length > 0) {
    rule.check = checks;
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
  let passed = 0;
  let scorable = 0;
  for (const req of baseline.requirements) {
    const ruleIdRef = sanitizeXccdfId('xccdf_hdf_rule_' + req.id + '_rule');

    for (const result of req.results) {
      const status = hdfStatusToXccdf(result.status);
      if (status === 'pass') {
        passed++;
        scorable++;
      } else if (status === 'fail') {
        scorable++;
      }
      const rr: Record<string, unknown> = {
        [`${ATTR}idref`]: ruleIdRef,
        result: wrap(status),
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

  // XCCDF requires a score element after the rule-results. Emit the
  // default-model pass percentage over scorable (pass/fail) rule-results.
  const score = scorable > 0 ? (passed / scorable) * 100 : 0;
  testResult.score = {
    [`${ATTR}system`]: 'urn:xccdf:scoring:default',
    [`${ATTR}maximum`]: '100.000000',
    '#text': score.toFixed(6),
  };

  return testResult;
}
