import { buildXml, parseTimestamp, formatTimestamp } from '@mitre/hdf-utilities';
import type {
  HDFResults,
  EvaluatedRequirement,
  Description,
  Tool,
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

/** Read a string-valued tag, or undefined if absent/non-string. */
function tagString(
  tags: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const v = tags?.[key];
  return typeof v === 'string' ? v : undefined;
}

/** Read a string-array tag, dropping non-string members. */
function tagStrings(
  tags: Record<string, unknown> | undefined,
  key: string,
): string[] {
  const v = tags?.[key];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/** Lowercase and strip ':'/space so the value is a safe CPE 2.2 field. */
function cpeField(s: string): string {
  return s.toLowerCase().trim().replace(/[: ]/g, '_');
}

/**
 * Render the HDF tool identity as the CPE 2.2 URI XCCDF's @test-system carries,
 * so the reverse importer recovers tool.version from it. Empty when no version.
 */
function toolTestSystem(tool: Tool | undefined): string | undefined {
  if (!tool || !tool.version) return undefined;
  const name = tool.name ? cpeField(tool.name) : 'tool';
  return `cpe:/a:${name}:${name}:${cpeField(tool.version)}`;
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
  // XCCDF benchmarkType orders description after title and before version.
  if (baseline.summary) {
    benchmark.description = wrap(baseline.summary);
  }
  benchmark.version = wrap(baseline.version ?? '1.0');

  // Profile
  benchmark.Profile = {
    [`${ATTR}id`]: sanitizeXccdfId('xccdf_hdf_profile_' + baseline.name),
    title: wrap(baseline.title ?? baseline.name),
  };

  // Rules: those carrying a gid tag are nested in their XCCDF Group (dedup by
  // gid, first-seen order) so the reverse importer rebuilds the hierarchy;
  // ungrouped rules stay flat under the Benchmark.
  const groups: Record<string, unknown>[] = [];
  const groupIndex = new Map<string, number>();
  const flatRules: Record<string, unknown>[] = [];
  if (baseline.requirements && baseline.requirements.length > 0) {
    for (const req of baseline.requirements) {
      const rule = buildRuleObj(req);
      const gid = tagString(req.tags, 'gid');
      if (!gid) {
        flatRules.push(rule);
        continue;
      }
      let idx = groupIndex.get(gid);
      if (idx === undefined) {
        idx = groups.length;
        groupIndex.set(gid, idx);
        const group: Record<string, unknown> = { [`${ATTR}id`]: gid };
        const gtitle = tagString(req.tags, 'gtitle');
        if (gtitle) group.title = wrap(gtitle);
        group.Rule = [] as Record<string, unknown>[];
        groups.push(group);
      }
      (groups[idx]!.Rule as Record<string, unknown>[]).push(rule);
    }
  }
  // Order (Profile, Group, Rule, TestResult) mirrors the Go struct and the XSD.
  if (groups.length > 0) {
    benchmark.Group = groups;
  }
  if (flatRules.length > 0) {
    benchmark.Rule = flatRules;
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
  };

  // XCCDF ruleType orders version before title; carries the STIG ID.
  const stigId = tagString(req.tags, 'stig_id');
  if (stigId) {
    rule.version = wrap(stigId);
  }
  rule.title = wrap(req.title ?? req.id);

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
  // Idents: CCI, CCE, legacy DISA IDs, and NIST 800-53 controls. Order matches
  // the Go twin for byte parity; the reverse importer buckets by @system.
  const idents: Record<string, unknown>[] = [];
  for (const cci of tagStrings(req.tags, 'cci')) {
    idents.push({ [`${ATTR}system`]: 'http://cyber.mil/cci', '#text': cci });
  }
  const cce = tagString(req.tags, 'cce');
  if (cce) {
    idents.push({ [`${ATTR}system`]: 'http://cce.mitre.org', '#text': cce });
  }
  for (const legacy of tagStrings(req.tags, 'legacy_id')) {
    idents.push({ [`${ATTR}system`]: 'http://cyber.mil/legacy', '#text': legacy });
  }
  for (const n of tagStrings(req.tags, 'nist')) {
    idents.push({ [`${ATTR}system`]: 'https://csrc.nist.gov/projects/risk-management/sp800-53-controls', '#text': n });
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

  // Timestamps. end-time carries the scan window: start + statistics.duration so
  // the duration round-trips (the importer derives duration = end − start).
  if (hdfData.timestamp) {
    const ts =
      typeof hdfData.timestamp === 'string'
        ? hdfData.timestamp
        : (hdfData.timestamp as Date).toISOString();
    testResult[`${ATTR}start-time`] = ts;

    let endTime = ts;
    const duration = hdfData.statistics?.duration;
    const start = parseTimestamp(ts);
    if (start && typeof duration === 'number' && duration > 0) {
      endTime = formatTimestamp(new Date(start.getTime() + duration * 1000));
    }
    testResult[`${ATTR}end-time`] = endTime;
  }

  // @test-system names the scanner via a CPE URI so the importer recovers
  // tool.version from it. Emitted only when the HDF carries a tool identity.
  const testSystem = toolTestSystem(hdfData.tool);
  if (testSystem) {
    testResult[`${ATTR}test-system`] = testSystem;
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
    const stigId = tagString(req.tags, 'stig_id');

    // When an override set requirement.effectiveStatus, the emitted result
    // reflects the governing (post-override) status; otherwise each result's
    // own raw status carries through.
    const effective = req.effectiveStatus
      ? hdfStatusToXccdf(req.effectiveStatus)
      : undefined;

    for (const result of req.results) {
      const status = effective ?? hdfStatusToXccdf(result.status);
      if (status === 'pass') {
        passed++;
        scorable++;
      } else if (status === 'fail') {
        scorable++;
      }
      const rr: Record<string, unknown> = {
        [`${ATTR}idref`]: ruleIdRef,
      };

      const startTime =
        typeof result.startTime === 'string'
          ? result.startTime
          : (result.startTime as Date).toISOString();
      rr[`${ATTR}time`] = startTime;
      if (stigId) {
        rr[`${ATTR}version`] = stigId;
      }
      rr.result = wrap(status);

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
