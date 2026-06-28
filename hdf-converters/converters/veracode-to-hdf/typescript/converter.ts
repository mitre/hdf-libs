/**
 * Veracode DetailedReport XML to HDF converter.
 *
 * Converts Veracode static analysis and SCA findings into HDF format.
 * Produces two types of controls:
 *   - CWE-based: From severity categories (static analysis findings)
 *   - CVE-based: From SCA vulnerable components
 *
 * Uses attributeNamePrefix '@_' to disambiguate XML attributes from child
 * elements (critical for the `vulnerabilities` attr/element collision on
 * `<component>`).
 */

import { parseXml, parseTimestamp } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, mapCWEToNIST, buildNistCciTags, ensureArray, DEFAULT_REMEDIATION_NIST_TAGS, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';

/** Attribute prefix used by fast-xml-parser — all XML attributes are accessed via `@_name`. */
const A = '@_';


/** Veracode severity level (0-5) to HDF impact mapping. */
const IMPACT_MAPPING: Map<string, number> = new Map([
  ['5', 0.9],
  ['4', 0.7],
  ['3', 0.5],
  ['2', 0.3],
  ['1', 0.1],
  ['0', 0.0],
]);

function veracodeSeverityToImpact(severity: string): number {
  return IMPACT_MAPPING.get(severity) ?? 0.1;
}

// ---- Utility functions ----

/** Get an attribute from a parsed XML node. */
function attr(node: Record<string, unknown>, name: string): string {
  return (node[`${A}${name}`] as string) ?? '';
}

/** Decode common XML/HTML character references (&#xHH; and &#NNN;). */
function decodeXmlEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex as string, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec as string, 10)));
}

/** Parse Veracode timestamp format ("2021-12-29 22:16:36 UTC") to Date. */
function parseVeracodeTimestamp(ts: string): Date | undefined {
  if (!ts) return undefined;
  // Decode XML entities in timestamps (e.g., &#x3a; -> :)
  const decoded = decodeXmlEntities(ts);
  const normalized = decoded.replace(' UTC', 'Z').replace(' ', 'T');
  return parseTimestamp(normalized) ?? undefined;
}

/** Format description paragraphs into text. */
function formatDesc(desc: Record<string, unknown> | undefined): string {
  if (!desc) return '';
  const paras = ensureArray(desc.para as Record<string, unknown> | Record<string, unknown>[]);
  return paras.map(p => attr(p, 'text')).filter(Boolean).join('\n');
}

/** Format recommendations into text. */
function formatRecommendations(rec: Record<string, unknown> | undefined): string {
  if (!rec) return '';
  const paras = ensureArray(rec.para as Record<string, unknown> | Record<string, unknown>[]);
  const parts: string[] = [];
  for (const p of paras) {
    const text = attr(p, 'text');
    if (text) parts.push(text);
    const bullets = ensureArray(p.bulletitem as Record<string, unknown> | Record<string, unknown>[]);
    for (const b of bullets) {
      const btext = attr(b, 'text');
      if (btext) parts.push(btext);
    }
  }
  return parts.join('\n');
}

/** Format CWE data for the cweid tag. */
function formatCWEData(cwes: Record<string, unknown>[]): string {
  return cwes.map(c => {
    let entry = `CWE-${attr(c, 'cweid')}: ${attr(c, 'cwename')}`;
    const categories: [string, string][] = [
      ['pcrirelated', attr(c, 'pcirelated')],
      ['owasp', attr(c, 'owasp')],
      ['sans', attr(c, 'sans')],
      ['certc', attr(c, 'certc')],
      ['certcpp', attr(c, 'certcpp')],
      ['certjava', attr(c, 'certjava')],
      ['owaspmobile', attr(c, 'owaspmobile')],
    ];
    for (const [name, val] of categories) {
      if (val) entry += `${name}: ${val}\n`;
    }
    return entry;
  }).join('\n');
}

/** Format CWE descriptions for the cweDescription tag. */
function formatCWEDesc(cwes: Record<string, unknown>[]): string {
  return cwes.map(c => {
    const desc = c.description as Record<string, unknown> | undefined;
    const text = desc?.text as Record<string, unknown> | undefined;
    const descText = text ? attr(text, 'text') : '';
    return `CWE-${attr(c, 'cweid')}: ${attr(c, 'cwename')} Description: ${descText}; `;
  }).join('\n');
}

/** Format a static flaw as a code description. */
function formatFlawCodeDesc(flaw: Record<string, unknown>): string {
  const sourcefilepath = attr(flaw, 'sourcefilepath');
  if (!sourcefilepath) {
    return `Issue ID: ${attr(flaw, 'issueid')}`;
  }

  const parts: string[] = [`Sourcefile Path: ${sourcefilepath}`];
  const fields: [string, string][] = [
    ['Line Number', attr(flaw, 'line')],
    ['Affect Policy Compliance', attr(flaw, 'affects_policy_compliance')],
    ['Remediation Effort', attr(flaw, 'remediationeffort')],
    ['Exploit level', attr(flaw, 'exploitLevel')],
    ['Issue ID', attr(flaw, 'issueid')],
    ['Module', attr(flaw, 'module')],
    ['Type', attr(flaw, 'type')],
    ['CWE ID', attr(flaw, 'cweid')],
    ['Date First Occurence', attr(flaw, 'date_first_occurrence')],
    ['CIA Impact', attr(flaw, 'cia_impact')],
    ['Description', attr(flaw, 'description')],
    ['Source File', attr(flaw, 'sourcefile')],
    ['Scope', attr(flaw, 'scope')],
    ['PCI Related', attr(flaw, 'pcirelated')],
    ['Function Prototype', attr(flaw, 'functionprototype')],
    ['Function Relative Location', attr(flaw, 'functionrelativelocation')],
  ];

  for (const [title, value] of fields) {
    if (value) parts.push(`${title}: ${value}`);
  }

  return parts.join('\n');
}

/** Format an SCA component as a code description. */
function formatSCACodeDesc(comp: Record<string, unknown>): string {
  const parts: string[] = [`component_id: ${attr(comp, 'component_id')}`];
  const fields: [string, string][] = [
    ['sha1', attr(comp, 'sha1')],
    ['file_name', attr(comp, 'file_name')],
    ['max_cvss_score', attr(comp, 'max_cvss_score')],
    ['version', attr(comp, 'version')],
    ['library', attr(comp, 'library')],
    ['library_id', attr(comp, 'library_id')],
    ['vendor', attr(comp, 'vendor')],
    ['description', attr(comp, 'description')],
    ['added_date', attr(comp, 'added_date')],
    ['component_affects_policy_compliance', attr(comp, 'component_affects_policy_compliance')],
  ];

  for (const [title, value] of fields) {
    if (value) parts.push(`${title}: ${value}`);
  }

  // File paths
  const filePaths = comp.file_paths as Record<string, unknown> | undefined;
  if (filePaths) {
    const fps = ensureArray(filePaths.file_path as Record<string, unknown> | Record<string, unknown>[]);
    for (const fp of fps) {
      const val = attr(fp, 'value');
      if (val) parts.push(`file_path: ${val}`);
    }
  }

  return parts.join('\n');
}

// ---- Requirement builders ----

/** Build CWE-based requirements from severity categories. */
function buildCWERequirements(severities: Record<string, unknown>[], firstBuildDate: string): EvaluatedRequirement[] {
  const requirements: EvaluatedRequirement[] = [];

  for (const sev of severities) {
    const impact = veracodeSeverityToImpact(attr(sev, 'level'));
    const categories = ensureArray(sev.category as Record<string, unknown> | Record<string, unknown>[]);

    for (const cat of categories) {
      requirements.push(buildCWERequirement(cat, impact, firstBuildDate));
    }
  }

  return requirements;
}

/** Build a single CWE-based requirement from a category. */
function buildCWERequirement(cat: Record<string, unknown>, impact: number, firstBuildDate: string): EvaluatedRequirement {
  const cwes = ensureArray(cat.cwe as Record<string, unknown> | Record<string, unknown>[]);

  // Collect CWE IDs for NIST mapping
  const cweIDs = cwes.map(c => attr(c, 'cweid')).filter(Boolean);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_REMEDIATION_NIST_TAGS);
  const cciTags = nistToCci(nist);

  // Build tags
  const extras: Record<string, unknown> = {};
  const cweData = formatCWEData(cwes);
  if (cweData) extras.cweid = cweData;
  const cweDescStr = formatCWEDesc(cwes);
  if (cweDescStr) extras.cweDescription = cweDescStr;

  const tags = buildNistCciTags(nist, cciTags, extras);

  // Build descriptions
  const descriptions: Description[] = [
    { label: 'default', data: formatDesc(cat.desc as Record<string, unknown> | undefined) },
  ];
  const recText = formatRecommendations(cat.recommendations as Record<string, unknown> | undefined);
  if (recText) {
    descriptions.push({ label: 'fix', data: recText });
  }

  // Collect all flaws from all CWEs in this category
  const startTime = parseVeracodeTimestamp(firstBuildDate) ?? new Date();
  const results = cwes.flatMap(c => {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    return flaws.map(flaw => createResult(ResultStatus.Failed, undefined, {
      codeDesc: formatFlawCodeDesc(flaw),
      startTime,
    }));
  });

  const req = createRequirement(
    attr(cat, 'categoryid'),
    attr(cat, 'categoryname'),
    descriptions,
    impact,
    results,
    { tags },
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

/** Build CVE-based requirements from SCA components. */
function buildCVERequirements(
  sca: Record<string, unknown> | undefined,
  firstBuildDate: string,
): EvaluatedRequirement[] {
  if (!sca) return [];
  const vulnComps = sca.vulnerable_components as Record<string, unknown> | undefined;
  if (!vulnComps?.component) return [];

  const components = ensureArray(vulnComps.component as Record<string, unknown> | Record<string, unknown>[]);

  // Group vulnerabilities by CVE ID across all components
  interface CVEEntry {
    vuln: Record<string, unknown>;
    components: Record<string, unknown>[];
  }

  const cveOrder: string[] = [];
  const cveMap = new Map<string, CVEEntry>();

  for (const comp of components) {
    const vulnCountAttr = attr(comp, 'vulnerabilities');
    if (vulnCountAttr === '0') continue;

    // With @_ prefix, child element <vulnerabilities> is at key 'vulnerabilities',
    // and the attribute is at '@_vulnerabilities'
    const vulnsElem = comp.vulnerabilities as Record<string, unknown> | undefined;
    if (!vulnsElem?.vulnerability) continue;
    const vulns = ensureArray(vulnsElem.vulnerability as Record<string, unknown> | Record<string, unknown>[]);

    for (const vuln of vulns) {
      const cveID = attr(vuln, 'cve_id');
      if (!cveID) continue;

      const existing = cveMap.get(cveID);
      if (existing) {
        existing.components.push(comp);
      } else {
        cveOrder.push(cveID);
        cveMap.set(cveID, { vuln, components: [comp] });
      }
    }
  }

  return cveOrder.map(cveID => {
    const entry = cveMap.get(cveID)!;
    return buildCVERequirement(entry.vuln, entry.components, firstBuildDate);
  });
}

/** Build a single CVE-based requirement. */
function buildCVERequirement(
  vuln: Record<string, unknown>,
  components: Record<string, unknown>[],
  firstBuildDate: string,
): EvaluatedRequirement {
  const impact = veracodeSeverityToImpact(attr(vuln, 'severity'));

  // Map CWE to NIST
  const cweID = attr(vuln, 'cwe_id');
  let nist: string[];
  if (cweID) {
    nist = mapCWEToNIST([cweID.replace(/^CWE-/, '')], DEFAULT_REMEDIATION_NIST_TAGS);
  } else {
    nist = DEFAULT_REMEDIATION_NIST_TAGS;
  }
  const cciTags = nistToCci(nist);
  const extras: Record<string, unknown> = {};
  if (cweID) extras.cwe = cweID;
  const tags = buildNistCciTags(nist, cciTags, extras);

  // One result per affected component
  const startTime = parseVeracodeTimestamp(firstBuildDate) ?? new Date();

  const results = components.map(comp => createResult(ResultStatus.Failed, undefined, {
    codeDesc: formatSCACodeDesc(comp),
    startTime,
  }));

  const cveSummary = attr(vuln, 'cve_summary');
  const cveId = attr(vuln, 'cve_id');
  const descriptions: Description[] = [
    { label: 'default', data: cveSummary || '' },
  ];

  const req = createRequirement(
    cveId,
    cveId,
    descriptions,
    impact,
    results,
    { tags },
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

// ---- Main converter ----

/**
 * Convert Veracode DetailedReport XML to HDF JSON string.
 *
 * @param input - Veracode DetailedReport XML string
 * @returns HDF JSON string
 */
export async function convertVeracodeToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('veracode: empty input');
  }
  validateInputSize(input, 'veracode');

  // Parse XML with @_ attribute prefix to disambiguate attributes from child elements.
  // This is critical for the <component> element where both `vulnerabilities` attribute
  // (count) and child `<vulnerabilities>` element (list) exist.
  const parsed = parseXml(input, { attributeNamePrefix: '@_' }) as Record<string, unknown>;

  // Check for summary report
  if ('summaryreport' in parsed) {
    throw new Error('veracode: summary reports are not supported; use a detailed report');
  }

  const report = parsed.detailedreport as Record<string, unknown> | undefined;
  if (!report) {
    throw new Error('veracode: invalid XML - no <detailedreport> root element');
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const firstBuildDate = attr(report, 'first_build_submitted_date');

  // Ensure severities is an array
  const severities = ensureArray(report.severity as Record<string, unknown> | Record<string, unknown>[]);

  // Build CWE-based requirements
  const cweRequirements = buildCWERequirements(severities, firstBuildDate);

  // Build CVE-based requirements from SCA
  const cveRequirements = buildCVERequirements(
    report.software_composition_analysis as Record<string, unknown> | undefined,
    firstBuildDate,
  );

  // Merge
  const allRequirements = [...cweRequirements, ...cveRequirements];

  const targetName = attr(report, 'app_name') || 'Veracode Application';

  if (allRequirements.length === 0) {
    allRequirements.push(buildNoFindingsRequirement(
      'veracode-no-findings',
      `Veracode scanned ${targetName} and reported zero findings.`,
      new Date(),
    ));
  }

  // Get module name for title
  let title: string | undefined;
  const staticAnalysis = report['static-analysis'] as Record<string, unknown> | undefined;
  if (staticAnalysis) {
    const modules = staticAnalysis.modules as Record<string, unknown> | undefined;
    if (modules?.module) {
      const moduleList = ensureArray(modules.module as Record<string, unknown> | Record<string, unknown>[]);
      if (moduleList.length > 0) {
        title = attr(moduleList[0]!, 'name');
      }
    }
  }

  const baseline = createMinimalBaseline('Veracode Scan', allRequirements, {
    resultsChecksum,
    title,
    version: attr(report, 'policy_version'),
    summary: attr(report, 'policy_name'),
  }) as EvaluatedBaseline;

  const timestamp = parseVeracodeTimestamp(firstBuildDate);

  return buildHdfResults({
    generatorName: 'veracode-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Veracode',
    toolFormat: 'XML',
    baselines: [baseline],
    components: [{ name: targetName, type: TargetType.Application }],
    timestamp,
  });
}
