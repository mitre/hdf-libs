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
import { buildCvss, cvssVersionFromString } from '../../../shared/typescript/cvss.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Cvss,
  Description,
  RequirementResult,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createResult,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
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

/** Get an attribute from a parsed XML node, entity-decoded. */
function attr(node: Record<string, unknown>, name: string): string {
  const raw = node[`${A}${name}`] as string | undefined;
  return raw === undefined ? '' : decodeXmlEntities(raw);
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

// Veracode escapes nearly every punctuation character in its attributes
// (&#x28; &#xd; &#x2f; …), and the shared XML parser runs with processEntities
// off as XXE defense-in-depth, so the references arrive undecoded. Go's
// encoding/xml decodes them for free. Only predefined and numeric character
// references are decoded; document-defined entities stay untouched.
function decodeXmlEntities(s: string): string {
  return s.replace(
    /&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));/g,
    (match, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
      if (dec !== undefined) return String.fromCodePoint(Number.parseInt(dec, 10));
      if (hex !== undefined) return String.fromCodePoint(Number.parseInt(hex, 16));
      return name !== undefined ? NAMED_ENTITIES[name] ?? match : match;
    },
  );
}

/** Parse Veracode timestamp format ("2021-12-29 22:16:36 UTC") to Date. */
function parseVeracodeTimestamp(ts: string): Date | undefined {
  if (!ts) return undefined;
  const normalized = ts.replace(' UTC', 'Z').replace(' ', 'T');
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

/** Format CWE descriptions for the cweDescription tag. */
function formatCWEDesc(cwes: Record<string, unknown>[]): string {
  return cwes.map(c => {
    const desc = c.description as Record<string, unknown> | undefined;
    const text = desc?.text as Record<string, unknown> | undefined;
    const descText = text ? attr(text, 'text') : '';
    return `CWE-${attr(c, 'cweid')}: ${attr(c, 'cwename')} Description: ${descText}; `;
  }).join('\n');
}

/**
 * Collect the distinct remediation_status values across a category's flaws, in
 * order of first appearance. Returns '' when no flaw carries the field (the
 * NOT-IN-SOURCE case).
 */
function formatRemediationStatus(cwes: Record<string, unknown>[]): string {
  const statuses: string[] = [];
  const seen = new Set<string>();
  for (const c of cwes) {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    for (const flaw of flaws) {
      const status = attr(flaw, 'remediation_status');
      if (status && !seen.has(status)) {
        seen.add(status);
        statuses.push(status);
      }
    }
  }
  return statuses.join('\n');
}

/**
 * Return the line number of the first flaw carrying a parseable numeric line
 * across a category's CWEs — the locus paired with the first source file in the
 * joined ref. Returns undefined when no flaw carries a numeric line (SCA/absent
 * case), so sourceLocation.line is omitted.
 */
function firstFlawLine(cwes: Record<string, unknown>[]): number | undefined {
  for (const c of cwes) {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    for (const flaw of flaws) {
      const lineStr = attr(flaw, 'line');
      if (!lineStr) continue;
      const n = Number(lineStr);
      if (Number.isFinite(n)) return n;
    }
  }
  return undefined;
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

/**
 * Synthesize a static flaw's source-context locus from its function prototype
 * and source-file position. Returns '' when the flaw carries neither a prototype
 * nor a source location (the NOT-IN-SOURCE case).
 */
function synthesizeFlawCode(flaw: Record<string, unknown>): string {
  let locus = attr(flaw, 'sourcefilepath') + attr(flaw, 'sourcefile');
  const line = attr(flaw, 'line');
  if (locus && line) locus += `:${line}`;
  const proto = attr(flaw, 'functionprototype');
  if (proto && locus) return `${proto} at ${locus}`;
  if (proto) return proto;
  return locus;
}

/**
 * Serialize a CVE and its affected components as indented JSON. Field order is
 * load-bearing: it must match the Go twin's struct declaration order so the two
 * `code` strings are byte-identical.
 */
function buildSCACode(vuln: Record<string, unknown>, components: Record<string, unknown>[]): string {
  const entry = {
    cve_id: attr(vuln, 'cve_id'),
    cvss_score: attr(vuln, 'cvss_score'),
    severity: attr(vuln, 'severity'),
    cwe_id: attr(vuln, 'cwe_id'),
    first_found_date: attr(vuln, 'first_found_date'),
    cve_summary: attr(vuln, 'cve_summary'),
    severity_desc: attr(vuln, 'severity_desc'),
    components: components.map(comp => {
      const filePathsElem = comp.file_paths as Record<string, unknown> | undefined;
      const fps = filePathsElem
        ? ensureArray(filePathsElem.file_path as Record<string, unknown> | Record<string, unknown>[])
        : [];
      return {
        component_id: attr(comp, 'component_id'),
        file_name: attr(comp, 'file_name'),
        sha1: attr(comp, 'sha1'),
        version: attr(comp, 'version'),
        library: attr(comp, 'library'),
        library_id: attr(comp, 'library_id'),
        vendor: attr(comp, 'vendor'),
        description: attr(comp, 'description'),
        max_cvss_score: attr(comp, 'max_cvss_score'),
        added_date: attr(comp, 'added_date'),
        file_paths: fps.map(fp => attr(fp, 'value')),
      };
    }),
  };
  return JSON.stringify(entry, null, 2);
}

// ---- Requirement builders ----

// The standards cross-reference attributes Veracode records on each <cwe>. Each
// maps to a discrete tag of the same name. Order is deterministic and shared
// with the Go twin (cweStandardTags).
const CWE_STANDARD_ATTRS = [
  'owasp',
  'sans',
  'certc',
  'certcpp',
  'certjava',
  'owaspmobile',
];

/**
 * Collect the distinct non-empty values of one standards cross-reference
 * attribute across a category's CWEs, in first-appearance order. Returns [] when
 * no CWE carries the attribute (the NOT-IN-SOURCE case).
 */
function collectCWEStandard(cwes: Record<string, unknown>[], key: string): string[] {
  const values: string[] = [];
  const seen = new Set<string>();
  for (const c of cwes) {
    const v = attr(c, key);
    if (v && !seen.has(v)) {
      seen.add(v);
      values.push(v);
    }
  }
  return values;
}

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
  const cweDescStr = formatCWEDesc(cwes);
  if (cweDescStr) extras.cweDescription = cweDescStr;

  // Veracode cross-references each CWE to external standards catalogs (OWASP,
  // SANS/CWE Top 25, CERT C/C++/Java, OWASP Mobile). Each becomes a discrete tag
  // carrying the category's distinct referenced entries; absent catalogs are
  // omitted (NOT-IN-SOURCE).
  for (const key of CWE_STANDARD_ATTRS) {
    const values = collectCWEStandard(cwes, key);
    if (values.length > 0) extras[key] = values;
  }

  const tags = buildNistCciTags(nist, cciTags, extras);

  // First-class CWE identifiers ("CWE-NN"). The category cweid attributes are
  // bare numbers; prefix them to match the schema's CWE-N convention.
  const cweList = cweIDs.map(id => `CWE-${id}`);

  // Build descriptions
  const descriptions: Description[] = [
    { label: 'default', data: formatDesc(cat.desc as Record<string, unknown> | undefined) },
  ];
  const recText = formatRecommendations(cat.recommendations as Record<string, unknown> | undefined);
  if (recText) {
    descriptions.push({ label: 'fix', data: recText });
  }

  // Carry each flaw's remediation_status (e.g. "New", "Fixed", "Cannot Fix").
  // Descriptions are requirement-level while the field is per-flaw, so the
  // distinct values across the category's flaws are collected into one entry.
  const remStatus = formatRemediationStatus(cwes);
  if (remStatus) {
    descriptions.push({ label: 'remediation_status', data: remStatus });
  }

  // Collect all flaws from all CWEs in this category
  const startTime = parseVeracodeTimestamp(firstBuildDate) ?? new Date();
  const results = cwes.flatMap(c => {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    return flaws.map((flaw): RequirementResult =>
      createResult(ResultStatus.Failed, undefined, { codeDesc: formatFlawCodeDesc(flaw), startTime }));
  });

  const sourceRef = cwes.flatMap(c => {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    return flaws.map(flaw => attr(flaw, 'sourcefile')).filter(Boolean);
  }).join('\n');
  const sourceLine = firstFlawLine(cwes);

  // Static findings carry no raw snippet; the code-locus (function prototype at
  // source-file:line) is the richest source context Veracode provides. Leave
  // code unset when no flaw carries either (NOT-IN-SOURCE).
  const codeLines = cwes.flatMap(c => {
    const staticflaws = c.staticflaws as Record<string, unknown> | undefined;
    const flaws = ensureArray(staticflaws?.flaw as Record<string, unknown> | Record<string, unknown>[]);
    return flaws.map(flaw => synthesizeFlawCode(flaw)).filter(Boolean);
  });

  const req = createRequirement(
    attr(cat, 'categoryid'),
    attr(cat, 'categoryname'),
    descriptions,
    impact,
    results,
    {
      tags,
      sourceLocation: sourceRef
        ? sourceLine !== undefined
          ? { line: sourceLine, ref: sourceRef }
          : { ref: sourceRef }
        : undefined,
    },
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  if (cweList.length > 0) {
    req.cwe = cweList;
  }
  if (codeLines.length > 0) {
    req.code = codeLines.join('\n');
  }

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

/**
 * Assemble the structured CVSS entry for an SCA CVE. Veracode reports a bare
 * numeric base score (no vector, no version), so the version defaults to 3.1 via
 * the shared helper. When the vulnerability itself carries no cvss_score, the
 * first affected component's max_cvss_score is used as a fallback. A missing or
 * non-numeric score yields no entry.
 */
function buildVeracodeCvss(vuln: Record<string, unknown>, components: Record<string, unknown>[]): Cvss[] {
  let scoreStr = attr(vuln, 'cvss_score');
  if (!scoreStr) {
    for (const comp of components) {
      const max = attr(comp, 'max_cvss_score');
      if (max) {
        scoreStr = max;
        break;
      }
    }
  }
  if (!scoreStr) return [];
  const score = Number(scoreStr);
  if (!Number.isFinite(score)) return [];
  return [buildCvss({ version: cvssVersionFromString(undefined), baseScore: score })];
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
  const tags = buildNistCciTags(nist, cciTags, {});

  // One result per affected component
  const startTime = parseVeracodeTimestamp(firstBuildDate) ?? new Date();

  const results = components.map((comp): RequirementResult =>
    createResult(ResultStatus.Failed, undefined, { codeDesc: formatSCACodeDesc(comp), startTime }));

  const cveSummary = attr(vuln, 'cve_summary');
  const cveId = attr(vuln, 'cve_id');
  const descriptions: Description[] = [
    { label: 'default', data: cveSummary || '' },
  ];

  const sourceRef = components.flatMap(comp => {
    const filePaths = comp.file_paths as Record<string, unknown> | undefined;
    if (!filePaths) return [];
    const fps = ensureArray(filePaths.file_path as Record<string, unknown> | Record<string, unknown>[]);
    return fps.map(fp => attr(fp, 'value')).filter(Boolean);
  }).join('\n');

  const req = createRequirement(
    cveId,
    cveId,
    descriptions,
    impact,
    results,
    { tags, sourceLocation: sourceRef ? { ref: sourceRef } : undefined },
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  const cvss = buildVeracodeCvss(vuln, components);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }

  // CVE is already the requirement.id, so no interim tags.cve is emitted; the
  // CWE moves to the first-class cwe[] (already in "CWE-NN" form on SCA vulns).
  if (cweID) {
    req.cwe = [cweID];
  }

  // SCA vulnerabilities have no source snippet or function prototype; the richest
  // faithful representation is the vulnerability/component entry serialized as
  // indented JSON (the ionchannel/nessus pattern).
  req.code = buildSCACode(vuln, components);

  return req;
}

// ---- Main converter ----

/**
 * Convert Veracode DetailedReport XML to HDF JSON string.
 *
 * @param input - Veracode DetailedReport XML string
 * @returns HDF JSON string
 */
export async function convertVeracodeToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('veracode: empty input');
  }
  validateInputSize(input, 'veracode');

  // Parse XML with @_ attribute prefix to disambiguate attributes from child elements.
  // This is critical for the <component> element where both `vulnerabilities` attribute
  // (count) and child `<vulnerabilities>` element (list) exist.
  // trimValues stays off: Veracode ships attribute text with significant leading
  // and trailing whitespace, and Go's decoder preserves it.
  const parsed = parseXml(input, {
    attributeNamePrefix: '@_',
    trimValues: false,
  }) as Record<string, unknown>;

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
    converterVersion,
    toolName: 'Veracode',
    baselines: [baseline],
    components: [{ name: targetName, type: TargetType.Application }],
    timestamp,
  });
}
