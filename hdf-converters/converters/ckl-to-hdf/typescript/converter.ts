import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import {
  deriveControlTypeFromTags,
  inputChecksum,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Component,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  Severity,
  createMinimalBaseline,
  createRequirement,
  createResult,
  severityToImpact,
} from '@mitre/hdf-schema';
import { getCCINistMappings } from '@mitre/hdf-mappings';

const CONVERTER_VERSION = '1.0.0';

// Elements that must always be parsed as arrays even when singular.
const ARRAY_TAGS = ['iSTIG', 'VULN', 'STIG_DATA', 'SI_DATA'];

// ---------------------------------------------------------------------------
// Parsed CKL types (post-fast-xml-parser)
// ---------------------------------------------------------------------------

interface CklParsed {
  CHECKLIST?: {
    ASSET?: AssetElement;
    STIGS?: { iSTIG?: IStigElement[] };
  };
}

interface AssetElement {
  HOST_NAME?: string;
  HOST_IP?: string;
  HOST_MAC?: string;
  HOST_FQDN?: string;
}

interface IStigElement {
  STIG_INFO?: { SI_DATA?: SiDataElement[] };
  VULN?: VulnElement[];
}

interface SiDataElement {
  SID_NAME?: string;
  SID_DATA?: string;
}

interface VulnElement {
  STIG_DATA?: StigDataElement[];
  STATUS?: string;
  FINDING_DETAILS?: string;
  COMMENTS?: string;
}

interface StigDataElement {
  VULN_ATTRIBUTE?: string;
  ATTRIBUTE_DATA?: string;
}

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

const STATUS_MAP: Record<string, ResultStatus> = {
  notafinding: ResultStatus.Passed,
  open: ResultStatus.Failed,
  notapplicable: ResultStatus.NotApplicable,
  notreviewed: ResultStatus.NotReviewed,
};

/** Map a CKL STATUS string to an HDF ResultStatus (unknown/empty -> notReviewed). */
function mapStatus(status: string | undefined): ResultStatus {
  const normalized = (status ?? '')
    .toLowerCase()
    .trim()
    .split('_')
    .join('')
    .split(' ')
    .join('');
  return STATUS_MAP[normalized] ?? ResultStatus.NotReviewed;
}

// ---------------------------------------------------------------------------
// STIG_DATA / SI_DATA accessors
// ---------------------------------------------------------------------------

function stigDataValue(vuln: VulnElement, attribute: string): string {
  const match = (vuln.STIG_DATA ?? []).find(
    (sd) => sd.VULN_ATTRIBUTE === attribute
  );
  return match?.ATTRIBUTE_DATA ?? '';
}

function stigDataValues(vuln: VulnElement, attribute: string): string[] {
  return (vuln.STIG_DATA ?? [])
    .filter((sd) => sd.VULN_ATTRIBUTE === attribute && sd.ATTRIBUTE_DATA)
    .map((sd) => sd.ATTRIBUTE_DATA as string);
}

function siDataValue(
  siData: SiDataElement[] | undefined,
  name: string
): string {
  const match = (siData ?? []).find((si) => si.SID_NAME === name);
  return match?.SID_DATA ?? '';
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

/**
 * Convert a DISA STIG Viewer .ckl document to HDF Results JSON.
 *
 * v3.2 classification fields: controlType is derived per-VULN from the CCI ->
 * NIST mapping. verificationMethod is deliberately NOT set — CKL does not
 * guarantee whether a finding was assessed manually, automated-then-exported,
 * or mixed, so a constant would assert a classification the source cannot
 * substantiate. applicability is omitted likewise. See the Go converter's
 * package doc and the build-converter skill Step 4d.
 */
export async function convertCklToHdf(input: string): Promise<string> {
  validateInputSize(input, 'ckl-to-hdf');

  const parsed = parseXmlWithArrays(input, ARRAY_TAGS) as CklParsed;
  const checklist = parsed.CHECKLIST;
  const istigs = checklist?.STIGS?.iSTIG;
  if (!checklist || !istigs || istigs.length === 0) {
    throw new Error('Input is not a CKL document (no <iSTIG> blocks found)');
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const baselines = istigs.map((istig) =>
    buildBaseline(istig, resultsChecksum)
  );

  const hdf: HdfResults = {
    baselines,
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
    tool: { name: 'DISA STIG Viewer', format: 'CKL' },
    timestamp: new Date(),
  };

  const component = buildComponent(checklist.ASSET);
  if (component) {
    hdf.components = [component];
  }

  return JSON.stringify(hdf, null, 2);
}

function buildBaseline(
  istig: IStigElement,
  resultsChecksum: Checksum
): EvaluatedBaseline {
  const title = siDataValue(istig.STIG_INFO?.SI_DATA, 'title');
  const version = siDataValue(istig.STIG_INFO?.SI_DATA, 'version');

  const requirements = (istig.VULN ?? []).map(vulnToRequirement);

  const baseline = createMinimalBaseline('STIG Checklist Scan', requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  if (title) {
    baseline.title = title;
  }
  if (version) {
    baseline.version = version;
  }
  return baseline;
}

function vulnToRequirement(vuln: VulnElement): EvaluatedRequirement {
  const id = stigDataValue(vuln, 'Vuln_Num');
  const title = stigDataValue(vuln, 'Rule_Title') || id;
  const severity = stigDataValue(vuln, 'Severity').toLowerCase();
  const impact = severity ? severityToImpact(severity) : 0.5;

  const descriptions = buildDescriptions(vuln);
  const result = buildResult(vuln);

  const tags: Record<string, unknown> = {};
  let nistTags: string[] = [];
  const cciIds = stigDataValues(vuln, 'CCI_REF');
  if (cciIds.length > 0) {
    tags['cci'] = cciIds;
    // Sorted to match the Go converter's cci.CCIToNIST (deduped + sorted).
    nistTags = [
      ...new Set(cciIds.flatMap((cci) => getCCINistMappings(cci) ?? [])),
    ].sort();
    tags['nist'] = nistTags;
  } else {
    tags['nist'] = [];
  }

  const req = createRequirement(
    id,
    title,
    descriptions,
    impact,
    [result],
    { tags }
  ) as EvaluatedRequirement;

  if (severity) {
    req.severity = severity as Severity;
  }

  // controlType from real per-VULN NIST signal; verificationMethod and
  // applicability deliberately omitted.
  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}

function buildDescriptions(vuln: VulnElement): Description[] {
  const descriptions: Description[] = [
    { label: 'default', data: stigDataValue(vuln, 'Vuln_Discuss') },
  ];
  const check = stigDataValue(vuln, 'Check_Content');
  if (check) {
    descriptions.push({ label: 'check', data: check });
  }
  const fix = stigDataValue(vuln, 'Fix_Text');
  if (fix) {
    descriptions.push({ label: 'fix', data: fix });
  }
  return descriptions;
}

function buildResult(vuln: VulnElement): RequirementResult {
  const status = mapStatus(vuln.STATUS);
  const parts: string[] = [];
  const findingDetails = (vuln.FINDING_DETAILS ?? '').trim();
  const comments = (vuln.COMMENTS ?? '').trim();
  if (findingDetails) {
    parts.push(findingDetails);
  }
  if (comments) {
    parts.push(comments);
  }
  const message = parts.length > 0 ? parts.join('\n\n') : '';

  return createResult(status, message, {
    codeDesc: `STIG rule ${stigDataValue(vuln, 'Rule_Ver')}`,
  }) as RequirementResult;
}

function buildComponent(asset: AssetElement | undefined): Component | undefined {
  if (!asset) {
    return undefined;
  }
  const { HOST_NAME, HOST_IP, HOST_MAC, HOST_FQDN } = asset;
  if (!HOST_NAME && !HOST_IP && !HOST_FQDN) {
    return undefined;
  }
  const component: Component = {
    name: HOST_NAME ?? '',
    type: Copyright.Host,
  };
  if (HOST_IP) {
    component.ipAddress = HOST_IP;
  }
  if (HOST_FQDN) {
    component.fqdn = HOST_FQDN;
  }
  if (HOST_MAC) {
    component.macAddress = HOST_MAC;
  }
  return component;
}
