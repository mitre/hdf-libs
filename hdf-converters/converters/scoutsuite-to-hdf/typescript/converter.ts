import { parseJSON } from '@mitre/hdf-utilities';
import {
  getScoutsuiteNistControl,
  nistToCci,
} from '@mitre/hdf-mappings';
import { inputChecksum, buildNistCciTags, limitArrayWithWarning, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  DataSource,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * ScoutSuite JSON output structures
 */
interface ScoutSuiteReport {
  account_id: string;
  environment?: string;
  last_run: LastRun;
  partition?: string;
  provider_code?: string;
  provider_name: string;
  services: Record<string, ServiceData>;
}

interface LastRun {
  ruleset_about?: string;
  ruleset_name: string;
  time: string;
  version: string;
}

interface ServiceData {
  findings?: Record<string, ScoutSuiteFinding>;
  [key: string]: unknown;
}

interface ScoutSuiteFinding {
  checked_items: number;
  compliance?: ComplianceItem[] | null;
  description: string;
  flagged_items: number;
  id_suffix?: string;
  items: string[];
  level: string;
  path?: string;
  rationale: string;
  references?: string[] | null;
  remediation?: string | null;
  service?: string;
}

interface ComplianceItem {
  name: string;
  reference: string;
  version: string;
}

/**
 * Maps ScoutSuite level strings to HDF impact values.
 */
function getImpact(level: string): number {
  switch (level.toLowerCase()) {
    case 'danger':
      return 0.7;
    case 'warning':
      return 0.5;
    default:
      return 0.3;
  }
}

/**
 * Determines the HDF result status based on checked and flagged item counts.
 */
function getStatus(checkedItems: number, flaggedItems: number): ResultStatus {
  if (checkedItems === 0) {
    return ResultStatus.NotReviewed;
  }
  if (flaggedItems === 0) {
    return ResultStatus.Passed;
  }
  return ResultStatus.Failed;
}

/**
 * Builds the result message based on checked/flagged item counts.
 */
function getMessage(checkedItems: number, flaggedItems: number, items: string[]): string {
  if (checkedItems === 0) {
    return 'Skipped because no items were checked';
  }
  if (flaggedItems === 0) {
    return `0 flagged items out of ${checkedItems} checked items`;
  }
  let msg = `${flaggedItems} flagged items out of ${checkedItems} checked items`;
  if (items.length > 0) {
    msg += ':\n' + items.join('\n');
  }
  return msg;
}

/** Known ScoutSuite JS variable assignment prefixes. */
const SCOUTSUITE_JS_PREFIX = /^\s*(scoutsuite_results)\s*=\s*$/i;

/**
 * Strips the "scoutsuite_results = " JS variable prefix from input.
 * ScoutSuite outputs results as a JS file with this prefix on the first line.
 * Only strips prefixes matching known ScoutSuite patterns; unrecognized prefixes
 * are left intact so JSON parsing produces a descriptive error.
 */
function stripJSPrefix(input: string): string {
  const idx = input.indexOf('{');
  if (idx < 0) {
    return input;
  }
  if (idx === 0) {
    return input; // Already valid JSON
  }
  const prefix = input.substring(0, idx).trim();
  if (SCOUTSUITE_JS_PREFIX.test(prefix)) {
    return input.substring(idx);
  }
  // Unknown prefix — don't strip, let JSON parser report the error
  return input;
}

/**
 * Gets NIST controls for a ScoutSuite rule, splitting pipe-delimited values.
 */
function getNistControls(ruleID: string): string[] {
  const ctrl = getScoutsuiteNistControl(ruleID);
  if (!ctrl) {
    return ['SA-11', 'RA-5']; // fallback
  }
  return ctrl.split('|');
}

/**
 * Collapses all service findings into a flat list of (ruleID, finding) pairs.
 */
function collapseFindings(report: ScoutSuiteReport): Array<[string, ScoutSuiteFinding]> {
  const result: Array<[string, ScoutSuiteFinding]> = [];

  const serviceNames = Object.keys(report.services).sort();
  for (const serviceName of serviceNames) {
    const svcRaw = report.services[serviceName];
    if (!svcRaw) continue;

    // The service object may have properties beyond "findings" (filters, regions, etc.)
    // We only care about findings
    const svc = svcRaw as ServiceData;
    if (!svc.findings) continue;

    const ruleNames = Object.keys(svc.findings).sort();
    for (const ruleName of ruleNames) {
      const finding = svc.findings[ruleName];
      if (finding) {
        result.push([ruleName, finding]);
      }
    }
  }

  return result;
}

/**
 * Builds a single EvaluatedRequirement from a ScoutSuite finding.
 */
function buildRequirement(
  ruleID: string,
  finding: ScoutSuiteFinding,
  startTime: string,
): EvaluatedRequirement {
  const nist = getNistControls(ruleID);
  const cciTags = nistToCci(nist);
  const tags = buildNistCciTags(nist, cciTags);

  const descriptions: Description[] = [
    { label: 'default', data: finding.rationale },
  ];
  if (finding.remediation) {
    descriptions.push({ label: 'fix', data: finding.remediation });
  }

  const status = getStatus(finding.checked_items, finding.flagged_items);
  const message = getMessage(finding.checked_items, finding.flagged_items, finding.items);

  const resultObj = createResult(status, message, {
    codeDesc: finding.description,
    startTime: startTime ? new Date(startTime) : undefined,
  });

  return createRequirement(
    ruleID,
    finding.description,
    descriptions,
    getImpact(finding.level),
    [resultObj],
    { tags },
  );
}

/**
 * Converts ScoutSuite output to HDF format.
 * Input may be a JS file with "scoutsuite_results = " prefix or pure JSON.
 *
 * @param input - ScoutSuite JS/JSON string
 * @returns HDF JSON string
 */
export async function convertScoutsuiteToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('scoutsuite: empty input');
  }
  validateInputSize(input, 'scoutsuite');

  // Strip JS variable prefix if present
  const jsonStr = stripJSPrefix(input);

  const resultsChecksum: Checksum = await inputChecksum(jsonStr);

  const report = parseJSON<ScoutSuiteReport>(jsonStr);

  if (!report || typeof report !== 'object') {
    throw new Error('scoutsuite: invalid JSON');
  }

  // Collapse all service findings
  const findingPairs = collapseFindings(report);
  const limitedPairs = limitArrayWithWarning(findingPairs, 'finding');

  const requirements: EvaluatedRequirement[] = limitedPairs.map(
    ([ruleID, finding]) => buildRequirement(ruleID, finding, report.last_run.time),
  );

  const title = `Scout Suite Report using ${report.last_run.ruleset_name} ruleset on ${report.provider_name} with account ${report.account_id}`;

  const baseline = createMinimalBaseline(
    'ScoutSuite Scan',
    requirements,
    {
      resultsChecksum,
      title,
      summary: report.last_run.ruleset_about,
    },
  ) as EvaluatedBaseline;

  const targetName = `${report.last_run.ruleset_name} ruleset:${report.provider_name}:${report.account_id}`;

  const dataSource: DataSource = {
    name: 'ScoutSuite',
    format: 'JSON',
    version: report.last_run.version,
  };

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: {
      name: 'scoutsuite-to-hdf',
      version: '1.0.0',
    },
    dataSource,
    targets: [{ name: targetName, type: Copyright.CloudAccount }],
    timestamp: report.last_run.time ? new Date(report.last_run.time) : new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
