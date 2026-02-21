import { createHash } from 'crypto';
import { parseJSON } from '@mitre/hdf-utilities';
import {
  getCweNistControl,
  nistToCci,
} from '@mitre/hdf-mappings';
import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement, RequirementResult, Checksum, DataSource } from '@mitre/hdf-schema';
import { ResultStatus, HashAlgorithm, createMinimalBaseline, createRequirement, createDescription, createResult } from '@mitre/hdf-schema';

interface SarifFile {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool?: {
    driver?: {
      name?: string;
      version?: string;
      informationUri?: string;
    };
  };
  results: SarifResult[];
}

interface SarifResult {
  ruleId: string;
  level?: 'error' | 'warning' | 'note' | 'none';
  message: {
    text: string;
  };
  locations?: SarifLocation[];
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
    };
  };
}

const IMPACT_MAPPING: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  note: 0.3,
};

const DEFAULT_STATIC_ANALYSIS_NIST_TAGS = ['SI-10'];

export function convertSarifToHdf(input: string): string {
  // Calculate checksum of source scan data for integrity verification
  const resultsChecksum: Checksum = {
    algorithm: HashAlgorithm.Sha256,
    value: createHash('sha256').update(input).digest('hex'),
  };

  // Parse SARIF JSON
  const sarif = parseJSON<SarifFile>(input);

  if (!sarif || typeof sarif !== 'object') {
    throw new Error('Invalid SARIF structure: not a valid JSON object');
  }

  if (!Array.isArray(sarif.runs)) {
    throw new Error('Invalid SARIF structure: missing or invalid runs field');
  }

  const dataSource: DataSource = { format: 'SARIF' };
  const firstRun = sarif.runs[0];
  const firstDriver = firstRun?.tool?.driver;
  if (firstDriver) {
    if (firstDriver.name) {
      dataSource.name = firstDriver.name;
    }
    if (firstDriver.version) {
      dataSource.version = firstDriver.version;
    }
  }

  // Build HDF
  const hdf: HdfResults = {
    timestamp: new Date(),
    baselines: sarif.runs.map(run => convertRun(run, sarif.version, resultsChecksum)),
    targets: [],
    generator: {
      name: 'sarif-to-hdf',
      version: '1.0.0',
    },
    dataSource,
  };

  return JSON.stringify(hdf, null, 2);
}

function convertRun(run: SarifRun, version: string, resultsChecksum: Checksum): EvaluatedBaseline {
  const requirements = run.results.map(result => convertResult(result));

  return createMinimalBaseline('SARIF', requirements, {
    version,
    title: 'Static Analysis Results Interchange Format',
    resultsChecksum,
  });
}

function convertResult(result: SarifResult): EvaluatedRequirement {
  const messageText = result.message.text;

  // Parse title and description from message
  const { title, description } = parseMessage(messageText);

  // Extract CWE IDs from message
  const cweIds = extractCweIds(messageText);

  // Map CWE to NIST
  const nistControls = mapCweToNist(cweIds);

  // Map NIST to CCI
  const cciControls = nistToCci(nistControls);

  // Get impact from level
  const impact = IMPACT_MAPPING[result.level || ''] || 0.1;

  // Get source location from first location
  const sourceLocation = result.locations && result.locations.length > 0
    ? extractSourceLocation(result.locations[0]!)
    : undefined;

  // Create results for each location
  const results: RequirementResult[] = (result.locations || [])
    .filter(loc => loc.physicalLocation?.artifactLocation?.uri)
    .map(loc => createResultFromLocation(loc));

  const options: {
    sourceLocation?: { ref: string; line: number };
    tags: Record<string, unknown>;
  } = {
    tags: {
      severity: result.level || 'none',
      cwe: cweIds,
      nist: nistControls,
      cci: cciControls,
    },
  };

  if (sourceLocation) {
    options.sourceLocation = sourceLocation;
  }

  return createRequirement(
    result.ruleId,
    title,
    [createDescription('default', description)],
    impact,
    results,
    options
  );
}

function parseMessage(text: string): { title: string; description: string } {
  const colonIndex = text.indexOf(':');

  if (colonIndex === -1) {
    return { title: text, description: '' };
  }

  return {
    title: text.substring(0, colonIndex).trim(),
    description: text.substring(colonIndex + 1).trim(),
  };
}

function extractCweIds(text: string): string[] {
  // Look for pattern like (CWE-123, CWE-456) or (CWE-119!/CWE-120)
  const cwePattern = /\(([^)]+)\)/g;
  const matches = text.match(cwePattern);

  if (!matches) {
    return [];
  }

  const cweIds: string[] = [];

  for (const match of matches) {
    // Remove parentheses
    const content = match.slice(1, -1);

    // Check if it contains CWE
    if (content.includes('CWE-')) {
      // Split by comma or !/
      const parts = content.split(/,\s*|!\//);

      for (const part of parts) {
        const trimmed = part.trim();
        if (trimmed.startsWith('CWE-')) {
          cweIds.push(trimmed);
        }
      }
    }
  }

  return cweIds;
}

function mapCweToNist(cweIds: string[]): string[] {
  if (cweIds.length === 0) {
    return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  }

  const nistSet = new Set<string>();

  for (const cweId of cweIds) {
    // Extract numeric part (e.g., "CWE-79" -> 79)
    const numericId = parseInt(cweId.replace('CWE-', ''), 10);

    if (isNaN(numericId)) {
      continue;
    }

    const nistControl = getCweNistControl(numericId);

    if (nistControl) {
      nistSet.add(nistControl);
    }
  }

  // If no NIST mappings found, use default
  if (nistSet.size === 0) {
    return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
  }

  return Array.from(nistSet);
}



function extractSourceLocation(location: SarifLocation): { ref: string; line: number } | undefined {
  const uri = location.physicalLocation?.artifactLocation?.uri;
  const line = location.physicalLocation?.region?.startLine;

  if (!uri || !line) {
    return undefined;
  }

  return { ref: uri, line };
}

function createResultFromLocation(location: SarifLocation): RequirementResult {
  const uri = location.physicalLocation?.artifactLocation?.uri || '';
  const line = location.physicalLocation?.region?.startLine || 0;
  const column = location.physicalLocation?.region?.startColumn || 0;

  return createResult(
    ResultStatus.Failed,
    '',
    {
      codeDesc: `URL : ${uri} LINE : ${line} COLUMN : ${column}`,
      startTime: new Date(),
    }
  );
}
