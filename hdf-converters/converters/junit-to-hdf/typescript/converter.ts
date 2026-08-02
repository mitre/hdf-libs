import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import { inputChecksum, limitArray, validateInputSize, buildHdfResults, buildNoFindingsRequirement, deriveControlTypeFromTags } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  TargetType,
  ResultStatus,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
} from '@mitre/hdf-schema';

// JUnit XML parsed types (from fast-xml-parser via parseXmlWithArrays)

interface JUnitTestSuites {
  testsuites?: {
    name?: string;
    testsuite?: JUnitTestSuite[];
  };
  testsuite?: JUnitTestSuite;
}

interface JUnitTestSuite {
  name?: string;
  tests?: number;
  failures?: number;
  errors?: number;
  skipped?: number;
  time?: string;
  timestamp?: string;
  hostname?: string;
  testcase?: JUnitTestCase[];
}

interface JUnitTestCase {
  classname?: string;
  name: string;
  time?: string;
  failure?: JUnitFailure;
  error?: JUnitError;
  skipped?: JUnitSkipped | '';
}

interface JUnitFailure {
  message?: string;
  type?: string;
  '#text'?: string;
}

interface JUnitError {
  message?: string;
  type?: string;
  '#text'?: string;
}

interface JUnitSkipped {
  message?: string;
}

const DEFAULT_NIST = ['SA-11'];

/**
 * The shared XML parser runs with `processEntities: false` (XXE defense), so
 * character references reach us undecoded. Surefire escapes quotes and angle
 * brackets in failure messages, so decode them here.
 */
function decodeXmlEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex: string) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

// Tags to always parse as arrays (even when single element)
const ARRAY_TAGS = ['testsuite', 'testcase'];

/**
 * Converts JUnit XML test results to HDF format.
 */
export async function convertJunitToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'junit');

  const { suites, name } = parseJUnitXML(input);
  const scanTime = resolveScanTime(suites);
  const requirements = buildRequirements(suites, scanTime);

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'junit-no-findings',
      `JUnit scanned ${noFindingsTarget(name, suites)} and reported zero findings.`,
      scanTime,
    ));
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const baseline = createMinimalBaseline(name, requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'junit-to-hdf',
    converterVersion,
    toolName: 'JUnit XML',
    baselines: [baseline],
    components: [{
      type: TargetType.Application,
      name,
    }],
    timestamp: scanTime,
  });
}

// Computes one timestamp per conversion: the first available <testsuite> timestamp,
// falling back to conversion time. Used for every result's startTime, the document
// timestamp, and any no-findings placeholder.
function resolveScanTime(suites: JUnitTestSuite[]): Date {
  for (const suite of suites) {
    if (suite.timestamp) {
      const parsed = parseTimestamp(suite.timestamp);
      if (parsed) {
        return parsed;
      }
    }
  }
  return new Date();
}

function parseJUnitXML(input: string): { suites: JUnitTestSuite[]; name: string } {
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS) as JUnitTestSuites;

  // <testsuites> root
  if (parsed.testsuites) {
    const suites = parsed.testsuites.testsuite ?? [];
    const name = parsed.testsuites.name ? decodeXmlEntities(parsed.testsuites.name) : 'JUnit Test Results';
    return { suites, name };
  }

  // <testsuite> root
  if (parsed.testsuite) {
    const suite = parsed.testsuite;
    // When testsuite is root, parseXmlWithArrays may return it directly
    // (not wrapped in an array since ARRAY_TAGS only forces arrays for child elements)
    const suites = Array.isArray(suite) ? (suite as JUnitTestSuite[]) : [suite];
    const suiteName = suites[0]?.name;
    const name = suiteName ? decodeXmlEntities(suiteName) : 'JUnit Test Results';
    return { suites, name };
  }

  throw new Error('Input is not a JUnit XML document: expected <testsuites> or <testsuite> root element');
}

function buildRequirements(suites: JUnitTestSuite[], scanTime: Date): EvaluatedRequirement[] {
  const { items: limitedSuites, truncated: truncatedSuites } = limitArray(suites);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedSuites) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedSuites.length} test suite items (original: ${suites.length})`);
  }
  const requirements: EvaluatedRequirement[] = [];

  for (const suite of limitedSuites) {
    const testcases = suite.testcase ?? [];
    const { items: limitedTestCases, truncated: truncatedTC } = limitArray(testcases);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedTC) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedTestCases.length} test case items (original: ${testcases.length})`);
    }
    for (const tc of limitedTestCases) {
      requirements.push(testCaseToRequirement(tc, scanTime));
    }
  }

  return requirements;
}

function testCaseToRequirement(
  tc: JUnitTestCase,
  scanTime: Date
): EvaluatedRequirement {
  const id = buildID(tc);
  const { status, message } = resolveStatus(tc);
  const codeDesc = buildCodeDesc(tc);

  // A passing test has nothing to explain, so `message` stays absent rather
  // than an empty string.
  const result: RequirementResult = {
    status,
    codeDesc,
    startTime: scanTime,
  };
  if (message !== undefined) {
    result.message = message;
  }
  if (tc.time) {
    const parsed = parseFloat(tc.time);
    if (!isNaN(parsed)) {
      result.runTime = parsed;
    }
  }

  const name = decodeXmlEntities(tc.name);
  const descriptions: Description[] = [
    {
      label: 'default',
      data: `JUnit test: ${name} in ${tc.classname ? decodeXmlEntities(tc.classname) : 'unknown'}`,
    },
  ];

  const req = createRequirement(id, name, descriptions, 0.5, [result], {
    tags: { nist: DEFAULT_NIST },
  }) as EvaluatedRequirement;
  const controlType = deriveControlTypeFromTags(DEFAULT_NIST);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

function buildID(tc: JUnitTestCase): string {
  if (tc.classname) {
    return `${decodeXmlEntities(tc.classname)}.${decodeXmlEntities(tc.name)}`;
  }
  return decodeXmlEntities(tc.name);
}

function resolveStatus(tc: JUnitTestCase): { status: ResultStatus; message?: string } {
  if (tc.failure) {
    const msg = buildFailureMessage(
      tc.failure.message ?? '',
      tc.failure.type ?? '',
      tc.failure['#text'] ?? ''
    );
    return { status: ResultStatus.Failed, message: msg };
  }
  if (tc.error) {
    const msg = buildFailureMessage(
      tc.error.message ?? '',
      tc.error.type ?? '',
      tc.error['#text'] ?? ''
    );
    return { status: ResultStatus.Error, message: msg };
  }
  if (tc.skipped !== undefined) {
    const skipped = typeof tc.skipped === 'object' ? tc.skipped : null;
    if (skipped?.message) {
      return { status: ResultStatus.NotReviewed, message: `Skipped: ${decodeXmlEntities(skipped.message)}` };
    }
    return { status: ResultStatus.NotReviewed, message: 'Skipped' };
  }
  return { status: ResultStatus.Passed };
}

function buildFailureMessage(message: string, typeName: string, body: string): string {
  let result = '';
  if (typeName) {
    result = `${decodeXmlEntities(typeName)}: `;
  }
  result += decodeXmlEntities(message);
  if (body) {
    result += '\n' + decodeXmlEntities(body);
  }
  return result;
}

function buildCodeDesc(tc: JUnitTestCase): string {
  if (tc.classname) {
    return `${decodeXmlEntities(tc.classname)} :: ${decodeXmlEntities(tc.name)}`;
  }
  return decodeXmlEntities(tc.name);
}

function noFindingsTarget(baselineName: string, suites: JUnitTestSuite[]): string {
  if (baselineName && baselineName !== 'JUnit Test Results') {
    return baselineName;
  }
  for (const s of suites) {
    if (s.name) return decodeXmlEntities(s.name);
  }
  return 'JUnit test suite';
}
