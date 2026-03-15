import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import { inputChecksum, limitArray, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createMinimalBaseline,
  createRequirement,
  createResult,
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
const CONVERTER_VERSION = '1.0.0';

// Tags to always parse as arrays (even when single element)
const ARRAY_TAGS = ['testsuite', 'testcase'];

/**
 * Converts JUnit XML test results to HDF format.
 */
export async function convertJunitToHdf(input: string): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'junit');

  const { suites, name } = parseJUnitXML(input);
  const requirements = buildRequirements(suites);

  const resultsChecksum: Checksum = await inputChecksum(input);

  const baseline = createMinimalBaseline(name, requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
    dataSource: { name: 'JUnit XML', format: 'XML' },
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}

function parseJUnitXML(input: string): { suites: JUnitTestSuite[]; name: string } {
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS) as JUnitTestSuites;

  // <testsuites> root
  if (parsed.testsuites) {
    const suites = parsed.testsuites.testsuite ?? [];
    const name = parsed.testsuites.name || 'JUnit Test Results';
    return { suites, name };
  }

  // <testsuite> root
  if (parsed.testsuite) {
    const suite = parsed.testsuite;
    // When testsuite is root, parseXmlWithArrays may return it directly
    // (not wrapped in an array since ARRAY_TAGS only forces arrays for child elements)
    const suites = Array.isArray(suite) ? (suite as JUnitTestSuite[]) : [suite];
    const name = suites[0]?.name || 'JUnit Test Results';
    return { suites, name };
  }

  throw new Error('Input is not a JUnit XML document: expected <testsuites> or <testsuite> root element');
}

function buildRequirements(suites: JUnitTestSuite[]): EvaluatedRequirement[] {
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
      requirements.push(testCaseToRequirement(tc, suite.timestamp));
    }
  }

  return requirements;
}

function testCaseToRequirement(
  tc: JUnitTestCase,
  suiteTimestamp?: string
): EvaluatedRequirement {
  const id = buildID(tc);
  const { status, message } = resolveStatus(tc);
  const codeDesc = buildCodeDesc(tc);

  const resultOptions: Record<string, unknown> = { codeDesc };
  if (tc.time) {
    const parsed = parseFloat(tc.time);
    if (!isNaN(parsed)) {
      resultOptions.runTime = parsed;
    }
  }
  if (suiteTimestamp) {
    resultOptions.startTime = suiteTimestamp;
  }

  const result = createResult(status, message ?? '', resultOptions) as RequirementResult;

  const descriptions: Description[] = [
    {
      label: 'default',
      data: `JUnit test: ${tc.name} in ${tc.classname || 'unknown'}`,
    },
  ];

  return createRequirement(id, tc.name, descriptions, 0.5, [result], {
    tags: { nist: DEFAULT_NIST },
  }) as EvaluatedRequirement;
}

function buildID(tc: JUnitTestCase): string {
  if (tc.classname) {
    return `${tc.classname}.${tc.name}`;
  }
  return tc.name;
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
      return { status: ResultStatus.NotReviewed, message: `Skipped: ${skipped.message}` };
    }
    return { status: ResultStatus.NotReviewed, message: 'Skipped' };
  }
  return { status: ResultStatus.Passed };
}

function buildFailureMessage(message: string, typeName: string, body: string): string {
  let result = '';
  if (typeName) {
    result = `${typeName}: `;
  }
  result += message;
  if (body) {
    result += '\n' + body;
  }
  return result;
}

function buildCodeDesc(tc: JUnitTestCase): string {
  if (tc.classname) {
    return `${tc.classname} :: ${tc.name}`;
  }
  return tc.name;
}
