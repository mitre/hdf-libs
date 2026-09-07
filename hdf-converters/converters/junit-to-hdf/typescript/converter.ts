import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import { inputChecksum, limitArray, validateInputSize, buildHdfResults, buildNoFindingsRequirement, deriveControlTypeFromTags } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Component,
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
    '@_name'?: string;
    testsuite?: JUnitTestSuite[];
    // Node's built-in runner (node --test --test-reporter=junit) emits testcases as
    // DIRECT children of <testsuites> with no <testsuite> wrapper. Without this they
    // parse as nothing, and a red run converts to an empty green document.
    testcase?: JUnitTestCase[];
  };
  testsuite?: JUnitTestSuite;
}

interface JUnitTestSuite {
  '@_name'?: string;
  '@_tests'?: number;
  '@_failures'?: number;
  '@_errors'?: number;
  '@_skipped'?: number;
  '@_time'?: string;
  '@_timestamp'?: string;
  '@_hostname'?: string;
  testcase?: JUnitTestCase[];
}

interface JUnitTestCase {
  '@_classname'?: string;
  '@_name': string;
  '@_time'?: string;
  failure?: JUnitFailure;
  error?: JUnitError;
  skipped?: JUnitSkipped | '';
  'system-out'?: string;
  'system-err'?: string;
  flakyFailure?: JUnitFlaky[];
  flakyError?: JUnitFlaky[];
}

// A Surefire flaky/rerun retry element, which can carry its own captured
// stdout/stderr for the attempt.
interface JUnitFlaky {
  'system-out'?: string;
  'system-err'?: string;
}

interface JUnitFailure {
  '@_message'?: string;
  '@_type'?: string;
  '#text'?: string;
}

interface JUnitError {
  '@_message'?: string;
  '@_type'?: string;
  '#text'?: string;
}

interface JUnitSkipped {
  '@_message'?: string;
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
const ARRAY_TAGS = ['testsuite', 'testcase', 'flakyFailure', 'flakyError'];

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
    components: [
      {
        type: TargetType.Application,
        name,
      },
      ...hostComponents(suites),
    ],
    timestamp: scanTime,
  });
}

// Derives one host component per distinct testsuite @hostname (the machine the
// tests ran on). Suites without a hostname contribute nothing; duplicate
// hostnames are emitted once, in first-seen order.
function hostComponents(suites: JUnitTestSuite[]): Component[] {
  const hosts: Component[] = [];
  const seen = new Set<string>();
  for (const suite of suites) {
    const hostname = suite['@_hostname']?.trim();
    if (!hostname || seen.has(hostname)) {
      continue;
    }
    seen.add(hostname);
    hosts.push({
      type: TargetType.Host,
      name: hostname,
      hostname,
    });
  }
  return hosts;
}

// Computes one timestamp per conversion: the first available <testsuite> timestamp,
// falling back to conversion time. Used for every result's startTime, the document
// timestamp, and any no-findings placeholder.
function resolveScanTime(suites: JUnitTestSuite[]): Date {
  for (const suite of suites) {
    if (suite['@_timestamp']) {
      const parsed = parseTimestamp(suite['@_timestamp']);
      if (parsed) {
        return parsed;
      }
    }
  }
  return new Date();
}

function parseJUnitXML(input: string): { suites: JUnitTestSuite[]; name: string } {
  // Attributes are prefixed so they cannot collide with same-named child
  // elements. Node's runner emits BOTH a failure= attribute and a <failure>
  // child on <testcase>; with the shared default of no prefix the attribute
  // overwrote the element, and the failure message, type and stack were lost.
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS, {
    attributeNamePrefix: '@_',
  }) as JUnitTestSuites;

  // <testsuites> root
  if (parsed.testsuites) {
    const suites = [...(parsed.testsuites.testsuite ?? [])];
    const name = parsed.testsuites['@_name'] ? decodeXmlEntities(parsed.testsuites['@_name']) : 'JUnit Test Results';
    // Testcases sitting directly under <testsuites> become an implicit suite so they
    // convert exactly like wrapped ones. Appended after any explicit suites, so a
    // document carrying both keeps all of its cases in a deterministic order rather
    // than silently dropping the loose ones. Mirrors Go's parseJUnitXML.
    const looseCases = parsed.testsuites.testcase ?? [];
    if (looseCases.length > 0) {
      suites.push({ '@_name': name, testcase: looseCases });
    }
    return { suites, name };
  }

  // <testsuite> root
  if (parsed.testsuite) {
    const suite = parsed.testsuite;
    // When testsuite is root, parseXmlWithArrays may return it directly
    // (not wrapped in an array since ARRAY_TAGS only forces arrays for child elements)
    const suites = Array.isArray(suite) ? (suite as JUnitTestSuite[]) : [suite];
    const suiteName = suites[0]?.['@_name'];
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
  if (tc['@_time']) {
    const parsed = parseFloat(tc['@_time']);
    if (!isNaN(parsed)) {
      result.runTime = parsed;
    }
  }

  const name = decodeXmlEntities(tc['@_name']);
  const descriptions: Description[] = [
    {
      label: 'default',
      data: `JUnit test: ${name} in ${tc['@_classname'] ? decodeXmlEntities(tc['@_classname']) : 'unknown'}`,
    },
  ];
  const { systemOut, systemErr } = collectSystemStreams(tc);
  if (systemOut) {
    descriptions.push({ label: 'system-out', data: systemOut });
  }
  if (systemErr) {
    descriptions.push({ label: 'system-err', data: systemErr });
  }

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

// Gathers captured stdout/stderr for a test case: any direct
// <system-out>/<system-err> children plus those nested inside Surefire
// flakyFailure/flakyError retry elements, in document order. Each block is
// trimmed of wrapping whitespace and empty blocks are dropped; multiple blocks
// are joined with a newline so each stream yields one description.
function collectSystemStreams(tc: JUnitTestCase): { systemOut: string; systemErr: string } {
  const outs: string[] = [];
  const errs: string[] = [];
  const add = (out?: string, err?: string): void => {
    if (out) {
      const trimmed = decodeXmlEntities(out).trim();
      if (trimmed) outs.push(trimmed);
    }
    if (err) {
      const trimmed = decodeXmlEntities(err).trim();
      if (trimmed) errs.push(trimmed);
    }
  };
  add(tc['system-out'], tc['system-err']);
  for (const f of tc.flakyFailure ?? []) add(f['system-out'], f['system-err']);
  for (const f of tc.flakyError ?? []) add(f['system-out'], f['system-err']);
  return { systemOut: outs.join('\n'), systemErr: errs.join('\n') };
}

function buildID(tc: JUnitTestCase): string {
  if (tc['@_classname']) {
    return `${decodeXmlEntities(tc['@_classname'])}.${decodeXmlEntities(tc['@_name'])}`;
  }
  return decodeXmlEntities(tc['@_name']);
}

function resolveStatus(tc: JUnitTestCase): { status: ResultStatus; message?: string } {
  if (tc.failure) {
    const msg = buildFailureMessage(
      tc.failure['@_message'] ?? '',
      tc.failure['@_type'] ?? '',
      tc.failure['#text'] ?? ''
    );
    return { status: ResultStatus.Failed, message: msg };
  }
  if (tc.error) {
    const msg = buildFailureMessage(
      tc.error['@_message'] ?? '',
      tc.error['@_type'] ?? '',
      tc.error['#text'] ?? ''
    );
    return { status: ResultStatus.Error, message: msg };
  }
  if (tc.skipped !== undefined) {
    const skipped = typeof tc.skipped === 'object' ? tc.skipped : null;
    if (skipped?.['@_message']) {
      return { status: ResultStatus.NotReviewed, message: `Skipped: ${decodeXmlEntities(skipped['@_message'])}` };
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
  if (tc['@_classname']) {
    return `${decodeXmlEntities(tc['@_classname'])} :: ${decodeXmlEntities(tc['@_name'])}`;
  }
  return decodeXmlEntities(tc['@_name']);
}

function noFindingsTarget(baselineName: string, suites: JUnitTestSuite[]): string {
  if (baselineName && baselineName !== 'JUnit Test Results') {
    return baselineName;
  }
  for (const s of suites) {
    if (s['@_name']) return decodeXmlEntities(s['@_name']);
  }
  return 'JUnit test suite';
}
