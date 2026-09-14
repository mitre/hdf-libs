import { describe, it, expect } from 'vitest';
import { runFingerprintTests } from '../../../shared/typescript/fptest.js';
import { register, junitFingerprint, isCheckovTestCaseName } from './fingerprint.js';

runFingerprintTests({
  id: 'junit-to-hdf',
  label: 'JUnit',
  direction: 'ingest',
  inputFamily: 'xml',
  outputType: 'results',
  fingerprint: junitFingerprint,
  register,
  positive: [
    {
      name: 'detects testsuites root at confidence 1.0',
      input: '<?xml version="1.0"?><testsuites><testsuite name="suite1"><testcase name="test1"/></testsuite></testsuites>',
      confidence: 1.0,
    },
    {
      name: 'detects testsuite root at confidence 1.0',
      input: '<?xml version="1.0"?><testsuite name="suite1"><testcase name="test1"/></testsuite>',
      confidence: 1.0,
    },
    {
      // Checkov JUnit is still JUnit: it is warned about at conversion, never rerouted.
      name: 'still scores Checkov-shaped JUnit at confidence 1.0',
      input: '<?xml version="1.0" ?><testsuites><testsuite name="terraform scan"><testcase name="[NONE][CKV_AWS_24] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22" classname="/main.tf.aws_security_group.wide_open" file="/main.tf"/></testsuite></testsuites>',
      confidence: 1.0,
    },
  ],
  negative: [
    { name: 'does not match XML with wrong root element', input: '<?xml version="1.0"?><Benchmark id="test"><title>Test</title></Benchmark>', confidence: 0 },
    { name: 'does not match JSON input', input: JSON.stringify({ version: '2.1.0', runs: [] }), confidence: 0 },
    { name: 'does not match empty input', input: '', confidence: 0 },
  ],
});

describe('isCheckovTestCaseName', () => {
  // Formats documented at https://www.checkov.io/8.Outputs/JUnit%20XML.html
  it.each([
    ['[NONE][CKV_AWS_24] Ensure no security groups allow ingress from 0.0.0.0:0 to port 22', true],
    ['[CRITICAL][CKV_AWS_20] S3 Bucket has an ACL defined which allows public READ access.', true],
    ['[LOW][CKV2_AWS_6] Ensure that S3 bucket has a Public Access block', true],
    ['[HIGH][CVE-2013-7370] connect: 2.6.0', true],
    ['[MEDIUM][CKV_AWS_18] a reworded description still matches', true],
    ['test_welcome_message', false],
    ['', false],
    ['[HIGH] only a severity bracket', false],
    ['[HIGH][TEST-1] a bracketed id that is not a Checkov or CVE id', false],
    ['CKV_AWS_24 is mentioned without the bracket prefix', false],
    ['prefix [NONE][CKV_AWS_24] not at the start', false],
  ])('%s -> %s', (name, want) => {
    expect(isCheckovTestCaseName(name)).toBe(want);
  });
});
