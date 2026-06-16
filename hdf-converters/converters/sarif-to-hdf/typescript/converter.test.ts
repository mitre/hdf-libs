import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSarifToHdf } from './converter.js';
import { expectValidResults } from '../../../test/helpers/expectValidHdf.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

// --- Backward compatibility tests ---

describe('SARIF Converter', async () => {
  describe('Basic conversion', async () => {
    it('should convert real Flawfinder SARIF to HDF', async () => {
      const input = loadFixture('input', 'sarif_input.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));
      expectValidResults(result);

      expect(result.tool?.format).toBe('SARIF');
      expect(result.tool?.name).toBe('Flawfinder');
      expect(result.tool?.version).toBe('2.0.15');
      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].name).toBe('Flawfinder');
      expect(result.baselines[0].version).toBe('2.1.0');
      expect(result.baselines[0].requirements).toHaveLength(21);

      // Verify FF1014 requirement (buffer/gets, error level)
      const ff1014 = result.baselines[0].requirements.find((r: any) => r.id === 'FF1014');
      expect(ff1014).toBeDefined();
      expect(ff1014.title).toBe('buffer/gets');
      expect(ff1014.descriptions[0].data).toContain('Does not check for buffer overflows');
      expect(ff1014.impact).toBe(0.7);
      expect(ff1014.tags.severity).toBe('error');
      expect(ff1014.tags.cwe).toContain('CWE-120');
      expect(ff1014.tags.cwe).toContain('CWE-20');
      expect(ff1014.tags.nist).toContain('SI-10');
      expect(ff1014.results.length).toBeGreaterThan(0);
      expect(ff1014.results[0].status).toBe('failed');
      expect(ff1014.results[0].codeDesc).toContain('test/test-patched.c');
    });

    it('should synthesize a passed placeholder for empty results array', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestTool', version: '1.0.0' } },
          results: []
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].requirements).toHaveLength(1);
      const req = result.baselines[0].requirements[0];
      expect(req.id).toBe('TestTool-no-findings');
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('TestTool');
      expect(req.results[0].codeDesc).toContain('zero findings');
      expect(req.results[0].startTime).toBe(result.timestamp);
    });

    it('should synthesize a placeholder from the empty-results fixture', async () => {
      const input = loadFixture('input', 'empty-results.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].requirements).toHaveLength(1);
      const req = result.baselines[0].requirements[0];
      expect(req.id).toBe('ExampleAnalyzer-no-findings');
      expect(req.results[0].status).toBe('passed');
      expect(req.results[0].codeDesc).toContain('ExampleAnalyzer');
      expect(req.results[0].codeDesc).toContain('zero findings');
    });

    it('should synthesize a per-run placeholder for each empty baseline', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [
          { tool: { driver: { name: 'ToolA', version: '1.0' } }, results: [] },
          { tool: { driver: { name: 'ToolB', version: '2.0' } }, results: [] },
        ],
      });
      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines).toHaveLength(2);
      expect(result.baselines[0].requirements).toHaveLength(1);
      expect(result.baselines[0].requirements[0].id).toBe('ToolA-no-findings');
      expect(result.baselines[1].requirements).toHaveLength(1);
      expect(result.baselines[1].requirements[0].id).toBe('ToolB-no-findings');
    });

    it('should fall back to SARIF analyzer target when driver name is empty', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: '', version: '1.0' } },
          results: [],
        }],
      });
      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.id).toBe('sarif-no-findings');
      expect(req.results[0].codeDesc).toContain('SARIF analyzer');
      expect(req.results[0].codeDesc).toContain('zero findings');
    });

    it('should handle missing locations', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestTool', version: '1.0.0' } },
          results: [{
            ruleId: 'TEST-001',
            level: 'error',
            message: { text: 'test/issue: Test issue description (CWE-79).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.sourceLocation).toBeUndefined();
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('failed');
      expect(req.results[0].codeDesc).toBe('No source location');
    });
  });

  // --- Level resolution / impact tests ---

  describe('Impact mapping', async () => {
    it('should map error level to 0.7', async () => {
      const result = await convertWithLevel('error');
      expect(result.baselines[0].requirements[0].impact).toBe(0.7);
    });

    it('should map warning level to 0.5', async () => {
      const result = await convertWithLevel('warning');
      expect(result.baselines[0].requirements[0].impact).toBe(0.5);
    });

    it('should map note level to 0.3', async () => {
      const result = await convertWithLevel('note');
      expect(result.baselines[0].requirements[0].impact).toBe(0.3);
    });

    it('should default to warning (0.5) for missing level', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            message: { text: 'test: description' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.5);
    });
  });

  describe('Level fallback to rule default', async () => {
    it('should use rule defaultConfiguration.level when result level is absent', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{
                id: 'R1',
                name: 'TestRule',
                defaultConfiguration: { level: 'error' }
              }]
            }
          },
          results: [{
            ruleId: 'R1',
            ruleIndex: 0,
            message: { text: 'Something bad happened' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.impact).toBe(0.7);
      expect(req.tags.severity).toBe('error');
    });
  });

  // --- CWE extraction priority tests ---

  describe('CWE extraction', async () => {
    it('should extract CWE IDs from message text with commas', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description (CWE-79, CWE-89).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-79');
      expect(cwes).toContain('CWE-89');
    });

    it('should extract CWE IDs from message text with !/', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'note',
            message: { text: 'test: description (CWE-119!/CWE-120).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-119');
      expect(cwes).toContain('CWE-120');
    });

    it('should handle message with no CWE IDs', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description without CWE.' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].tags.cwe).toEqual([]);
    });

    it('should prefer CWE from rule relationships over message', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{
                id: 'R1',
                name: 'TestRule',
                relationships: [{
                  target: { id: '89', toolComponent: { name: 'CWE' } },
                  kinds: ['superset']
                }],
                properties: { tags: ['CWE-999'] }
              }]
            }
          },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test (CWE-111).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toEqual(['CWE-89']);
    });

    it('should fall back to CWE from properties.tags', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{
                id: 'R1',
                name: 'TestRule',
                properties: { tags: ['security', 'CWE-798', 'credentials'] }
              }]
            }
          },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toEqual(['CWE-798']);
    });

    it('should fall back to default NIST when no CWE anywhere', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{ id: 'R1', name: 'NoRelationships' }]
            }
          },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'No CWE reference here' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const nist = result.baselines[0].requirements[0].tags.nist;
      expect(nist).toContain('SA-11');
      expect(nist).toContain('RA-5');
    });
  });

  // --- Message parsing tests ---

  describe('Message parsing', async () => {
    it('should split title and description on first colon', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'buffer/strcpy: Does not check for buffer overflows (CWE-120).' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('buffer/strcpy');
      expect(req.descriptions[0].data).toBe('Does not check for buffer overflows (CWE-120).');
    });

    it('should handle message without colon', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'Simple message without colon' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('Simple message without colon');
      expect(req.descriptions[0].data).toBe('');
    });
  });

  // --- Multiple locations tests ---

  describe('Multiple locations', async () => {
    it('should create one result per location', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: description (CWE-120).' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'file1.c' },
                  region: { startLine: 10, startColumn: 5 }
                }
              },
              {
                physicalLocation: {
                  artifactLocation: { uri: 'file2.c' },
                  region: { startLine: 20, startColumn: 3 }
                }
              }
            ]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];

      expect(req.sourceLocation.ref).toBe('file1.c');
      expect(req.sourceLocation.line).toBe(10);
      expect(req.results).toHaveLength(2);
      expect(req.results[0].codeDesc).toContain('file1.c');
      expect(req.results[0].codeDesc).toContain('LINE : 10');
      expect(req.results[1].codeDesc).toContain('file2.c');
      expect(req.results[1].codeDesc).toContain('LINE : 20');
    });
  });

  // --- Kind → status mapping tests ---

  describe('Kind to status mapping', async () => {
    // Impact is now determined at rule level, not per-result kind.
    // Without a rule definition, resolveRuleLevel falls back to first fail-kind
    // result's level or "warning". Non-fail-only results get "warning" → 0.5.
    const kindTests = [
      { kind: 'pass', expectedStatus: 'passed', expectedImpact: 0.5 },
      { kind: 'fail', expectedStatus: 'failed', expectedImpact: 0.7 },
      { kind: undefined, expectedStatus: 'failed', expectedImpact: 0.7 },
      { kind: 'open', expectedStatus: 'failed', expectedImpact: 0.5 },
      { kind: 'review', expectedStatus: 'notReviewed', expectedImpact: 0.5 },
      { kind: 'informational', expectedStatus: 'notApplicable', expectedImpact: 0.5 },
      { kind: 'notApplicable', expectedStatus: 'notApplicable', expectedImpact: 0.5 },
    ];

    for (const tt of kindTests) {
      it(`should map kind="${tt.kind ?? 'undefined'}" to status=${tt.expectedStatus}`, async () => {
        const input = JSON.stringify({
          version: '2.1.0',
          runs: [{
            tool: { driver: { name: 'Test', version: '1.0' } },
            results: [{
              ruleId: 'TEST',
              kind: tt.kind,
              level: 'error',
              message: { text: 'test message' },
              locations: [{
                physicalLocation: {
                  artifactLocation: { uri: 'file.go' },
                  region: { startLine: 1, startColumn: 1 }
                }
              }]
            }]
          }]
        });

        const result = JSON.parse(await convertSarifToHdf(input));
        const req = result.baselines[0].requirements[0];
        expect(req.impact).toBe(tt.expectedImpact);
        expect(req.results).toHaveLength(1);
        expect(req.results[0].status).toBe(tt.expectedStatus);
      });
    }
  });

  // --- Suppression tests ---

  describe('Suppressions', async () => {
    it('should mark accepted suppression as notReviewed', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: suppressed finding' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'file.go' },
                region: { startLine: 1, startColumn: 1 }
              }
            }],
            suppressions: [
              { kind: 'inSource', status: 'accepted', justification: 'false positive' }
            ]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('notReviewed');
      expect(req.results[0].message).toContain('false positive');
    });

    it('should keep failed status for rejected suppression', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test: not suppressed' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'file.go' },
                region: { startLine: 1, startColumn: 1 }
              }
            }],
            suppressions: [
              { kind: 'external', status: 'rejected' }
            ]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('failed');
    });

    it('should store suppressions in tags', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'TEST',
            level: 'error',
            message: { text: 'test finding' },
            locations: [],
            suppressions: [
              { kind: 'inSource', status: 'accepted', justification: 'test' },
              { kind: 'external', status: 'rejected' }
            ]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      const supps = req.tags.suppressions;
      expect(supps).toHaveLength(2);
      expect(supps[0].kind).toBe('inSource');
      expect(supps[0].status).toBe('accepted');
      expect(supps[1].kind).toBe('external');
      expect(supps[1].status).toBe('rejected');
    });
  });

  // --- Rule metadata tests ---

  describe('Rule metadata', async () => {
    it('should use rule name as title when available', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{
                id: 'R1',
                name: 'SqlInjection',
                shortDescription: { text: 'SQL Injection vulnerability' },
                fullDescription: { text: 'Full description of the SQL injection issue.' },
                helpUri: 'https://example.com/rules/R1',
                help: { text: 'Use parameterized queries.' }
              }]
            }
          },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'User input used in SQL query.' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];

      expect(req.title).toBe('SqlInjection');
      expect(req.descriptions[0].label).toBe('default');
      expect(req.descriptions[0].data).toBe('User input used in SQL query.');

      const rationale = req.descriptions.find((d: { label: string }) => d.label === 'rationale');
      expect(rationale).toBeDefined();
      expect(rationale.data).toBe('Full description of the SQL injection issue.');

      const check = req.descriptions.find((d: { label: string }) => d.label === 'check');
      expect(check).toBeDefined();
      expect(check.data).toBe('Use parameterized queries.');

      expect(req.tags.helpUri).toBe('https://example.com/rules/R1');
    });

    it('should fall back to message parsing when rule has no name', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: {
            driver: {
              name: 'Test', version: '1.0',
              rules: [{ id: 'R1' }]
            }
          },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'category/name: Description here.' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('category/name');
      expect(req.descriptions[0].data).toBe('Description here.');
    });

    it('should use tool name as baseline name', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'gosec', version: '2.18.2' } },
          results: []
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines[0].name).toBe('gosec');
    });

    it('should fall back to SARIF when tool name is empty', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: '', version: '1.0' } },
          results: []
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      expect(result.baselines[0].name).toBe('SARIF');
    });
  });

  // --- Fix tests ---

  describe('Fixes', async () => {
    it('should add fix description when present', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: [],
            fixes: [
              { description: { text: 'Replace with safe alternative.' } }
            ]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      const fix = req.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix.data).toBe('Replace with safe alternative.');
    });

    it('should not add fix description when absent', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      const fix = req.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeUndefined();
    });
  });

  // --- Code flow / backtrace tests ---

  describe('Code flows', async () => {
    it('should build backtrace from code flow', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'data flow issue' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'sink.go' },
                region: { startLine: 50, startColumn: 1 }
              }
            }],
            codeFlows: [{
              threadFlows: [{
                locations: [
                  {
                    location: {
                      physicalLocation: {
                        artifactLocation: { uri: 'source.go' },
                        region: { startLine: 10, startColumn: 1 }
                      },
                      message: { text: 'User input received' }
                    },
                    importance: 'essential'
                  },
                  {
                    location: {
                      physicalLocation: {
                        artifactLocation: { uri: 'sink.go' },
                        region: { startLine: 50, startColumn: 1 }
                      },
                      message: { text: 'Unsanitized use' }
                    },
                    importance: 'essential'
                  }
                ]
              }]
            }]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      const bt = req.results[0].backtrace;
      expect(bt).toHaveLength(2);
      expect(bt[0]).toBe('source.go:10 - User input received');
      expect(bt[1]).toBe('sink.go:50 - Unsanitized use');
    });

    it('should have empty backtrace when no code flows', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'no code flow' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'file.go' },
                region: { startLine: 1, startColumn: 1 }
              }
            }]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].backtrace).toEqual([]);
    });
  });

  // --- Snippet tests ---

  describe('Snippets', async () => {
    it('should include snippet in codeDesc when present', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'file.go' },
                region: {
                  startLine: 42,
                  startColumn: 5,
                  snippet: { text: 'db.Query(sql + input)' }
                }
              }
            }]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].codeDesc).toContain('URL : file.go LINE : 42 COLUMN : 5');
      expect(req.results[0].codeDesc).toContain('db.Query(sql + input)');
    });

    it('should not include snippet when absent', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'file.go' },
                region: { startLine: 42, startColumn: 5 }
              }
            }]
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].codeDesc).toBe('URL : file.go LINE : 42 COLUMN : 5');
    });
  });

  // --- Fingerprint tests ---

  describe('Fingerprints', async () => {
    it('should store fingerprints in tags', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: [],
            fingerprints: { primaryLocationHash: 'abc123' },
            partialFingerprints: { lineHash: 'def456' }
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.tags.fingerprints).toBeDefined();
      expect(req.tags.fingerprints.fingerprints.primaryLocationHash).toBe('abc123');
      expect(req.tags.fingerprints.partialFingerprints.lineHash).toBe('def456');
    });

    it('should not include fingerprints when absent', async () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'Test', version: '1.0' } },
          results: [{
            ruleId: 'R1',
            level: 'error',
            message: { text: 'test finding' },
            locations: []
          }]
        }]
      });

      const result = JSON.parse(await convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.tags.fingerprints).toBeUndefined();
    });
  });

  // --- Error handling ---

  describe('Error handling', async () => {
    it('should error on invalid JSON', async () => {
      await expect(convertSarifToHdf('not valid json')).rejects.toThrow();
    });

    it('should error on missing runs', async () => {
      const input = JSON.stringify({ version: '2.1.0' });
      await expect(convertSarifToHdf(input)).rejects.toThrow('Invalid SARIF structure');
    });

    it('should error on non-array runs', async () => {
      const input = JSON.stringify({ version: '2.1.0', runs: {} });
      await expect(convertSarifToHdf(input)).rejects.toThrow('Invalid SARIF structure');
    });
  });

  // --- Integration tests with fixtures ---

  describe('Rich fixture integration', async () => {
    it('should convert rich.sarif with all enriched fields', async () => {
      const input = loadFixture('input', 'rich.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      expect(result.baselines).toHaveLength(1);
      const baseline = result.baselines[0];
      expect(baseline.name).toBe('SecurityScanner');
      expect(baseline.requirements).toHaveLength(5);

      // SEC-001: SqlInjection — 3 SARIF results (fail, informational, open)
      const sec001 = baseline.requirements[0];
      expect(sec001.id).toBe('SEC-001');
      expect(sec001.title).toBe('SqlInjection');
      expect(sec001.impact).toBe(0.7); // error → 0.7 (rule-level)
      expect(sec001.tags.cwe).toContain('CWE-89');
      expect(sec001.tags.helpUri).toBe('https://example.com/rules/SEC-001');
      const fix = sec001.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix.data).toContain('parameterized query');
      expect(sec001.results).toHaveLength(3);
      expect(sec001.results[0].status).toBe('failed');
      expect(sec001.results[0].codeDesc).toContain('db.Query');
      expect(sec001.results[0].backtrace).toHaveLength(3);
      expect(sec001.results[0].backtrace[0]).toContain('src/handlers/user.go:22');
      expect(sec001.results[1].status).toBe('notApplicable'); // informational
      expect(sec001.results[2].status).toBe('failed'); // open

      // SEC-002: WeakCrypto — 1 result, rule default level "warning"
      const sec002 = baseline.requirements[1];
      expect(sec002.id).toBe('SEC-002');
      expect(sec002.title).toBe('WeakCrypto');
      expect(sec002.impact).toBe(0.5);
      expect(sec002.tags.severity).toBe('warning');
      expect(sec002.results).toHaveLength(1);
      expect(sec002.results[0].status).toBe('failed');

      // SEC-003: HardcodedCredential — 3 results (accepted supp, rejected supp, multiple supps)
      const sec003 = baseline.requirements[2];
      expect(sec003.id).toBe('SEC-003');
      expect(sec003.impact).toBe(0.7); // error
      expect(sec003.results).toHaveLength(3);
      expect(sec003.results[0].status).toBe('notReviewed'); // accepted suppression
      expect(sec003.results[0].message).toContain('test API key');
      expect(sec003.results[1].status).toBe('failed'); // rejected suppression
      expect(sec003.results[2].status).toBe('notReviewed'); // multiple suppressions

      // SEC-004: InfoLeak — 2 results (pass, review)
      const sec004 = baseline.requirements[3];
      expect(sec004.id).toBe('SEC-004');
      expect(sec004.impact).toBe(0.3); // note
      expect(sec004.results).toHaveLength(2);
      expect(sec004.results[0].status).toBe('passed');
      expect(sec004.results[1].status).toBe('notReviewed');

      // SEC-005: DeprecatedAPI — 1 result (notApplicable)
      const sec005 = baseline.requirements[4];
      expect(sec005.id).toBe('SEC-005');
      expect(sec005.impact).toBe(0.3); // note
      expect(sec005.results).toHaveLength(1);
      expect(sec005.results[0].status).toBe('notApplicable');
    });
  });

  // --- Multi-tool fixture tests (DefectDojo-sourced, schema-validated) ---

  describe('CodeQL fixture integration', async () => {
    it('should convert codeQL-output.sarif with grouping, codeFlows, and fingerprints', async () => {
      const input = loadFixture('input', 'codeQL-output.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      const baseline = result.baselines[0];
      expect(baseline.name).toBe('CodeQL');
      expect(baseline.version).toBe('2.1.0');
      expect(baseline.requirements).toHaveLength(13);

      // py/sql-injection — has codeFlows
      const sqlInj = baseline.requirements.find((r: any) => r.id === 'py/sql-injection');
      expect(sqlInj).toBeDefined();
      expect(sqlInj.results).toHaveLength(2);
      expect(sqlInj.results[0].backtrace.length).toBeGreaterThan(0);
      expect(sqlInj.impact).toBe(0.7); // defaultConfiguration.level = "error"

      // Fingerprints from CodeQL
      expect(sqlInj.tags.fingerprints).toBeDefined();
      expect(sqlInj.tags.fingerprints.partialFingerprints).toBeDefined();

      // py/unused-import — heaviest grouping: 40 results
      const unusedImport = baseline.requirements.find((r: any) => r.id === 'py/unused-import');
      expect(unusedImport).toBeDefined();
      expect(unusedImport.results).toHaveLength(40);
    });
  });

  describe('Gitleaks fixture integration', async () => {
    it('should handle results with no ruleId (all grouped under empty string)', async () => {
      const input = loadFixture('input', 'gitleaks_7.5.0.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      const baseline = result.baselines[0];
      expect(baseline.name).toBe('Gitleaks');

      // All 8 results lack ruleId. Should group by message text:
      // 6x "AWS Access Key secret detected" → 1 requirement
      // 2x "Asymmetric Private Key secret detected" → 1 requirement
      expect(baseline.requirements).toHaveLength(2);

      const awsReq = baseline.requirements.find((r: any) => r.id === 'AWS Access Key secret detected');
      expect(awsReq).toBeDefined();
      expect(awsReq.results).toHaveLength(6);

      const asymReq = baseline.requirements.find((r: any) => r.id === 'Asymmetric Private Key secret detected');
      expect(asymReq).toBeDefined();
      expect(asymReq.results).toHaveLength(2);

      // Results should have location info with snippets
      for (const r of awsReq.results) {
        expect(r.codeDesc).toContain('URL :');
        expect(r.codeDesc).toContain('LINE :');
      }
    });
  });

  describe('SpotBugs fixture integration', async () => {
    it('should convert spotbugs.sarif with all note-level rules', async () => {
      const input = loadFixture('input', 'spotbugs.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      const baseline = result.baselines[0];
      expect(baseline.name).toBe('SpotBugs');
      expect(baseline.requirements).toHaveLength(9);

      // All SpotBugs results are note level → 0.3 impact
      for (const req of baseline.requirements) {
        expect(req.impact).toBe(0.3);
        expect(req.tags.severity).toBe('note');
      }

      // NM_METHOD_NAMING_CONVENTION — 33 results
      const nmMethod = baseline.requirements.find((r: any) => r.id === 'NM_METHOD_NAMING_CONVENTION');
      expect(nmMethod).toBeDefined();
      expect(nmMethod.results).toHaveLength(33);
      expect(nmMethod.tags.helpUri).toBeDefined();

      // SpotBugs uses message.id + arguments instead of message.text.
      // The converter should resolve messageStrings templates.
      const dmiRule = baseline.requirements.find((r: any) => r.id === 'DMI_HARDCODED_ABSOLUTE_FILENAME');
      expect(dmiRule).toBeDefined();
      // messageStrings.default.text = "Hard coded reference to an absolute pathname in {0}."
      // arguments = ["Boot.main(String[])"]
      expect(dmiRule.descriptions[0].data).toContain('Boot.main(String[])');
    });
  });

  describe('Dockle fixture integration', async () => {
    it('should handle results with no locations (0 RequirementResults)', async () => {
      const input = loadFixture('input', 'dockle_0_3_15.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      const baseline = result.baselines[0];
      expect(baseline.name).toBe('Dockle');
      expect(baseline.requirements).toHaveLength(4);

      // All Dockle results have 0 locations (container-level findings).
      // Each should still produce 1 RequirementResult with a generic codeDesc.
      for (const req of baseline.requirements) {
        expect(req.results).toHaveLength(1);
        expect(req.results[0].status).toBe('failed');
      }

      // CIS-DI-0010 is error, others are note
      const cis0010 = baseline.requirements.find((r: any) => r.id === 'CIS-DI-0010');
      expect(cis0010.impact).toBe(0.7);
      const cis0005 = baseline.requirements.find((r: any) => r.id === 'CIS-DI-0005');
      expect(cis0005.impact).toBe(0.3);

      // Dockle rules have help → check description
      const check = cis0010.descriptions.find((d: any) => d.label === 'check');
      expect(check).toBeDefined();
      expect(check.data).toContain('CHECKPOINT');
    });
  });

  describe('Gosec fixture integration', async () => {
    it('should convert gosec.sarif with CWE taxonomy', async () => {
      const input = loadFixture('input', 'gosec.sarif');
      const result = JSON.parse(await convertSarifToHdf(input));

      const baseline = result.baselines[0];
      expect(baseline.name).toBe('gosec');
      expect(baseline.requirements).toHaveLength(4);

      // G201 — CWE from relationships
      const r0 = baseline.requirements[0];
      expect(r0.id).toBe('G201');
      expect(r0.tags.cwe).toContain('CWE-89');
      expect(r0.impact).toBe(0.7);
      expect(r0.results[0].codeDesc).toContain('fmt.Sprintf');

      // G304 — suppressed
      const r1 = baseline.requirements[1];
      expect(r1.id).toBe('G304');
      expect(r1.results[0].status).toBe('notReviewed');
      expect(r1.tags.cwe).toContain('CWE-22');

      // G401 — CWE from relationships
      const r2 = baseline.requirements[2];
      expect(r2.tags.cwe).toContain('CWE-326');

      // G101 — CWE from properties.tags
      const r3 = baseline.requirements[3];
      expect(r3.tags.cwe).toContain('CWE-798');
    });
  });

  describe('SCA-shaped SARIF (result.properties package identity)', () => {
    async function convertWithProps(props: Record<string, unknown>) {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestSCA', version: '1.0' } },
          results: [{
            ruleId: 'CVE-2026-1234',
            level: 'error',
            message: { text: 'vulnerable package detected' },
            locations: [],
            properties: props,
          }],
        }],
      });
      return JSON.parse(await convertSarifToHdf(input));
    }

    it('extracts purl into affectedPackages and decomposes ecosystem', async () => {
      const result = await convertWithProps({ purl: 'pkg:npm/lodash@4.17.20' });
      const req = result.baselines[0].requirements[0];
      expect(req.affectedPackages).toHaveLength(1);
      expect(req.affectedPackages[0].purl).toBe('pkg:npm/lodash@4.17.20');
      expect(req.affectedPackages[0].ecosystem).toBe('npm');
    });

    it('extracts packageName + packageVersion into name+version+generic', async () => {
      const result = await convertWithProps({
        packageName: 'openssl',
        packageVersion: '1.1.1k',
      });
      const req = result.baselines[0].requirements[0];
      expect(req.affectedPackages[0]).toMatchObject({
        name: 'openssl',
        version: '1.1.1k',
        ecosystem: 'generic',
      });
    });

    it('emits cpe-only when only cpe is present', async () => {
      const result = await convertWithProps({
        cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
      });
      const req = result.baselines[0].requirements[0];
      expect(req.affectedPackages[0]).toEqual({
        cpe: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*',
      });
    });

    it('honors fixedInVersion from properties', async () => {
      const result = await convertWithProps({
        purl: 'pkg:npm/lodash@4.17.20',
        fixedInVersion: '4.17.21',
      });
      const req = result.baselines[0].requirements[0];
      expect(req.affectedPackages[0].fixedInVersion).toBe('4.17.21');
    });

    it('omits affectedPackages on pure SAST results (empty properties)', async () => {
      const result = await convertWithProps({});
      const req = result.baselines[0].requirements[0];
      expect(req.affectedPackages).toBeUndefined();
    });
  });
});

// --- Helpers ---

async function convertWithLevel(level: string) {
  const input = JSON.stringify({
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Test', version: '1.0' } },
      results: [{
        ruleId: 'TEST',
        level,
        message: { text: 'test: description' },
        locations: []
      }]
    }]
  });

  return JSON.parse(await convertSarifToHdf(input));
}
