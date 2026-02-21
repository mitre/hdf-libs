import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { convertSarifToHdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, '..', 'fixtures');

function loadFixture(type: 'input' | 'expected', filename: string): string {
  return readFileSync(join(fixturesDir, type, filename), 'utf-8');
}

// --- Backward compatibility tests ---

describe('SARIF Converter', () => {
  describe('Basic conversion', () => {
    it('should convert minimal SARIF to HDF', () => {
      const input = loadFixture('input', 'minimal.sarif');
      const result = JSON.parse(convertSarifToHdf(input));

      expect(result.dataSource?.format).toBe('SARIF');
      expect(result.dataSource?.name).toBe('Flawfinder');
      expect(result.dataSource?.version).toBe('2.0.15');
      expect(result.baselines).toHaveLength(1);
      // Baseline name is now the tool driver name
      expect(result.baselines[0].name).toBe('Flawfinder');
      expect(result.baselines[0].version).toBe('2.1.0');
      expect(result.baselines[0].requirements).toHaveLength(2);

      const req1 = result.baselines[0].requirements[0];
      expect(req1.id).toBe('RULE-001');
      expect(req1.title).toBe('buffer/strcpy');
      expect(req1.descriptions[0].data).toContain('Does not check for buffer overflows');
      expect(req1.impact).toBe(0.7);
      expect(req1.tags.severity).toBe('error');
      expect(req1.tags.cwe).toContain('CWE-120');
      expect(req1.tags.cwe).toContain('CWE-20');
      expect(req1.tags.nist).toContain('SI-10');
      expect(req1.sourceLocation.ref).toBe('src/main.c');
      expect(req1.sourceLocation.line).toBe(42);
      expect(req1.results).toHaveLength(1);
      expect(req1.results[0].status).toBe('failed');
      expect(req1.results[0].codeDesc).toContain('src/main.c');
      expect(req1.results[0].codeDesc).toContain('LINE : 42');

      const req2 = result.baselines[0].requirements[1];
      expect(req2.id).toBe('RULE-002');
      expect(req2.title).toBe('format/printf');
      expect(req2.impact).toBe(0.5);
      expect(req2.tags.severity).toBe('warning');
      expect(req2.tags.cwe).toContain('CWE-134');
    });

    it('should handle empty results array', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'TestTool', version: '1.0.0' } },
          results: []
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines).toHaveLength(1);
      expect(result.baselines[0].requirements).toHaveLength(0);
    });

    it('should handle missing locations', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.sourceLocation).toBeUndefined();
      expect(req.results).toHaveLength(0);
    });
  });

  // --- Level resolution / impact tests ---

  describe('Impact mapping', () => {
    it('should map error level to 0.7', () => {
      const result = convertWithLevel('error');
      expect(result.baselines[0].requirements[0].impact).toBe(0.7);
    });

    it('should map warning level to 0.5', () => {
      const result = convertWithLevel('warning');
      expect(result.baselines[0].requirements[0].impact).toBe(0.5);
    });

    it('should map note level to 0.3', () => {
      const result = convertWithLevel('note');
      expect(result.baselines[0].requirements[0].impact).toBe(0.3);
    });

    it('should default to warning (0.5) for missing level', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].impact).toBe(0.5);
    });
  });

  describe('Level fallback to rule default', () => {
    it('should use rule defaultConfiguration.level when result level is absent', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.impact).toBe(0.7);
      expect(req.tags.severity).toBe('error');
    });
  });

  // --- CWE extraction priority tests ---

  describe('CWE extraction', () => {
    it('should extract CWE IDs from message text with commas', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-79');
      expect(cwes).toContain('CWE-89');
    });

    it('should extract CWE IDs from message text with !/', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toContain('CWE-119');
      expect(cwes).toContain('CWE-120');
    });

    it('should handle message with no CWE IDs', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].requirements[0].tags.cwe).toEqual([]);
    });

    it('should prefer CWE from rule relationships over message', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toEqual(['CWE-89']);
    });

    it('should fall back to CWE from properties.tags', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const cwes = result.baselines[0].requirements[0].tags.cwe;
      expect(cwes).toEqual(['CWE-798']);
    });

    it('should fall back to default NIST when no CWE anywhere', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const nist = result.baselines[0].requirements[0].tags.nist;
      expect(nist).toContain('SA-11');
      expect(nist).toContain('RA-5');
    });
  });

  // --- Message parsing tests ---

  describe('Message parsing', () => {
    it('should split title and description on first colon', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('buffer/strcpy');
      expect(req.descriptions[0].data).toBe('Does not check for buffer overflows (CWE-120).');
    });

    it('should handle message without colon', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('Simple message without colon');
      expect(req.descriptions[0].data).toBe('');
    });
  });

  // --- Multiple locations tests ---

  describe('Multiple locations', () => {
    it('should create one result per location', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
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

  describe('Kind to status mapping', () => {
    const kindTests = [
      { kind: 'pass', expectedStatus: 'passed', expectedImpact: 0.0 },
      { kind: 'fail', expectedStatus: 'failed', expectedImpact: 0.7 },
      { kind: undefined, expectedStatus: 'failed', expectedImpact: 0.7 },
      { kind: 'open', expectedStatus: 'failed', expectedImpact: 0.0 },
      { kind: 'review', expectedStatus: 'notReviewed', expectedImpact: 0.0 },
      { kind: 'informational', expectedStatus: 'notApplicable', expectedImpact: 0.0 },
      { kind: 'notApplicable', expectedStatus: 'notApplicable', expectedImpact: 0.0 },
    ];

    for (const tt of kindTests) {
      it(`should map kind="${tt.kind ?? 'undefined'}" to status=${tt.expectedStatus}`, () => {
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

        const result = JSON.parse(convertSarifToHdf(input));
        const req = result.baselines[0].requirements[0];
        expect(req.impact).toBe(tt.expectedImpact);
        expect(req.results).toHaveLength(1);
        expect(req.results[0].status).toBe(tt.expectedStatus);
      });
    }
  });

  // --- Suppression tests ---

  describe('Suppressions', () => {
    it('should mark accepted suppression as notReviewed', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('notReviewed');
      expect(req.results[0].message).toContain('false positive');
    });

    it('should keep failed status for rejected suppression', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].status).toBe('failed');
    });

    it('should store suppressions in tags', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
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

  describe('Rule metadata', () => {
    it('should use rule name as title when available', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
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

    it('should fall back to message parsing when rule has no name', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.title).toBe('category/name');
      expect(req.descriptions[0].data).toBe('Description here.');
    });

    it('should use tool name as baseline name', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'gosec', version: '2.18.2' } },
          results: []
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].name).toBe('gosec');
    });

    it('should fall back to SARIF when tool name is empty', () => {
      const input = JSON.stringify({
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: '', version: '1.0' } },
          results: []
        }]
      });

      const result = JSON.parse(convertSarifToHdf(input));
      expect(result.baselines[0].name).toBe('SARIF');
    });
  });

  // --- Fix tests ---

  describe('Fixes', () => {
    it('should add fix description when present', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      const fix = req.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix.data).toBe('Replace with safe alternative.');
    });

    it('should not add fix description when absent', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      const fix = req.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeUndefined();
    });
  });

  // --- Code flow / backtrace tests ---

  describe('Code flows', () => {
    it('should build backtrace from code flow', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      const bt = req.results[0].backtrace;
      expect(bt).toHaveLength(2);
      expect(bt[0]).toBe('source.go:10 - User input received');
      expect(bt[1]).toBe('sink.go:50 - Unsanitized use');
    });

    it('should have empty backtrace when no code flows', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].backtrace).toEqual([]);
    });
  });

  // --- Snippet tests ---

  describe('Snippets', () => {
    it('should include snippet in codeDesc when present', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].codeDesc).toContain('URL : file.go LINE : 42 COLUMN : 5');
      expect(req.results[0].codeDesc).toContain('db.Query(sql + input)');
    });

    it('should not include snippet when absent', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.results).toHaveLength(1);
      expect(req.results[0].codeDesc).toBe('URL : file.go LINE : 42 COLUMN : 5');
    });
  });

  // --- Fingerprint tests ---

  describe('Fingerprints', () => {
    it('should store fingerprints in tags', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.tags.fingerprints).toBeDefined();
      expect(req.tags.fingerprints.fingerprints.primaryLocationHash).toBe('abc123');
      expect(req.tags.fingerprints.partialFingerprints.lineHash).toBe('def456');
    });

    it('should not include fingerprints when absent', () => {
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

      const result = JSON.parse(convertSarifToHdf(input));
      const req = result.baselines[0].requirements[0];
      expect(req.tags.fingerprints).toBeUndefined();
    });
  });

  // --- Error handling ---

  describe('Error handling', () => {
    it('should error on invalid JSON', () => {
      expect(() => convertSarifToHdf('not valid json')).toThrow();
    });

    it('should error on missing runs', () => {
      const input = JSON.stringify({ version: '2.1.0' });
      expect(() => convertSarifToHdf(input)).toThrow('Invalid SARIF structure');
    });

    it('should error on non-array runs', () => {
      const input = JSON.stringify({ version: '2.1.0', runs: {} });
      expect(() => convertSarifToHdf(input)).toThrow('Invalid SARIF structure');
    });
  });

  // --- Integration tests with fixtures ---

  describe('Rich fixture integration', () => {
    it('should convert rich.sarif with all enriched fields', () => {
      const input = loadFixture('input', 'rich.sarif');
      const result = JSON.parse(convertSarifToHdf(input));

      expect(result.baselines).toHaveLength(1);
      const baseline = result.baselines[0];
      expect(baseline.name).toBe('SecurityScanner');
      expect(baseline.requirements).toHaveLength(10);

      // Result 0: SEC-001 fail with full metadata
      const r0 = baseline.requirements[0];
      expect(r0.id).toBe('SEC-001');
      expect(r0.title).toBe('SqlInjection');
      expect(r0.impact).toBe(0.7);
      expect(r0.results).toHaveLength(1);
      expect(r0.results[0].status).toBe('failed');
      expect(r0.results[0].codeDesc).toContain('db.Query');
      expect(r0.results[0].backtrace).toHaveLength(3);
      expect(r0.results[0].backtrace[0]).toContain('src/handlers/user.go:22');
      expect(r0.tags.cwe).toContain('CWE-89');
      expect(r0.tags.helpUri).toBe('https://example.com/rules/SEC-001');
      const fix = r0.descriptions.find((d: { label: string }) => d.label === 'fix');
      expect(fix).toBeDefined();
      expect(fix.data).toContain('parameterized query');
      expect(r0.tags.fingerprints).toBeDefined();

      // Result 1: SEC-002 with no level → falls back to rule default "warning"
      const r1 = baseline.requirements[1];
      expect(r1.id).toBe('SEC-002');
      expect(r1.title).toBe('WeakCrypto');
      expect(r1.impact).toBe(0.5);
      expect(r1.tags.severity).toBe('warning');

      // Result 2: SEC-003 with accepted suppression
      const r2 = baseline.requirements[2];
      expect(r2.results[0].status).toBe('notReviewed');
      expect(r2.results[0].message).toContain('test API key');

      // Result 3: SEC-003 with rejected suppression → still failed
      const r3 = baseline.requirements[3];
      expect(r3.results[0].status).toBe('failed');

      // Result 4: kind=pass
      const r4 = baseline.requirements[4];
      expect(r4.results[0].status).toBe('passed');
      expect(r4.impact).toBe(0.0);

      // Result 5: kind=notApplicable
      const r5 = baseline.requirements[5];
      expect(r5.results[0].status).toBe('notApplicable');

      // Result 6: kind=review
      const r6 = baseline.requirements[6];
      expect(r6.results[0].status).toBe('notReviewed');

      // Result 7: kind=informational
      const r7 = baseline.requirements[7];
      expect(r7.results[0].status).toBe('notApplicable');

      // Result 8: kind=open
      const r8 = baseline.requirements[8];
      expect(r8.results[0].status).toBe('failed');

      // Result 9: multiple suppressions
      const r9 = baseline.requirements[9];
      expect(r9.results[0].status).toBe('notReviewed');
    });
  });

  describe('Gosec fixture integration', () => {
    it('should convert gosec.sarif with CWE taxonomy', () => {
      const input = loadFixture('input', 'gosec.sarif');
      const result = JSON.parse(convertSarifToHdf(input));

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
});

// --- Helpers ---

function convertWithLevel(level: string) {
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

  return JSON.parse(convertSarifToHdf(input));
}
