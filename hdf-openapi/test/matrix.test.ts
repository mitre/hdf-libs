// The tooling matrix as a TEST, not only as a script.
//
// `scripts/openapi-matrix.mjs` measures everything including oapi-codegen, which is a Go
// binary and therefore cannot be a precondition of `pnpm test` or the pre-commit hook. But
// a baseline that nothing runs rots silently, so the npm-resolvable half of the same
// measurement — both lints and openapi-typescript — runs here, from the same code path, and
// reaches CI through `pnpm -r run test:ts`. The oapi-codegen half stays in the script.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  BASELINE,
  NPM_GENERATORS,
  compareToBaseline,
  countKeywords,
  composeMeasurement,
  measureCodegen,
  measureLint,
  lintGate,
  measure,
  readBaseline,
  runCli,
  serialise,
  stableError,
  tally,
  toolVersion,
  unwaived,
  withoutKeyword,
} from '../scripts/openapi-matrix.mjs';
import { main as generateComponentsDocument } from '../src/generate-components.js';

// The matrix measures a BUILD ARTIFACT — dist/hdf-components.oas.json — and the suite is
// run by `pnpm -r run test:ts`, which runs vitest and not `build:components`. So generate
// it here, at module scope: the measurement happens during collection, which is before any
// beforeAll would fire. Unconditional rather than if-missing, so the suite behaves the same
// on a fresh clone as on a tree that has been built. This does not weaken anything — the
// generator is deterministic from the tracked embed, and components.test.ts is what
// verifies its output.
generateComponentsDocument();

const tracked = JSON.parse(readFileSync(BASELINE, 'utf8')) as Record<string, any>;

/** Whether the Go generator can be measured here, as opposed to only in CI. */
function oapiCodegenAvailable(): boolean {
  try {
    execFileSync(process.env.OAPI_CODEGEN ?? 'oapi-codegen', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// Two lint runs each plus one generation per tracked keyword; well past vitest's default.
const TIMEOUT = 180_000;

describe('the tracked baseline still describes what the tooling does', () => {
  // Measured once: `measure` shells out to four CLIs and is far too slow to repeat per
  // assertion.
  const measured = measure(NPM_GENERATORS) as Record<string, any>;

  it('reports zero lint findings at every severity, under the tracked config', () => {
    expect(measured.lint.redocly.tracked.bySeverity).toEqual({
      error: 0,
      warn: 0,
      info: 0,
      hint: 0,
    });
  }, TIMEOUT);

  it('absorbs exactly the waived findings the baseline records', () => {
    expect(measured.lint.redocly.waiverAbsorbs).toEqual(tracked.lint.redocly.waiverAbsorbs);
  }, TIMEOUT);

  it('uses exactly the keywords the baseline records, at the recorded counts', () => {
    expect(measured.keywordCounts).toEqual(tracked.keywordCounts);
  }, TIMEOUT);

  it('agrees with the baseline on every openapi-typescript keyword verdict', () => {
    const expected = Object.fromEntries(
      Object.entries(tracked.codegen.keywords as Record<string, Record<string, string>>).map(
        ([keyword, verdicts]) => [keyword, { 'openapi-typescript': verdicts['openapi-typescript'] }],
      ),
    );
    expect(measured.codegen.keywords).toEqual(expected);
  }, TIMEOUT);

  it('agrees that openapi-typescript consumes the whole document', () => {
    expect(measured.codegen.document['openapi-typescript']).toEqual({ consumes: true });
  }, TIMEOUT);
});

describe('the oapi-codegen half of the baseline is gated too', () => {
  // Reading the baseline and comparing it to a literal in the test would be
  // self-consistent by construction: it pins the recorded value against an accidental
  // edit, but cannot notice that oapi-codegen's real behaviour changed. So the Go half is
  // measured for real where the binary is available, and where it is not, what gets
  // asserted is that CI measures it — because an ungated baseline is the actual risk, and
  // a skip would hide exactly that.
  const goGenerator = oapiCodegenAvailable();

  it.runIf(goGenerator)('re-measures BOTH generators and matches the baseline exactly', () => {
    // The whole serialised document, not a subset: this also pins the recorded tool
    // versions and the oapi-codegen refusal, which the npm-only comparison cannot reach.
    expect(serialise(measure())).toBe(readFileSync(BASELINE, 'utf8'));
  }, TIMEOUT);

  it('is run by CI, with the generator installed at the version the baseline records', () => {
    const workflow = readFileSync(join(import.meta.dirname, '..', '..', '.github', 'workflows', 'ci.yml'), 'utf8');
    // A job that runs the matrix...
    expect(workflow).toContain('run matrix');
    // ...with the Go toolchain and the pinned generator...
    expect(workflow).toContain('cmd/oapi-codegen@$OAPI_CODEGEN_VERSION');
    const pinned = /OAPI_CODEGEN_VERSION: 'v([\d.]+)'/.exec(workflow)?.[1];
    expect(pinned, 'CI must pin the generator version').toBeDefined();
    // ...at the version these verdicts were measured against. A CI bump without a
    // re-measurement would gate the new tool against the old record.
    expect(tracked.tools['oapi-codegen']).toBe(pinned);
    // ...and a job nothing depends on cannot fail the build, so assert it is gated.
    expect(workflow).toContain('check-openapi-matrix, scan-deps');
  });
});

describe('the measurement helpers', () => {
  it('redacts a Windows path too, since matrix:update can be run there', () => {
    const redacted = stableError(
      'error loading spec in D:\\a\\hdf-libs\\hdf-libs\\hdf-openapi\\dist\\doc.oas.json : failed to unmarshal bool',
    );
    expect(redacted).not.toMatch(/[A-Za-z]:\\/);
    expect(redacted).toContain('<document>');
    expect(redacted).toContain('failed to unmarshal bool');
  });

  it('redacts absolute paths from a recorded tool error', () => {
    const redacted = stableError(
      '[WARN] noise\nerror loading spec in /Users/someone/work/repo/pkg/dist/doc.oas.json\n' +
        ': failed to unmarshal /home/other/cfg.yaml',
    );
    expect(redacted).not.toMatch(/\/Users\/|\/home\//);
    expect(redacted).toContain('<document>');
    // The cause must survive the redaction, or the baseline records nothing useful.
    expect(redacted).toContain('failed to unmarshal');
    // And the [WARN] lines the CLIs emit about an unreadable npmrc must not be recorded.
    expect(redacted).not.toContain('noise');
  });

  it('counts a keyword use but not a property that happens to share its name', () => {
    const counts = countKeywords({
      Thing: {
        type: 'object',
        properties: {
          // Author-chosen names that collide with keyword names. HDF really has these,
          // and counting them inflated `type` by 25 and `description` by 18.
          type: { type: 'string' },
          description: { type: 'string' },
          format: { type: 'string' },
        },
      },
    });
    // `Thing.type` plus the three property schemas' own `type` — not the three NAMES.
    expect(counts.type).toBe(4);
    expect(counts.description).toBeUndefined();
    expect(counts.format).toBeUndefined();
    expect(counts.properties).toBe(1);
  });

  it('does not count keys inside an example as keyword uses', () => {
    const counts = countKeywords({
      Thing: {
        type: 'string',
        examples: [{ type: 'x', format: 'y', properties: { nested: 'z' } }],
      },
    });
    expect(counts.type).toBe(1);
    expect(counts.format).toBeUndefined();
    expect(counts.properties).toBeUndefined();
  });

  it('strips a keyword from the schemas only, leaving the Info Object intact', () => {
    const doc = {
      openapi: '3.1.1',
      info: { title: 'kept', version: '1.0.0', description: 'kept' },
      components: { schemas: { A: { title: 'gone', type: 'object' } } },
    };
    const stripped = withoutKeyword(doc, 'title') as typeof doc;
    // Without this scoping, removing `title` invalidates the document and the generator's
    // refusal reads as a keyword limitation rather than the probe's own fault.
    expect(stripped.info.title).toBe('kept');
    expect(stripped.components.schemas.A).toEqual({ type: 'object' });
  });
});

describe('the measurement is split so the lint gate can short-circuit', () => {
  it('measures lint without touching codegen', () => {
    const lintPart = measureLint() as Record<string, unknown>;
    expect(Object.keys(lintPart)).toEqual(['tools', 'keywordCounts', 'lint']);
    // The absence is the point: if this half carried codegen, measuring it would run the
    // probes that a broken lint config takes down, and the gate's message would be lost.
    expect(lintPart).not.toHaveProperty('codegen');
  }, TIMEOUT);

  it('composes the two halves into the baseline\'s exact key order', () => {
    const composed = composeMeasurement(
      { tools: { a: '1' }, keywordCounts: { type: 1 }, lint: { redocly: {} } },
      { tools: { b: '2' }, codegen: { document: {}, keywords: {} } },
    ) as Record<string, unknown>;
    // Guards the committed file: a reordering here would rewrite every line of the
    // baseline and read as tooling drift.
    expect(Object.keys(composed)).toEqual(Object.keys(tracked));
    expect(composed.tools).toEqual({ a: '1', b: '2' });
  });
});

describe('the gate logic', () => {
  /** A measurement shaped like the real one, small enough to reason about. */
  const sample = (overrides: Record<string, unknown> = {}) => ({
    tools: { 'openapi-typescript': '7.13.0' },
    keywordCounts: { type: 1 },
    lint: {
      redocly: { tracked: { bySeverity: { error: 0, warn: 0, info: 0, hint: 0 }, byRule: {} }, waiverAbsorbs: {} },
    },
    codegen: { document: {}, keywords: {} },
    ...overrides,
  });

  it('passes the lint gate when both linters report zero errors', () => {
    expect(lintGate(sample())).toEqual([]);
  });

  it('fails the lint gate per offending linter, naming the rules', () => {
    const failures = lintGate(
      sample({
        lint: {
          redocly: {
            tracked: { bySeverity: { error: 2, warn: 0, info: 0, hint: 0 }, byRule: { 'no-empty-servers': 2 } },
            waiverAbsorbs: {},
          },
        },
      }),
    );
    expect(failures).toHaveLength(1);
    expect(failures[0]).toContain('redocly reports 2 error(s)');
    // The rule must be named, or the failure says nothing actionable.
    expect(failures[0]).toContain('no-empty-servers');
  });

  it('reports a match when the measurement equals the tracked text', () => {
    const measured = sample();
    const result = compareToBaseline(measured, serialise(measured));
    expect(result.ok).toBe(true);
    expect(result.report).toContain('matches the baseline');
  });

  it('reports every differing line, baseline against measured', () => {
    const measured = sample();
    const stale = serialise(sample({ keywordCounts: { type: 99 } }));
    const result = compareToBaseline(measured, stale);
    expect(result.ok).toBe(false);
    expect(result.report).toContain('"type": 99');
    expect(result.report).toContain('"type": 1');
    // And it must point at the deliberate way to accept a real change.
    expect(result.report).toContain('matrix:update');
  });

  it('marks a line absent when the two differ in length', () => {
    const measured = sample();
    const truncated = serialise(measured).split('\n').slice(0, 3).join('\n');
    const result = compareToBaseline(measured, truncated);
    expect(result.ok).toBe(false);
    expect(result.report).toContain('<absent>');
  });

  it('refuses rather than silently passing when no baseline is recorded', () => {
    const result = compareToBaseline(sample(), null);
    expect(result.ok).toBe(false);
    expect(result.report).toContain('no baseline recorded');
  });

  it('serialises with a trailing newline, so the committed file is diff-clean', () => {
    expect(serialise(sample())).toMatch(/}\n$/);
  });
});

describe('the CLI', () => {
  const cleanLint = () => ({
    tools: {},
    keywordCounts: {},
    lint: {
      redocly: { tracked: { bySeverity: { error: 0, warn: 0, info: 0, hint: 0 }, byRule: {} }, waiverAbsorbs: {} },
    },
  });
  const cleanCodegen = () => ({ tools: {}, codegen: { document: {}, keywords: {} } });
  // Composed through the production function, so a sample that drifted from the real
  // shape would fail here rather than quietly testing a shape nothing emits.
  const clean = () => composeMeasurement(cleanLint(), cleanCodegen());

  /** Collects what the CLI wrote, so the exit code is not the only thing asserted. */
  const capture = () => {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, io: { out: (t: string) => out.push(t), err: (t: string) => err.push(t) } };
  };

  it('exits 0 and says so when the measurement matches', () => {
    const measured = clean();
    const { out, io } = capture();
    const code = runCli([], {
      ...io,
      measureLint: cleanLint,
      measureCodegen: cleanCodegen,
      readTracked: () => serialise(measured),
    });
    expect(code).toBe(0);
    expect(out.join('')).toContain('matches the baseline');
  });

  it('exits 1 on drift and writes the report to stderr, not stdout', () => {
    const { out, err, io } = capture();
    const code = runCli([], {
      ...io,
      measureLint: cleanLint,
      measureCodegen: cleanCodegen,
      readTracked: () => serialise({ ...clean(), keywordCounts: { type: 7 } }),
    });
    expect(code).toBe(1);
    expect(err.join('')).toContain('differs from the baseline');
    expect(out.join('')).toBe('');
  });

  it('exits 1 on a lint error WITHOUT running the codegen probes', () => {
    // The codegen probes cost ~16s and read redocly.yaml themselves, so a lint
    // misconfiguration used to kill the run inside the keyword probe with openapi-
    // typescript's own stack trace — never reaching the gate's message.
    const { out, err, io } = capture();
    let codegenRan = false;
    const code = runCli([], {
      ...io,
      measureLint: () => ({
        tools: { '@redocly/cli': '2.54.3' },
        keywordCounts: {},
        lint: {
          redocly: {
            tracked: { bySeverity: { error: 3, warn: 0, info: 0, hint: 0 }, byRule: { 'no-empty-servers': 3 } },
            waiverAbsorbs: {},
          },
        },
      }),
      measureCodegen: () => {
        codegenRan = true;
        return { tools: {}, codegen: { document: {}, keywords: {} } };
      },
      readTracked: () => null,
    });
    expect(code).toBe(1);
    expect(codegenRan, 'the codegen probes must not run once the lint gate has failed').toBe(false);
    expect(err.join('')).toContain('lint gate failed');
    expect(err.join('')).toContain('no-empty-servers');
    expect(out.join('')).toBe('');
  });

  it('exits 1 on a lint error WITHOUT consulting the baseline', () => {
    const { err, io } = capture();
    let consulted = false;
    const code = runCli([], {
      ...io,
      measureLint: () => ({
        ...cleanLint(),
        lint: {
          redocly: {
            tracked: { bySeverity: { error: 1, warn: 0, info: 0, hint: 0 }, byRule: { 'no-empty-servers': 1 } },
            waiverAbsorbs: {},
          },
        },
      }),
      measureCodegen: cleanCodegen,
      readTracked: () => {
        consulted = true;
        return null;
      },
    });
    expect(code).toBe(1);
    expect(err.join('')).toContain('lint gate failed');
    // A lint error is not something a baseline can bless, so the comparison must not run.
    expect(consulted).toBe(false);
  });

  it('--update records the measurement and never compares', () => {
    const { out, io } = capture();
    let written: string | null = null;
    const code = runCli(['--update'], {
      ...io,
      measureLint: cleanLint,
      measureCodegen: cleanCodegen,
      readTracked: () => {
        throw new Error('--update must not read the baseline');
      },
      writeTracked: (text: string) => {
        written = text;
      },
    });
    expect(code).toBe(0);
    expect(written).toBe(serialise(clean()));
    expect(out.join('')).toContain('baseline recorded');
  });
});

describe('the measurement preconditions', () => {
  it('refuses a missing tool with the pinned install command, rather than skipping it', () => {
    expect(() => toolVersion('definitely-not-a-real-binary-xyz', ['--version'], 'oapi-codegen')).toThrow(
      /go install github\.com\/oapi-codegen/,
    );
  });

  it('reports the raw output for a non-Go tool, which has no install command to suggest', () => {
    expect(() => toolVersion('definitely-not-a-real-binary-xyz', ['--version'], 'redocly')).toThrow(
      /could not read a version from redocly/,
    );
  });

  it('refuses an unknown generator name', () => {
    expect(() => measureCodegen(['not-a-generator'])).toThrow(/unknown generator not-a-generator/);
  });

  it('strips every waiver from a config while keeping its ruleset base', async () => {
    // Load-bearing for the whole waiverAbsorbs claim: if this failed to strip, the
    // "unwaived" run would report zero and every waiver would look like it absorbs nothing.
    const { mkdtempSync, readFileSync: read, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const { parse } = await import('yaml');
    const scratch = mkdtempSync(join(tmpdir(), 'matrix-test-'));
    try {
      const out = unwaived(join(import.meta.dirname, '..', 'redocly.yaml'), scratch, 'probe.yaml');
      const config = parse(read(out, 'utf8')) as Record<string, unknown>;
      expect(config.extends).toEqual(['recommended']);
      expect(config.rules).toBeUndefined();
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});

describe('the CLI\'s real default effects', () => {
  // The injected-effect tests above substitute all three defaults, which leaves the real
  // ones unrun — including the one that writes the committed file. Pointing baselinePath at
  // a temporary file exercises them for real instead.
  const cleanLint = () => ({
    tools: {},
    keywordCounts: {},
    lint: {
      redocly: { tracked: { bySeverity: { error: 0, warn: 0, info: 0, hint: 0 }, byRule: {} }, waiverAbsorbs: {} },
    },
  });
  const cleanCodegen = () => ({ tools: {}, codegen: { document: {}, keywords: {} } });
  const clean = () => composeMeasurement(cleanLint(), cleanCodegen());

  it('writes, then reads back, then compares clean — through the defaults', () => {
    const scratch = mkdtempSync(join(tmpdir(), 'matrix-cli-'));
    try {
      const baselinePath = join(scratch, 'keywords.json');
      // --update with no writeTracked and no out: the real default must create the file.
      expect(runCli(['--update'], { baselinePath, measureLint: cleanLint, measureCodegen: cleanCodegen })).toBe(0);
      expect(JSON.parse(readFileSync(baselinePath, 'utf8'))).toEqual(clean());
      // A second run with no readTracked: the real default must read what was just written.
      expect(runCli([], { baselinePath, measureLint: cleanLint, measureCodegen: cleanCodegen })).toBe(0);
      // And the real default `err` must report a failure. Driven through the absent-baseline
      // path rather than a drift, whose report would dump the whole document to stderr on
      // every test run.
      expect(
        runCli([], {
          baselinePath: join(scratch, 'absent.json'),
          measureLint: cleanLint,
          measureCodegen: cleanCodegen,
        }),
      ).toBe(1);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it('treats an unreadable baseline as absent rather than throwing', () => {
    expect(readBaseline(join(tmpdir(), 'no-such-matrix-baseline-xyz.json'))).toBeNull();
  });
});

describe('the tallies are defensive about shapes they did not expect', () => {
  it('labels an unrecognised severity rather than dropping the finding', () => {
    // A linter adding a severity must not make findings vanish from the counts.
    const counted = tally(
      [{ sev: 'catastrophe', rule: 'r' }],
      (p: { sev: string }) => p.sev,
      (p: { rule: string }) => p.rule,
    ) as { bySeverity: Record<string, number>; byRule: Record<string, number> };
    expect(counted.bySeverity.catastrophe).toBe(1);
    expect(counted.byRule.r).toBe(1);
  });

  it('treats an absent error count as zero', () => {
    const failures = lintGate({
      lint: {
        redocly: { tracked: { bySeverity: {}, byRule: {} } },
      },
    });
    expect(failures).toEqual([]);
  });
});
