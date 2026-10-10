import { spawnSync } from 'child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { beforeAll, describe, expect, it } from 'vitest';

const HERE = new URL('.', import.meta.url).pathname;
const PACKAGE = join(HERE, '..');
const OUT = join(PACKAGE, 'dist', 'downstream');
const GENERATED = join(OUT, 'zod.gen.ts');

// ADR-0008 §7: everything downstream of this package — the service's Zod, its routes'
// validators, and the generated client — comes from `@hey-api/openapi-ts` reading this
// document. That makes "the document is consumable" a property of THIS package, not a
// discovery for ADR-0011 to make. The run is the whole assertion: if the document grows a
// construct the generator warns on, the pipeline's input is no longer guaranteed.
interface Run {
  stdout: string;
  stderr: string;
  status: number | null;
}

/**
 * spawnSync, not execFileSync: the latter RETURNS stdout and discards stderr on success,
 * so asserting on a captured stderr would have been an assertion against a variable
 * nothing ever wrote.
 */
function generate(input: string, output: string): Run {
  const run = spawnSync(
    process.execPath,
    [
      join(PACKAGE, 'node_modules', '@hey-api', 'openapi-ts', 'bin', 'run.js'),
      '-i',
      input,
      '-o',
      output,
      '-p',
      'zod',
    ],
    { cwd: PACKAGE, encoding: 'utf-8' },
  );
  return { stdout: run.stdout ?? '', stderr: run.stderr ?? '', status: run.status };
}

let run: Run;

beforeAll(() => {
  rmSync(OUT, { recursive: true, force: true });
  // A bare relative input path is read as a Hey API registry shorthand, so the ./ matters.
  run = generate('./dist/hdf-api.oas.json', './dist/downstream');
}, 120_000);

describe('@hey-api/openapi-ts consumes the document without warnings', () => {
  it('emits the Zod module', () => {
    expect(existsSync(GENERATED), 'no zod.gen.ts was emitted').toBe(true);
    expect(readFileSync(GENERATED, 'utf-8').length).toBeGreaterThan(1000);
    expect(run.stdout.length, 'the run produced no output at all').toBeGreaterThan(0);
  });

  // This generator reports a warning on STDERR and still exits 0, so stderr is the only
  // surface that carries one. The first version also matched warning words in stdout,
  // which can never fire — and proved non-vacuity by showing stdout was captured, i.e. by
  // measuring the stream that cannot carry the signal.
  it('writes nothing to stderr', () => {
    expect(run.status, `generator exited ${run.status}: ${run.stderr}`).toBe(0);
    expect(run.stderr).toBe('');
  });

  // Which makes that assertion worth proving live: a document with one unresolvable $ref
  // is warned about on stderr, at exit 0, with a clean stdout. If stderr ever stopped
  // being captured, `expect(run.stderr).toBe('')` would pass on silence instead.
  it('does report on stderr when the document has an unresolvable $ref', () => {
    const planted = join(PACKAGE, 'dist', 'dangling.oas.json');
    const doc = JSON.parse(
      readFileSync(join(PACKAGE, 'dist', 'hdf-api.oas.json'), 'utf-8'),
    ) as Record<string, never>;
    const responses = doc.paths['/documents/{id}'].get.responses as Record<string, never>;
    responses['200'].content['application/json'] = {
      schema: { $ref: '#/components/schemas/DoesNotExist' },
    };
    writeFileSync(planted, JSON.stringify(doc));
    let planted_run: Run;
    try {
      planted_run = generate('./dist/dangling.oas.json', './dist/downstream-dangling');
    } finally {
      rmSync(planted, { force: true });
      rmSync(join(PACKAGE, 'dist', 'downstream-dangling'), { recursive: true, force: true });
    }
    expect(planted_run.status, 'the probe is only meaningful if it still exits 0').toBe(0);
    expect(planted_run.stderr).toMatch(/Skipping unresolvable \$ref/);
  }, 120_000);

  it('is pinned exactly, so a minor bump that changes its output is a reviewed change', () => {
    const pkg = JSON.parse(readFileSync(join(PACKAGE, 'package.json'), 'utf-8')) as {
      devDependencies: Record<string, string>;
      dependencies?: Record<string, string>;
    };
    const pinned = pkg.devDependencies['@hey-api/openapi-ts'];
    expect(pinned, '@hey-api/openapi-ts must be a devDependency').toBeDefined();
    expect(pinned, 'must be exact-pinned, not a range').toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dependencies?.['@hey-api/openapi-ts'], 'must not be a runtime dependency')
      .toBeUndefined();
  });
});

// The §7 claim is not just "it generates" but "the Zod it generates describes the same
// thing the document does". Parsing the document's own tracked examples with the emitted
// schemas is what connects the two.
describe('the emitted Zod parses the tracked examples', () => {
  interface Parser {
    safeParse: (value: unknown) => { success: boolean; error?: unknown };
  }
  const emitted = async (): Promise<Record<string, Parser>> =>
    (await import(GENERATED)) as unknown as Record<string, Parser>;

  const problemExamples = (): unknown[] => {
    const doc = JSON.parse(
      readFileSync(join(PACKAGE, 'dist', 'hdf-api.oas.json'), 'utf-8'),
    ) as Record<string, unknown>;
    const found: unknown[] = [];
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) {
        node.forEach(walk);
        return;
      }
      if (node === null || typeof node !== 'object') return;
      const object = node as Record<string, unknown>;
      const problem = object['application/problem+json'] as { example?: unknown } | undefined;
      if (problem?.example !== undefined) found.push(problem.example);
      Object.values(object).forEach(walk);
    };
    walk(doc);
    return found;
  };

  it('zProblem parses every problem example the document ships', async () => {
    const { zProblem } = await emitted();
    const examples = problemExamples();
    expect(examples.length, 'no problem examples found to parse').toBeGreaterThan(5);
    for (const example of examples) {
      const result = zProblem.safeParse(example);
      expect(result.success, `${JSON.stringify(example)} -> ${JSON.stringify(result.error)}`).toBe(
        true,
      );
    }
  });

  it('zHdfQueryResponse parses the envelope captured from the MCP', async () => {
    const { zHdfQueryResponse } = await emitted();
    const envelope = JSON.parse(
      readFileSync(join(HERE, 'fixtures', 'query-envelope.json'), 'utf-8'),
    ) as Record<string, unknown>;
    const result = zHdfQueryResponse.safeParse(envelope);
    expect(result.success, JSON.stringify(result.error)).toBe(true);
  });

  // Both schemas above would pass against a permissive stand-in, so each is shown to
  // reject something its shape forbids.
  it('rejects a problem whose status is not an integer', async () => {
    const { zProblem } = await emitted();
    const [first] = problemExamples() as Record<string, unknown>[];
    expect(zProblem.safeParse({ ...first, status: 'four-oh-four' }).success).toBe(false);
  });

  it('rejects an envelope whose limit exceeds the declared maximum', async () => {
    const { zHdfQueryResponse } = await emitted();
    const envelope = JSON.parse(
      readFileSync(join(HERE, 'fixtures', 'query-envelope.json'), 'utf-8'),
    ) as Record<string, unknown>;
    expect(zHdfQueryResponse.safeParse({ ...envelope, limit: 1001 }).success).toBe(false);
  });

  it('rejects an envelope whose rows are not requirement shapes', async () => {
    const { zHdfQueryResponse } = await emitted();
    expect(zHdfQueryResponse.safeParse({ requirements: [{ nope: true }] }).success).toBe(false);
  });
});
