#!/usr/bin/env node
/**
 * Measures what real tooling does with the generated components document and compares the
 * result to the tracked baseline in test/baseline/keywords.json. Exits non-zero on any
 * difference; `--update` rewrites the baseline instead.
 *
 * Four things are measured, and the reason each is here:
 *
 *   keywordCounts    Which JSON Schema keywords the document actually uses. A schema
 *                    change that introduces a keyword no tool in the matrix supports
 *                    should be visible as a baseline diff, not discovered by a consumer.
 *
 *   lint             Redocly under the tracked config, which must report zero findings at
 *                    every severity — AND the per-rule counts its waivers are absorbing,
 *                    obtained by re-running with every waiver stripped. Without that second
 *                    run a waiver could silently grow to cover a new finding; with it, the
 *                    growth is a failing diff.
 *
 *                    Spectral and the OWASP API Security ruleset are deferred to Phase 2
 *                    (ADR-0008 §5 still names both; the correction is carded): its CLI is
 *                    the only carrier of an unpatchable
 *                    braces advisory, and on a components document all 735 of its OWASP
 *                    findings are request-surface rules that do not apply. Phase 2's API
 *                    document is where they have something to say.
 *
 *   codegen.document Whether each generator can consume the whole document at all. This is
 *                    not a formality: oapi-codegen cannot, and recording the refusal with
 *                    its trigger is the honest statement of the compatibility claim.
 *
 *   codegen.keywords Per keyword, whether a generator's output DEPENDS on it. Measured
 *                    differentially — generate from a probe schema carrying the keyword,
 *                    generate again with that one keyword deleted, compare the bytes.
 *                    Different output means the keyword reached the artifact (honored);
 *                    identical output means the generator discarded it (ignored). This is
 *                    a measurement, not a reading of anybody's documentation.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = join(HERE, '..');
const DOC = join(PKG, 'dist', 'hdf-components.oas.json');
const BASELINE = join(PKG, 'test', 'baseline', 'keywords.json');
/**
 * A tool's JS entry point, resolved from its own package.json `bin` field.
 *
 * Spawned as `node <entry>` rather than through `node_modules/.bin/<name>`, because that
 * shim is not portable: on Windows the executable is `<name>.CMD` and the extensionless
 * file is a Bash script, so `execFileSync` fails with ENOENT. Running the entry with the
 * current Node binary needs no shim and no shell — the same pattern site/seed-archive.mjs
 * already uses. package.json is read by path rather than resolved, so an `exports` map
 * that does not publish ./package.json cannot block it.
 */
function toolEntry(pkg, binName) {
  const dir = join(PKG, 'node_modules', pkg);
  const { bin } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const relative = typeof bin === 'string' ? bin : bin[binName];
  if (relative === undefined) {
    throw new Error(`${pkg} declares no bin named ${binName}`);
  }
  return join(dir, relative);
}

const REDOCLY = () => toolEntry('@redocly/cli', 'redocly');
const OPENAPI_TS = () => toolEntry('openapi-typescript', 'openapi-typescript');

/** oapi-codegen is a Go binary, so it is not in node_modules. */
const OAPI = process.env.OAPI_CODEGEN ?? 'oapi-codegen';
const OAPI_INSTALL =
  'go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0';

/** Redocly's severities, in the order a report lists them. */
const SEVERITY = ['error', 'warn', 'info', 'hint'];

/** The keywords whose tooling support this baseline tracks. */
const TRACKED_KEYWORDS = [
  '$comment', '$ref', 'additionalProperties', 'allOf', 'anyOf', 'const', 'contains',
  'contentEncoding', 'dependentRequired', 'description', 'else', 'enum', 'examples',
  'format', 'if', 'items', 'maximum', 'minItems', 'minLength', 'minimum', 'not', 'oneOf',
  'pattern', 'properties', 'required', 'then', 'title', 'type', 'unevaluatedProperties',
];

function run(file, args, cwd) {
  try {
    const stdout = execFileSync(file, args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, REDOCLY_TELEMETRY: 'off' },
      maxBuffer: 64 * 1024 * 1024,
    });
    return { ok: true, stdout, stderr: '' };
  } catch (error) {
    return {
      ok: false,
      stdout: error.stdout?.toString() ?? '',
      stderr: error.stderr?.toString() ?? String(error.message ?? error),
    };
  }
}

export function toolVersion(file, args, label) {
  const result = run(file, args);
  const text = `${result.stdout}${result.stderr}`;
  const match = /\d+\.\d+\.\d+(?:-[\w.]+)?/.exec(text);
  if (!match) {
    throw new Error(
      `could not read a version from ${label}. ` +
        (label === 'oapi-codegen'
          ? `Install the pinned build with:\n  ${OAPI_INSTALL}\nor point OAPI_CODEGEN at it.`
          : `Output was: ${text.slice(0, 200)}`),
    );
  }
  return match[0];
}

// ---------------------------------------------------------------------------
// Keyword inventory

/**
 * Keywords whose VALUE is a map from names to subschemas. The names in such a map are
 * author-chosen, so a property called `type` or `description` is not a keyword use — and
 * HDF has several. Counting them inflated `type` by 25 and `description` by 18.
 */
const SCHEMA_MAPS = ['properties', '$defs', 'patternProperties', 'dependentSchemas'];

/**
 * Counts keyword USES, distinguishing a schema object from a map of author-named
 * subschemas and from example data. Both distinctions are load-bearing: without the first
 * a property named `format` is tallied as the `format` keyword, and without the second any
 * key inside an example is.
 */
export function countKeywords(schemas) {
  const counts = {};
  /** @param {unknown} node @param {boolean} isSchema whether node is a schema, not a map of them */
  const walk = (node, isSchema) => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item, isSchema);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node)) {
      if (isSchema) {
        if (TRACKED_KEYWORDS.includes(key)) counts[key] = (counts[key] ?? 0) + 1;
        if (key === 'examples') continue;
        walk(value, !SCHEMA_MAPS.includes(key));
      } else {
        // A map of named subschemas: the name is not a keyword, the value is a schema.
        walk(value, true);
      }
    }
  };
  // The top level is `components.schemas` — itself a map of named schemas.
  walk(schemas, false);
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

// ---------------------------------------------------------------------------
// Lint

export function tally(problems, severityOf, ruleOf) {
  // Seeded with explicit zeros: an empty object would leave "no errors" and "never
  // measured" indistinguishable in the tracked baseline.
  const bySeverity = Object.fromEntries(SEVERITY.map((name) => [name, 0]));
  // Every severity, not just error/warn: a waived rule that reports at info or hint would
  // otherwise absorb findings that never appear in waiverAbsorbs, which is exactly the
  // silent growth the tracked counts exist to prevent.
  const byRule = {};
  for (const problem of problems) {
    const severity = severityOf(problem);
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
    byRule[ruleOf(problem)] = (byRule[ruleOf(problem)] ?? 0) + 1;
  }
  return { bySeverity, byRule };
}

function sortCounts(counts) {
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

/** Strips every waiver from a tracked config, leaving the same ruleset base. */
export function unwaived(configPath, scratch, name) {
  const config = parseYaml(readFileSync(configPath, 'utf8'));
  delete config.rules;
  delete config.overrides;
  const out = join(scratch, name);
  writeFileSync(out, stringifyYaml(config));
  return out;
}

function redoclyLint(configPath) {
  const result = run(process.execPath, [
    REDOCLY(),
    'lint', DOC, '--config', configPath, '--format', 'json', '--max-problems', '100000',
  ], PKG);
  if (!result.stdout.trim()) {
    throw new Error(`redocly produced no JSON. stderr:\n${result.stderr.slice(0, 1500)}`);
  }
  const parsed = JSON.parse(result.stdout);
  return tally(parsed.problems ?? [], (p) => p.severity, (p) => p.ruleId);
}

// ---------------------------------------------------------------------------
// Codegen

function generateTs(docPath, scratch, tag) {
  const out = join(scratch, `${tag}.d.ts`);
  const result = run(process.execPath, [OPENAPI_TS(), docPath, '-o', out], PKG);
  if (!result.ok) return { ok: false, detail: result.stderr };
  return { ok: true, output: readFileSync(out, 'utf8') };
}

function generateGo(docPath, scratch, tag) {
  const out = join(scratch, `${tag}.gen.go`);
  const config = join(scratch, `${tag}.cfg.yaml`);
  writeFileSync(
    config,
    // skip-prune is REQUIRED, not a preference: oapi-codegen drops components that no
    // operation references, and this document has no operations. Without it every probe
    // emits an identical header-only file and every keyword reads as "ignored".
    stringifyYaml({
      package: 'probe',
      output: out,
      generate: { models: true },
      'output-options': { 'skip-prune': true },
    }),
  );
  const result = run(OAPI, ['-config', config, docPath], PKG);
  if (!result.ok) return { ok: false, detail: result.stderr };
  return { ok: true, output: readFileSync(out, 'utf8') };
}

const GENERATORS = { 'openapi-typescript': generateTs, 'oapi-codegen': generateGo };

/** Generators installed by pnpm, so reachable without a Go toolchain. */
export const NPM_GENERATORS = ['openapi-typescript'];

/**
 * Reduces a multi-line tool error to a stable one-line cause. Absolute paths are removed:
 * this string is committed, and a contributor's home directory must not be.
 */
function stableError(text) {
  const lines = text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('[WARN]'));
  return lines
    .join(' ')
    // Both separators: this is the only thing standing between a contributor's home
    // directory and the committed baseline, and `matrix:update` can be run on Windows.
    .replace(/(?:[A-Za-z]:)?[\\/](?:[\w.@-]+[\\/])+[\w.@-]+\.(?:json|ya?ml)/g, '<document>')
    .replaceAll(PKG, '<package>')
    .slice(0, 400);
}

export function documentSupport(scratch, generators) {
  const support = {};
  for (const [name, generate] of generators) {
    const result = generate(DOC, scratch, `doc-${name}`);
    support[name] = result.ok
      ? { consumes: true }
      : { consumes: false, error: stableError(result.detail) };
  }
  return support;
}

/**
 * A probe document exercising every tracked keyword at once. Each keyword is measured by
 * deleting it from this document and regenerating, so the surrounding context is identical
 * across the two runs and the only difference is the keyword under test.
 */
function probeDocument() {
  return {
    openapi: '3.1.1',
    info: { title: 'keyword probe', version: '1.0.0' },
    jsonSchemaDialect: 'https://json-schema.org/draft/2020-12/schema',
    paths: {},
    components: {
      schemas: {
        Target: {
          type: 'object',
          title: 'Target',
          description: 'probe subject',
          $comment: 'probe',
          required: ['name'],
          unevaluatedProperties: false,
          additionalProperties: true,
          dependentRequired: { kind: ['name'] },
          properties: {
            name: { type: 'string', minLength: 1, pattern: '^[a-z]+$' },
            kind: { type: 'string', enum: ['a', 'b'] },
            marker: { const: 'fixed' },
            when: { type: 'string', format: 'date-time' },
            score: { type: 'number', minimum: 0, maximum: 1 },
            tags: { type: 'array', items: { type: 'string' }, minItems: 1, contains: { type: 'string' } },
            blob: { type: 'string', contentEncoding: 'base64' },
            nested: { $ref: '#/components/schemas/Aux' },
            either: { anyOf: [{ type: 'string' }, { type: 'integer' }] },
            exactly: { oneOf: [{ type: 'string' }, { type: 'integer' }] },
            merged: { allOf: [{ type: 'object' }] },
            never: { not: { type: 'string' } },
          },
          examples: [{ name: 'abc', kind: 'a', when: '2026-01-01T00:00:00Z' }],
          if: { required: ['kind'] },
          then: { required: ['when'] },
          else: { required: ['score'] },
        },
        Aux: { type: 'object', properties: { id: { type: 'string' } } },
      },
    },
  };
}

/**
 * Deletes every occurrence of one keyword from the SCHEMAS ONLY, leaving the rest of the
 * document intact. Scoping matters: `title` and `description` are also Info Object fields,
 * and stripping them document-wide produces an invalid OpenAPI document, which reads as a
 * tool limitation rather than the probe's own fault.
 */
function withoutKeyword(document, keyword) {
  const strip = (node) => {
    if (Array.isArray(node)) return node.map(strip);
    if (node === null || typeof node !== 'object') return node;
    const out = {};
    for (const [key, value] of Object.entries(node)) {
      if (key === keyword) continue;
      out[key] = strip(value);
    }
    return out;
  };
  return {
    ...document,
    components: { schemas: strip(document.components.schemas) },
  };
}

export function keywordSupport(scratch, generators) {
  const base = probeDocument();
  const basePath = join(scratch, 'probe-base.json');
  writeFileSync(basePath, JSON.stringify(base, null, 2));

  const support = {};
  for (const [name, generate] of generators) {
    const reference = generate(basePath, scratch, `probe-base-${name}`);
    if (!reference.ok) {
      throw new Error(
        `${name} could not generate from the keyword probe, so no keyword can be measured ` +
          `against it. Error:\n${reference.detail.slice(0, 800)}`,
      );
    }
    for (const keyword of TRACKED_KEYWORDS) {
      const variantPath = join(scratch, `probe-no-${keyword.replace(/\W/g, '_')}.json`);
      writeFileSync(variantPath, JSON.stringify(withoutKeyword(base, keyword), null, 2));
      const variant = generate(variantPath, scratch, `probe-${name}-${keyword.replace(/\W/g, '_')}`);
      support[keyword] ??= {};
      support[keyword][name] = !variant.ok
        ? 'load-error'
        : variant.output === reference.output
          ? 'ignored'
          : 'honored';
    }
  }
  return Object.fromEntries(
    TRACKED_KEYWORDS.map((keyword) => [keyword, support[keyword]]),
  );
}

export { stableError, withoutKeyword, BASELINE };

// ---------------------------------------------------------------------------

/** Runs `fn` with a scratch directory that is always cleaned up. */
function withScratch(fn) {
  const scratch = mkdtempSync(join(tmpdir(), 'hdf-openapi-matrix-'));
  try {
    return fn(scratch);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function resolveGenerators(only) {
  const names = only ?? Object.keys(GENERATORS);
  return names.map((name) => {
    if (!(name in GENERATORS)) throw new Error(`unknown generator ${name}`);
    return [name, GENERATORS[name]];
  });
}

/**
 * The lint half: keyword inventory plus Redocly under the tracked config and again with
 * every waiver stripped.
 *
 * Separate from the codegen half so the CLI can gate on it FIRST. The codegen probes read
 * `redocly.yaml` themselves — openapi-typescript validates through Redocly's core — so a
 * lint misconfiguration takes them out too, and measuring them first meant the run died in
 * the keyword probe with openapi-typescript's stack trace instead of the gate's message.
 */
export function measureLint() {
  return withScratch((scratch) => {
    if (!existsSync(DOC)) {
      // The subject is a build artifact, and a bare ENOENT does not say so.
      throw new Error(
        `no components document at ${DOC}\nRun \`pnpm run build:components\` first.`,
      );
    }
    const document = JSON.parse(readFileSync(DOC, 'utf8'));
    const redoclyConfig = join(PKG, 'redocly.yaml');
    return {
      tools: {
        '@redocly/cli': toolVersion(process.execPath, [REDOCLY(), '--version'], 'redocly'),
      },
      keywordCounts: countKeywords(document.components.schemas),
      lint: {
        redocly: {
          tracked: redoclyLint(redoclyConfig),
          waiverAbsorbs: sortCounts(redoclyLint(unwaived(redoclyConfig, scratch, 'redocly-unwaived.yaml')).byRule),
        },
      },
    };
  });
}

/** The codegen half: whether each generator consumes the document, and per-keyword verdicts. */
export function measureCodegen(only) {
  const generators = resolveGenerators(only);
  const names = generators.map(([name]) => name);
  return withScratch((scratch) => ({
    tools: {
      ...(names.includes('openapi-typescript')
        ? {
            'openapi-typescript': toolVersion(
              process.execPath,
              [OPENAPI_TS(), '--version'],
              'openapi-typescript',
            ),
          }
        : {}),
      ...(names.includes('oapi-codegen')
        ? { 'oapi-codegen': toolVersion(OAPI, ['--version'], 'oapi-codegen') }
        : {}),
    },
    codegen: {
      document: documentSupport(scratch, generators),
      keywords: keywordSupport(scratch, generators),
    },
  }));
}

const BASELINE_COMMENT =
  'Generated by scripts/openapi-matrix.mjs — run `pnpm run matrix:update` to refresh, ' +
  'and review the diff: a change here is a change in what real tooling does with the ' +
  'published contract. honored/ignored are measured differentially (generate with the ' +
  'keyword, generate without it, compare bytes), never read from documentation.';

/**
 * Both halves, assembled in the baseline's key order. `measure` exists so the test suite
 * gets one call; the CLI — `matrix` and `matrix:update` alike — uses the halves separately
 * so it can short-circuit.
 *
 * @param {string[]} [only] generator names to measure; defaults to all of them. The vitest
 *   gate passes NPM_GENERATORS so it can run the same measurement without a Go toolchain.
 */
export function measure(only) {
  return composeMeasurement(measureLint(), measureCodegen(only));
}

/** Assembles the two halves into the exact shape and key order the baseline records. */
export function composeMeasurement(lintPart, codegenPart) {
  return {
    $comment: BASELINE_COMMENT,
    tools: { ...lintPart.tools, ...codegenPart.tools },
    keywordCounts: lintPart.keywordCounts,
    lint: lintPart.lint,
    codegen: codegenPart.codegen,
  };
}

/** Serialises a measurement exactly as the tracked baseline stores it. */
export function serialise(measured) {
  return `${JSON.stringify(measured, null, 2)}\n`;
}

/**
 * The lint half of the gate: zero errors under the tracked configs is not negotiable, so a
 * non-zero count short-circuits before the baseline is even consulted. Returns one message
 * per offending linter, empty when clean.
 */
export function lintGate(measured) {
  const failures = [];
  for (const [linter, result] of Object.entries(measured.lint)) {
    const count = result.tracked.bySeverity.error ?? 0;
    if (count > 0) {
      failures.push(
        `${linter} reports ${count} error(s) under its tracked config: ` +
          JSON.stringify(result.tracked.byRule),
      );
    }
  }
  return failures;
}

/**
 * The drift half of the gate. Kept pure — taking the tracked text rather than reading it —
 * so the comparison and its report can be tested without a filesystem or a process exit.
 *
 * @param {string|null} trackedText the committed baseline, or null if absent
 * @returns {{ok: boolean, report: string}}
 */
export function compareToBaseline(measured, trackedText) {
  const serialised = serialise(measured);
  if (trackedText === null) {
    return {
      ok: false,
      report: `openapi-matrix: no baseline recorded. Create it with \`pnpm run matrix:update\`.\n`,
    };
  }
  if (trackedText === serialised) {
    return { ok: true, report: 'openapi-matrix: tooling behaviour matches the baseline\n' };
  }
  const expected = trackedText.split('\n');
  const actual = serialised.split('\n');
  let report = 'openapi-matrix: measured tooling behaviour differs from the baseline.\n';
  for (let i = 0; i < Math.max(expected.length, actual.length); i += 1) {
    if (expected[i] !== actual[i]) {
      report +=
        `  line ${i + 1}\n    baseline: ${expected[i] ?? '<absent>'}\n` +
        `    measured: ${actual[i] ?? '<absent>'}\n`;
    }
  }
  report +=
    '\nIf this is a deliberate tooling upgrade or schema change, review each line above ' +
    'and re-record with `pnpm run matrix:update`.\n';
  return { ok: false, report };
}

/** The tracked baseline, or null when there is not one yet. */
export function readBaseline(path = BASELINE) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/**
 * The CLI, with its effects injected so the control flow can be tested without running the
 * measurement (which shells out to four tools) or ending the process.
 *
 * @returns {number} the exit code
 */
export function runCli(argv, io = {}) {
  const {
    baselinePath = BASELINE,
    measureLint: lintFn = measureLint,
    measureCodegen: codegenFn = measureCodegen,
    // Defaults rather than required arguments so the CLI has no setup of its own, and
    // `baselinePath` is injectable so a test can exercise these real defaults against a
    // temporary file instead of substituting its own and leaving them unrun.
    readTracked = () => readBaseline(baselinePath),
    writeTracked = (text) => writeFileSync(baselinePath, text),
    out = (text) => process.stdout.write(text),
    err = (text) => process.stderr.write(text),
  } = io;

  // Lint first, and stop here on a failure: the lint verdict already decides the exit code,
  // so the probes' seconds buy nothing. They also read `redocly.yaml` themselves, so a
  // config error that breaks Redocly tends to crash them and bury this message.
  const lintPart = lintFn();
  const lintFailures = lintGate(lintPart);
  if (lintFailures.length > 0) {
    err(`openapi-matrix: lint gate failed\n  ${lintFailures.join('\n  ')}\n`);
    return 1;
  }

  const measured = composeMeasurement(lintPart, codegenFn());

  if (argv.includes('--update')) {
    writeTracked(serialise(measured));
    out('openapi-matrix: baseline recorded\n');
    return 0;
  }

  const { ok, report } = compareToBaseline(measured, readTracked());
  if (!ok) {
    err(report);
    return 1;
  }
  out(report);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(runCli(process.argv.slice(2)));
}
