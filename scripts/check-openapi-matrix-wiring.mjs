#!/usr/bin/env node
// The oapi-codegen half of hdf-openapi's tooling baseline is measured only where the
// generator is installed, so what has to hold is that CI installs it at the version the
// baseline records and that a failed measurement fails the run. Checking that from the
// package's own test suite would mean reading the workflow and the toolchain pins from
// outside the package; it lives here with the repo's other cross-cutting guards instead.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { realpathSync } from 'node:fs';

import { parse as parseYaml } from 'yaml';

export const TOOL = 'go:github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen';

const MATRIX_RUN = 'pnpm --filter @mitre/hdf-openapi run matrix';
const JOB = 'check-openapi-matrix';
const GATE = 'gate-hdf-scans';
const ANY_UNSUCCESSFUL = ['failure', 'cancelled', 'skipped']
  .map((result) => `contains(needs.*.result, '${result}')`)
  .join(' || ');

const squash = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();

/**
 * Reports what disagrees about the generator's wiring, as {reason} entries; an empty
 * array means CI measures the baseline's Go half at the version the baseline records.
 */
export function checkMatrixWiring({ ci, miseToml, miseLock, baselineTools }) {
  const offenders = [];
  const fail = (reason) => offenders.push({ reason });

  const job = ci?.jobs?.[JOB];
  if (!job) {
    fail(`CI has no ${JOB} job, so nothing measures the generator half of the baseline`);
    return offenders;
  }
  const steps = job.steps ?? [];
  const matrixAt = steps.findIndex((step) => squash(step.run) === MATRIX_RUN);
  if (matrixAt < 0) fail(`${JOB} does not run the matrix (${MATRIX_RUN})`);

  const installAt = steps.findIndex(
    (step) =>
      String(step.uses ?? '').startsWith('jdx/mise-action@') &&
      String(step.with?.install_args ?? '').split(/\s+/).includes(TOOL),
  );
  if (installAt < 0) {
    fail(`${JOB} does not install the generator through the pinned toolchain`);
  } else if (matrixAt >= 0 && installAt > matrixAt) {
    fail(`${JOB} installs the generator after, not before the matrix step`);
  }
  const mentions = steps.filter((step) => JSON.stringify(step).includes('oapi-codegen'));
  if (installAt >= 0 && (mentions.length !== 1 || mentions[0] !== steps[installAt])) {
    fail(`no step other than the install may fetch the generator, but ${mentions.length} steps of ${JOB} mention it`);
  }

  // A measurement a condition can skip, or whose failure is swallowed, gates nothing.
  const upTo = matrixAt < 0 ? steps : steps.slice(0, matrixAt + 1);
  for (const unit of [job, ...upTo]) {
    if (unit.if !== undefined) fail(`a condition may skip ${JOB} or a step it needs: ${squash(unit.if)}`);
    if (unit['continue-on-error'] !== undefined) fail(`a failure must fail the job, but continue-on-error is set`);
  }

  // One version across the pin, the lock and the measured record.
  const pinned = /^"?.+"? = "(\d+\.\d+\.\d+)"$/.exec(
    (miseToml ?? '').split(/\r?\n/).find((line) => line.startsWith(`"${TOOL}" = "`)) ?? '',
  )?.[1];
  if (!pinned) {
    fail('the toolchain file does not pin the generator version');
  } else {
    const lockLines = (miseLock ?? '').split(/\r?\n/);
    const entry = lockLines.indexOf(`[[tools."${TOOL}"]]`);
    if (entry < 0) fail('the lock file does not lock the generator');
    else if (lockLines[entry + 1] !== `version = "${pinned}"`) {
      fail(`the lock file does not lock the generator at the pinned ${pinned}`);
    }
    const recorded = baselineTools?.['oapi-codegen'];
    if (recorded !== pinned) {
      fail(`the pin is ${pinned} but the baseline records ${recorded}, so the gate would judge a new tool by an old record`);
    }
  }

  const gate = ci?.jobs?.[GATE];
  const needs = [gate?.needs ?? []].flat();
  if (!needs.includes(JOB)) {
    fail(`${GATE} must need ${JOB}; a job nothing needs cannot fail the run`);
  }
  if (squash(gate?.if) !== 'always()') {
    fail(`${GATE} must run with always(), or a failed upstream skips it instead of failing`);
  }
  const rejects = (gate?.steps ?? []).filter(
    (step) =>
      squash(step.if) === ANY_UNSUCCESSFUL &&
      /^\s*exit 1\s*$/m.test(step.run ?? '') &&
      step['continue-on-error'] === undefined,
  );
  if (rejects.length !== 1) {
    fail(`${GATE} must reject a run whose upstream failed, was cancelled or was skipped, in one step`);
  }
  return offenders;
}

const TARGET = 'lint:matrix-wiring';

/**
 * Reports whether this guard itself is invoked. The hook reaches it through
 * `check`; CI enumerates its lint targets instead, so a guard in `check` alone
 * runs on a contributor's machine and never on a pull request. Neither side
 * catches its own removal; this catches an accidental one while the other runs.
 */
export function checkGuardWiring({ packageJson, ci }) {
  const offenders = [];
  const scripts = packageJson?.scripts ?? {};
  if (!scripts[TARGET]) offenders.push({ reason: `package.json has no ${TARGET} script` });
  if (!String(scripts.check ?? '').includes(`pnpm run ${TARGET}`)) {
    offenders.push({ reason: `the check target does not run ${TARGET}, so the pre-commit hook skips it` });
  }
  const runsIt = Object.values(ci?.jobs ?? {}).some((job) =>
    (job?.steps ?? []).some((step) => squash(step.run) === `pnpm run ${TARGET}`),
  );
  if (!runsIt) offenders.push({ reason: `no CI job runs ${TARGET}, so a pull request does not check it` });
  return offenders;
}

function main() {
  const root = join(fileURLToPath(new URL('../', import.meta.url)));
  const read = (...parts) => readFileSync(join(root, ...parts), 'utf8');
  const ci = parseYaml(read('.github', 'workflows', 'ci.yml'));
  const offenders = [
    ...checkMatrixWiring({
      ci,
      miseToml: read('mise.toml'),
      miseLock: read('mise.lock'),
      baselineTools: JSON.parse(read('hdf-openapi', 'test', 'baseline', 'keywords.json')).tools,
    }),
    ...checkGuardWiring({ packageJson: JSON.parse(read('package.json')), ci }),
  ];
  if (offenders.length === 0) {
    console.log(`openapi-matrix-wiring: ok — CI measures the generator half at the pinned version`);
    return;
  }
  for (const { reason } of offenders) console.error(`openapi-matrix-wiring: ${reason}`);
  process.exitCode = 1;
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) main();
