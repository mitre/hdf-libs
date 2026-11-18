import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkMatrixWiring, checkGuardWiring, TOOL } from '../check-openapi-matrix-wiring.mjs';

const MATRIX_RUN = 'pnpm --filter @mitre/hdf-openapi run matrix';
const ANY_UNSUCCESSFUL = ['failure', 'cancelled', 'skipped']
  .map((result) => `contains(needs.*.result, '${result}')`)
  .join(' || ');

/** A workflow whose wiring is correct; each test breaks exactly one thing. */
function ci({ job, gate } = {}) {
  return {
    jobs: {
      'check-openapi-matrix': {
        steps: [
          { uses: 'jdx/mise-action@abc', with: { install_args: `node pnpm go ${TOOL}` } },
          { run: MATRIX_RUN },
        ],
        ...job,
      },
      'gate-hdf-scans': {
        needs: ['check-openapi-matrix', 'scan-code'],
        if: 'always()',
        steps: [{ if: ANY_UNSUCCESSFUL, run: 'exit 1\n' }],
        ...gate,
      },
    },
  };
}

const inputs = (over = {}) => ({
  ci: ci(),
  miseToml: `[tools]\n"${TOOL}" = "2.8.0"\n`,
  miseLock: `[[tools."${TOOL}"]]\nversion = "2.8.0"\n`,
  baselineTools: { 'oapi-codegen': '2.8.0' },
  ...over,
});

const reasons = (over) => checkMatrixWiring(inputs(over)).map((o) => o.reason).join(' | ');

test('correct wiring reports nothing', () => {
  assert.deepEqual(checkMatrixWiring(inputs()), []);
});

test('the job must exist and run the matrix', () => {
  assert.match(reasons({ ci: { jobs: {} } }), /check-openapi-matrix/);
  const noRun = ci();
  noRun.jobs['check-openapi-matrix'].steps = [noRun.jobs['check-openapi-matrix'].steps[0]];
  assert.match(checkMatrixWiring(inputs({ ci: noRun })).map((o) => o.reason).join(''), /run the matrix/);
});

test('the generator must be installed through the pinned toolchain, before the matrix', () => {
  const noInstall = ci();
  noInstall.jobs['check-openapi-matrix'].steps = [{ run: MATRIX_RUN }];
  assert.match(reasons({ ci: noInstall }), /install the generator/);

  const after = ci();
  after.jobs['check-openapi-matrix'].steps.reverse();
  assert.match(reasons({ ci: after }), /before the matrix/);
});

test('no other step may fetch the generator', () => {
  const extra = ci();
  extra.jobs['check-openapi-matrix'].steps.push({ run: `go install ${TOOL}@latest` });
  assert.match(reasons({ ci: extra }), /other than the install may fetch/);
});

test('nothing may skip the job or let it pass on failure', () => {
  assert.match(reasons({ ci: ci({ job: { if: "github.event_name == 'push'" } }) }), /condition/);
  assert.match(reasons({ ci: ci({ job: { 'continue-on-error': true } }) }), /must fail the job/);
  const stepIf = ci();
  stepIf.jobs['check-openapi-matrix'].steps[0].if = 'always()';
  assert.match(reasons({ ci: stepIf }), /condition/);
});

test('the pin, the lock and the baseline must agree on one version', () => {
  assert.match(reasons({ miseToml: '[tools]\n' }), /pin the generator/);
  assert.match(reasons({ miseLock: '' }), /lock the generator/);
  assert.match(reasons({ miseLock: `[[tools."${TOOL}"]]\nversion = "2.7.0"\n` }), /lock the generator at/);
  assert.match(reasons({ baselineTools: { 'oapi-codegen': '2.7.0' } }), /baseline records/);
});

test('the scan gate must need the job and reject a failed upstream', () => {
  assert.match(reasons({ ci: ci({ gate: { needs: ['scan-code'] } }) }), /must need/);
  assert.match(reasons({ ci: ci({ gate: { if: 'success()' } }) }), /always\(\)/);
  assert.match(reasons({ ci: ci({ gate: { steps: [] } }) }), /reject a run/);
  const partial = ci({ gate: { steps: [{ if: "contains(needs.*.result, 'failure')", run: 'exit 1\n' }] } });
  assert.match(reasons({ ci: partial }), /reject a run/);
  const softened = ci({ gate: { steps: [{ if: ANY_UNSUCCESSFUL, run: 'exit 1\n', 'continue-on-error': true }] } });
  assert.match(reasons({ ci: softened }), /reject a run/);
});

const wiring = (over = {}) =>
  checkGuardWiring({
    packageJson: { scripts: { 'lint:matrix-wiring': 'node ...', check: 'pnpm run lint && pnpm run lint:matrix-wiring' } },
    ci: { jobs: { 'check-ts': { steps: [{ run: 'pnpm run lint:matrix-wiring' }] } } },
    ...over,
  }).map((o) => o.reason).join(' | ');

test('this guard is wired into both the hook target and a CI job', () => {
  assert.equal(wiring(), '');
});

test('a guard nothing invokes is reported, per side', () => {
  assert.match(wiring({ packageJson: { scripts: { check: 'pnpm run lint' } } }), /no lint:matrix-wiring script/);
  assert.match(
    wiring({ packageJson: { scripts: { 'lint:matrix-wiring': 'node ...', check: 'pnpm run lint' } } }),
    /check target does not run/,
  );
  assert.match(wiring({ ci: { jobs: { 'check-ts': { steps: [{ run: 'pnpm run lint' }] } } } }), /no CI job runs/);
});
