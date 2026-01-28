# Branch Protection Setup

## Required Status Checks

To enforce "all tests must pass before merge", configure branch protection in GitHub:

**Settings → Branches → Branch protection rules → Add rule**

### Protected Branch: `main`

**Required settings**:
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
  - **Required checks**:
    - `test` (the CI job that runs all tests)
- ✅ Require branches to be up to date before merging
- ✅ Do not allow bypassing the above settings

**Optional (recommended)**:
- ✅ Require signed commits
- ✅ Require linear history
- ✅ Require conversation resolution before merging

### Workflow

With branch protection enabled:

1. Developer creates PR from feature branch → `main`
2. GitHub Actions runs CI workflow automatically
3. If tests fail → PR cannot merge (red X)
4. If tests pass → PR can merge (green checkmark)
5. Merge button only enabled when all checks pass

### Testing the Setup

Create a test PR with a failing test to verify protection is working:

```bash
# Create branch with failing test
git checkout -b test-branch-protection
# ... add failing test ...
git push origin test-branch-protection
# Create PR to main → should block merge
```

## CI Workflow Coverage

The `test` job runs:
- ✅ Linting (TypeScript + Go)
- ✅ Build (all packages)
- ✅ TypeScript tests (all packages, 95% coverage required)
- ✅ Go tests (hdf-cli)
- ✅ Coverage reporting (Codecov)

All must pass for PR to merge.
