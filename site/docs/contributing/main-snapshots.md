---
title: Main snapshots
description: Consume development snapshots and operate automatic publication from main.
---

# Main snapshots

Install `@mitre/hdf-converters@next` to follow the newest successfully published development snapshot of `main`. Other publishable `@mitre/hdf-*` libraries use the same `next` channel. Snapshot publication can lag merges while builds are queued or failed; it is not a promise that the registry already contains current HEAD.

Each snapshot has an immutable version such as `3.8.0-next.12345.1`. Pin that exact version for reproducible downstream builds. Go consumers use the matching `v3.8.0-next.12345.1` module version; Go has no equivalent of npm's mutable dist-tag. Snapshot versions remain available when `next` advances.

## Channels and authorization

| Channel | Purpose | Publication authority |
| --- | --- | --- |
| `next` | Latest successfully published main snapshot | Automatic snapshot workflow |
| `rc` | Maintainer-selected formal release candidate | Existing formal release process |
| `stable` on `@mitre/hdf-converters` | Stable v3 converter release | Existing formal release process |
| `latest` on the other libraries | Stable release | Existing formal release process |

The converter package's `latest` belongs to Heimdall's v2 line and is never assigned a v3 snapshot or release. The snapshot workflow does not publish formal root `v*` tags or GitHub Releases. Formal releases retain maintainer approval, the hardware-backed signing policy, provenance, and the release-preparation review process. Enforcing a specific signing subkey in CI is a separate follow-up; this implementation does not add that enforcement.

Snapshots use the GitHub Actions service identity. A read-only preparation job checks out the commit that triggered the run and, through `scripts/derive-snapshot-version.sh` and `scripts/prepare-snapshot.sh`, creates versioned manifests and version constants without installing workspace dependencies. The dependency build runs on a separate runner; the tag writer receives the preparation artifact by its immutable ID, checks its commit and parent, and uses its module inventory. Build outputs cannot select the Git source or version to tag. Their version-rewrite commits are derived from main, contain only the npm manifest, Go module and hdf-engine version changes, and are not committed back to main or represented as maintainer-signed commits. An artifact attestation covers the package tarballs and a manifest identifying both the source SHA and prepared commit. npm publication also requests provenance through OIDC Trusted Publishing.

## Versions

Preparation finds the highest stable root version reachable from the selected source commit. It chooses the next patch when `hdf-schema/src/schemas` is unchanged since that release, or the next minor when that directory changed, and floors the result at the version `hdf-schema/package.json` declares, so a merged prepare-release commit whose tag has not been pushed yet, including one for a major, is never undercut by a snapshot. It never infers a major release on its own. A major-version transition needs an explicit preparation process; the snapshot module inventory currently requires the v3 module paths.

The prerelease suffix combines the GitHub workflow run ID and attempt number. Each complete attempt gets a fresh version, including a rerun of the same source. These numbers identify publication attempts, not commits or release candidates. Gaps are expected, and snapshots do not create or advance `rc`.

The prepared commit receives a `snapshots/vVERSION` tag and matching module tags such as `hdf-converters/vVERSION`. Its sibling Go requirements name the same version, and the hdf-engine version constants (`hdf-engine/src/version.ts`, `hdf-engine/go/engine.go`) are stamped with it, so the documents and MCP handles a snapshot produces report the snapshot version rather than the previous release. PR CI’s standard Go consumer-graph check validates the source dependency graph, and the snapshot version-rewrite helper verifies matching sibling requirements. These checks run before publication; they do not fetch the newly tagged modules from the Go proxy. Snapshots use the same Go verification level as formal releases rather than adding a separate post-tag fetch job.

## Concurrent merges and recovery

Every push to main triggers the workflow, including documentation and dependency changes. GitHub concurrency keeps one running publication and one pending run; newer pushes replace the pending run. Each run builds the commit that triggered it, which is the commit its npm provenance and build attestation name. Intermediate commits replaced in the pending slot never receive a snapshot. The running publication finishes even if main advances during its build; the newer commit's own run follows. Preparation fails closed if main has already moved past the triggering commit when it starts, so a run that lost that race, or a rerun of an older run, never moves `next` back to older code.

The single workflow serializes preparation, build, tag and npm publication. A complete rerun builds the same commit under a fresh version, and is refused once main has moved past it. The snapshot installs at the selected source with frozen workspace dependencies, then selects the prepared commit and builds and packs from it, so the stamped version constants reach the published `dist/`; the packed npm archives then use the same install/import smoke check as formal pre-release verification. The full lint, test and security suite stays in PR CI. Publication performs the build, version validation and shared npm smoke check without rerunning that suite.

Before any npm write, the publisher validates the complete archive batch with `scripts/check-snapshot-archives.sh` against the inventory `scripts/list-npm-packages.sh` derives from the trusted source checkout; the same inventory drives CI packing, the pre-release smoke test and the formal release, so a new package reaches every path or none. It requires exact snapshot names, versions and sibling pins, one regular package manifest per archive, and no publication configuration beyond public access. Preparation also refuses to tag or publish anything until `@mitre/hdf-converters` carries a `stable` dist-tag, because snapshots take over the `next` alias that stable v3 installs previously used. Registry and channel selection come from explicit publication commands. Packages initially publish under `snapshot-staging`. The workflow advances their `next` aliases only after the entire publication batch succeeds. npm does not provide a transaction across package dist-tags: a failed promotion can leave aliases temporarily split. Consumers needing a coordinated snapshot should pin exact versions; each package pins its runtime sibling dependencies to the same snapshot version.

To recover from a failure on the newest commit, select **Re-run all jobs** on its run. For anything older, manually run **Main snapshots** on main with no inputs, which snapshots the current tip under a fresh version. **Re-run failed jobs** cannot reuse an earlier attempt's artifact/version and fails closed. Already published immutable versions and Git tags remain available; the workflow never deletes or overwrites them. A partially published failed attempt may leave staging versions that never become `next`. Unlike formal releases, snapshots do not compare registry contents to resume partially published immutable versions.

## Maintainer activation

Before enabling the first snapshot publication:

1. Verify the GitHub environments `npm-snapshots` and `snapshot-tags` allow only the `main` branch. These environments were created during security remediation, without the formal release environment's per-release reviewer requirement. Keep the formal `npm-publish` environment and release-tag rules unchanged. The tag-writing job uses `snapshot-tags`; npm trusts `npm-snapshots`.
2. Add a separate npm Trusted Publisher for `mitre/hdf-libs`, calling workflow **`snapshot.yml`**, environment **`npm-snapshots`**, to each public `@mitre/hdf-*` package listed in `hdf-*/package.json`. Permit direct publication and **Allow npm dist-tag**. Preserve existing formal-release and Heimdall publisher configurations.
3. Initialize the converter package's `stable` alias to the current released v3 version (`npm dist-tag add @mitre/hdf-converters@<version> stable`) before this change merges: the READMEs already instruct `@stable`, and preparation refuses to tag or publish anything until the alias exists. Confirm its `latest` still points to v2.
4. Verify the immutable module/snapshot tag ruleset protects `snapshots/**` and `hdf-*/**` against updates and deletion. It retains the maintainer-team bypass and permits new module/snapshot tags; the workflow pushes an explicit, atomic snapshot ref list. Formal root `v*` creation protections remain unchanged. Formal module-tag creation authorization and exact signing-key enforcement need the separate release-hardening work; this immutability rule does not supply them.
5. Merge the implementation and inspect the first publication's attestations, matching module versions, npm consumer result, and npm `next` aliases. External settings and live publication cannot be verified by local tests. Complete this activation near the first publish: newly configured npm trust relationships expire if not validated within two days.

npm Trusted Publishing binds the package to the repository, workflow and environment; it does not provide a next-only version or alias restriction. The validation above prevents a compromised build artifact from requesting stable publication, but compromise of the privileged publisher itself remains a broader authority risk. Signing Git tags alone cannot restrict that independent npm authority. Before activating npm trust, check for older eligible snapshot runs: reruns retain historical workflow definitions. If vulnerable runs exist, retire their workflow identity before enabling trust for the hardened implementation.

CI, pre-release consumer checks, formal publication and snapshots all use npm 11.21.0 from the shared integrity-pinned npm setup action, which only the jobs that run npm invoke. The same client performs consumer installs and OIDC dist-tag operations. It does not need a persistent npm token or a copy of a maintainer's signing key. The formal workflow continues using the same preparation and approval boundary; changes to formal publishing mechanics still require its RC pipeline validation before the next stable release.

See the [developer guide](./developer-guide) and [release verification](../guides/verifying-releases) for build commands and artifact verification.
