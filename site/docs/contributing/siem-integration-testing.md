---
title: Local SIEM integration testing
description: Start isolated Elasticsearch and Splunk test services with Testcontainers and verify current HDF artifacts.
---

# Local SIEM integration testing

Use this development harness to verify HDF export preservation through real SIEM ingestion, native queries and raw retrieval. Testcontainers Node manages a shared Docker Compose definition; each run uses a private directory and matching project name with a 128-bit lowercase random identifier, plus generated credentials. Published HDF packages do not depend on Testcontainers.

The environment smoke test is implemented. Elasticsearch 9.5.6 and the pinned Splunk image (reporting version 10.6.1.1) passed authenticated readiness, license checks and cleanup together. Both target suites exercise current CLI and packed TypeScript exports through ingestion, native queries and raw retrieval. Environment readiness alone is not preservation verification; hosted product acceptance additionally requires the integration evidence gate.

## Prerequisites

- Use the repository's supported Node, pnpm and Go versions, and install dependencies with `pnpm install --frozen-lockfile`.
- Provide a Docker-compatible Linux container runtime and Docker Compose. Testcontainers must reach its socket, and its resource reaper must work. Do not disable the reaper to bypass a failed check.
- The Compose definition pins Elasticsearch 9.5.6 and Splunk Enterprise 10.6.1 by digest. Their configured memory limits are 2 GiB and 4 GiB respectively; allow additional memory for the host and build tools. These are test allocations, not production sizing recommendations.
- Elasticsearch uses Basic licensing. Splunk requires acceptance of its [current General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html). Its inspected Enterprise image supports AMD64 only; ARM64 runtime use requires an explicit emulation opt-in and successful qualification.

The local service endpoints use authenticated HTTP bound to loopback, following the vendor development examples. This configuration is for disposable tests on a trusted development machine. The request helper verifies certificates for HTTPS callers and accepts an explicit CA; it never disables TLS certificate verification.

## Qualify a service

Run from the repository root:

```sh
node --env-file=test/siem/.env.example test/siem/run.mjs --environment-only --target elasticsearch
```

The explicit `--env-file` loads the qualified Ryuk 0.14.0 cleanup image digest from `test/siem/.env.example`; the image supports Linux AMD64 and ARM64 and its tooling uses the MIT license. The runner rejects a missing or different `RYUK_CONTAINER_IMAGE` before starting services; this file is the single source of the qualified pin. An explicit matching process environment value also works. Testcontainers can reuse an already-running Node reaper, so qualify its actual image when sharing a runtime with other Testcontainers runs.

After accepting Splunk's terms, set `HDF_SIEM_ACCEPT_SPLUNK_TERMS=yes` in the process environment. On an ARM64 runtime, also set `HDF_SIEM_ALLOW_AMD64_EMULATION=yes` only when you intend to test emulation. The runner checks these opt-ins before starting services. Process environment values take precedence over the empty opt-ins in `test/siem/.env.example`; this file contains no credentials and accepts no terms by default.

For one approved Splunk run on ARM64, scope both opt-ins to that command:

```sh
HDF_SIEM_ACCEPT_SPLUNK_TERMS=yes HDF_SIEM_ALLOW_AMD64_EMULATION=yes \
  node --env-file=test/siem/.env.example test/siem/run.mjs --environment-only --target splunk
```

The runner supplies Splunk's `--accept-license` startup argument and `--accept-sgt-current-at-splunk-com` General Terms argument only when the terms opt-in is `yes`. Native AMD64 hosts need only the terms opt-in.

Then run either selected target or both:

```sh
node --env-file=test/siem/.env.example test/siem/run.mjs --environment-only --target splunk
node --env-file=test/siem/.env.example test/siem/run.mjs --environment-only --target all
```

Environment-only mode verifies service readiness, authenticated version access, Elasticsearch's active Basic license, Splunk's active license and HEC health, and owned-resource cleanup. It does not require the CLI bundle delivery command. A missing runtime, refused credentials, unhealthy service or failed cleanup causes failure.

Elasticsearch can briefly return HTTP 404 from its [license endpoint during startup](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-license-get). The runner retries that status for up to 30 seconds, then still requires an active Basic license. Authentication errors fail immediately; cancellation interrupts both requests and retry waits.

## Test the helpers and current packages

Unit tests need no containers. The transport tests bind ephemeral loopback HTTP/HTTPS listeners; the HTTPS test uses OpenSSL to create a temporary test certificate.

```sh
node --test test/siem/run.test.mjs test/siem/harness.test.mjs test/siem/ci-report.test.mjs
```

The build check compiles the current CLI, packs its TypeScript converter dependency closure into a private consumer, imports the public converter entry point, and validates the referenced fixture inputs with the current CLI. It needs registry access for external package dependencies:

```sh
HDF_SIEM_TEST_BUILD=yes node --test test/siem/harness.test.mjs
```

For combined artifact and real service coverage, select the services explicitly. The same Splunk opt-ins apply when selecting Splunk or `all`:

```sh
HDF_SIEM_TEST_BUILD=yes HDF_SIEM_TEST_SERVICES=elasticsearch node --env-file=test/siem/.env.example --test --experimental-test-coverage --test-coverage-include='**/test/siem/*.mjs' --test-coverage-exclude='**/*.test.mjs' test/siem/run.test.mjs test/siem/harness.test.mjs
```

To include full-mode orchestration coverage, add `HDF_SIEM_TEST_WIRING=yes` and `--test-concurrency=1` to the combined command. This starts a real Elasticsearch instance, builds the current CLI and packed packages, then loads a temporary verification module that performs an authenticated request and deliberately fails. The test requires a failure report with successful cleanup. It tests the module boundary and failure propagation, not HDF ingestion or preservation. Serial file execution avoids concurrent builds of the same workspace packages.

The include pattern is necessary: Node otherwise excludes source files under the `test/` directory and can display an empty coverage report. A unit run that skips the opt-in build/service tests is not full card acceptance evidence.

## GitHub Actions service smoke

The `SIEM service smoke` workflow runs separate Elasticsearch and Splunk jobs on native AMD64 Ubuntu runners. Pull requests qualify the workflow before merge; pushes to `main` and manual dispatch also run it. Manual dispatch becomes available after GitHub registers the workflow on the default branch.

Each job records runner architecture, memory, free disk (including Docker storage) and Docker/Compose versions, then uses the same pinned images and Testcontainers runner as the local command. It checks startup, authentication, license readiness and cleanup in `--environment-only` mode. Memory and disk usage are recorded again after execution without deleting unrelated resources. Smoke mode installs Node and pnpm through the shared setup; it does not install Go or build the CLI. A passing smoke job does **not** prove event ingestion, preservation or full end-to-end correctness. [Hosted run 42820622016](https://github.com/mitre/hdf-libs/actions/runs/42820622016) at source SHA `0a5fab45d0f00787be7627beb58e578e962f34ef` qualified both targets: Elasticsearch 9.5.6 and Splunk 10.6.1.1 passed authenticated readiness and cleanup on native AMD64 runners. That run qualifies readiness only; hosted ingestion/readback is checked by the separate integration jobs described below.

Splunk consent is off by default. After accepting the current General Terms, a repository maintainer can set the Actions repository variable `HDF_SIEM_ACCEPT_SPLUNK_TERMS` to `yes` for automatic runs. A manual run can instead opt in through the `accept_splunk_terms` boolean. This is an operator opt-in, not a security boundary against edits to a pull request workflow. Before merge, qualification requires the repository variable because manual dispatch is not yet registered. No emulation opt-in is needed on these native AMD64 runners. Missing consent fails the Splunk smoke job before checkout or container startup and reports `NOT VERIFIED`; it never produces a successful smoke result.

Only `test/siem/.runs/*/report.json` is uploaded, under per-target artifact names with seven-day retention. The glob deliberately excludes credentials, package files and raw container configuration. Startup and cleanup failures remain failures even when a sanitized report is uploaded. A failure before report creation remains visible in the job log; the upload step warns that no report exists.

## GitHub Actions integration gate

The same workflow also runs `SIEM end-to-end (elasticsearch)` and `SIEM end-to-end (splunk)`. Each uses a separate native AMD64 runner, installs Go through the shared setup, and invokes `run.mjs --target` without `--environment-only`. The current checkout builds both the CLI and isolated packed TypeScript consumer. Each target must complete every fixture/producer pair in `cases.json`, including the empty assessment and rejection checks, and clean up its owned resources.

Node's [built-in JUnit reporter](https://nodejs.org/docs/latest-v24.x/api/test.html#test-reporters) emits one integration verdict per target from the completed report. Detailed case counts and fingerprints remain in the accompanying JSON. `ci-report.mjs` refuses missing, ambiguous, malformed, readiness-only or incomplete reports, failed cleanup, a different commit, or an uncommitted source tree. `HDF_SIEM_REPORT_TARGET`, `HDF_SIEM_REPORT_DIR` and `HDF_SIEM_REPORT_COMMIT` identify the required target, directory containing exactly one run, and expected checkout commit. On a pull request this is the tested merge commit, not necessarily the branch head.

`Gate SIEM integration on HDF thresholds` independently rechecks both reports, normalizes their JUnit using the trusted pinned-main HDF CLI, and applies `.github/hdf-thresholds/tests-siem.yaml`. The named integration verdict must pass; a generic passing file result or the converter's empty-JUnit placeholder cannot substitute. Failures, errors and skips have zero allowance. Missing artifacts or a failed, cancelled or skipped prerequisite job prevent success. A controlled missing-report probe must produce failed JUnit and fail HDF policy. A second probe selects no integration test and must also fail HDF policy, even when Node reports the file itself as passed. The probe is expected to fail; it never counts as product success.

The trusted CLI build lives in the [reusable workflow](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows) `.github/workflows/gate-cli.yml`, shared with the existing CI gates. Existing unit-test thresholds and required check names are unchanged. Ordinary unit tests still need no containers.

Only sanitized JSON reports, JUnit and normalized HDF are uploaded, with seven-day retention. Full run directories, credentials, packages and raw container configuration remain excluded. The aggregate check must pass on the actual hosted run before treating this integration as accepted; local runs and workflow lint are supporting evidence.

Hosted qualification on 2026-11-10 passed [all six SIEM jobs](https://github.com/mitre/hdf-libs/actions/runs/42862597502) and [all 20 native CI jobs](https://github.com/mitre/hdf-libs/actions/runs/42862597056). Each target completed 16 CLI/packed-TypeScript cases and 3,224 events with cleanup PASS. Branch commit `377012ae148ef1a949a25939eb3a8c08620ccc95` and tested merge commit `ded8f80e56b8a067b2c2d193625b480a33839619` share tree `481a7b6a0cd73925d7ca5f8a639bc70e1212a816`. Both negative reporting probes were rejected by HDF policy on the hosted runner. Prerequisite-result checks enforce failed-job propagation; this qualification did not deliberately fail a hosted service job.

## Repeat the complete workflow

After installing dependencies and qualifying the runtime, run both targets twice. On an ARM64 runtime with the Splunk terms and emulation already accepted:

```sh
HDF_SIEM_ACCEPT_SPLUNK_TERMS=yes HDF_SIEM_ALLOW_AMD64_EMULATION=yes \
  node --env-file=test/siem/.env.example test/siem/run.mjs --target all
HDF_SIEM_ACCEPT_SPLUNK_TERMS=yes HDF_SIEM_ALLOW_AMD64_EMULATION=yes \
  node --env-file=test/siem/.env.example test/siem/run.mjs --target all
```

Omit the emulation opt-in on native AMD64. Each invocation creates a new isolated project, builds the current CLI and packed TypeScript consumer, checks every case on both services, and verifies removal of its own containers, networks and volumes. Retain both sanitized reports, including their distinct project IDs and source fingerprints. A second successful startup alone is insufficient: both reports must say `mode: integration`, `status: PASS` and `cleanup: PASS`, with complete per-target results.

## Reports and cleanup

Private run directories live under the ignored `test/siem/.runs/` directory. Each contains a sanitized `report.json`; full runs also retain their local package artifacts. The report records the checkout commit, a SHA-256 of tracked changes against that commit, and names of untracked build/harness inputs. Per-case hashes identify the actual input bytes. The runner checks source identity again after build, verification and cleanup; a source change during the run fails it. Local dirty runs remain useful diagnostics, but cannot satisfy the clean-checkout CI evidence gate. Runtime passwords are generated per run and written to a private environment file. The file is removed after successful cleanup and retained privately if cleanup fails so the project can be recovered. Do not share it or raw Docker configuration output.

For a failed run, read the sanitized report first. Authentication or license failures require correcting that service prerequisite; timeouts and capacity failures require checking the recorded runtime resources. A preservation or native-query mismatch is a product failure to investigate, never a reason to disable assertions. Keep the source tree unchanged during a run, or the identity check will fail.

Normal cleanup removes only resources labelled for that run's Compose project. If a process terminates unexpectedly, verify resource-reaper cleanup. If cleanup fails, the report identifies the project. From the repository root, replace the placeholder below with the exact `project` from that report, then use its retained private environment file:

```bash
SIEM_PROJECT='hdf-siem-<id-from-report>'
docker compose --project-name "$SIEM_PROJECT" \
  --env-file "test/siem/.runs/$SIEM_PROJECT/runtime.env" \
  -f test/siem/compose.yaml --profile '*' down --volumes --timeout 30
```

The explicit project name limits removal to that run; enabling all profiles includes either target. Do not prune the Docker daemon or remove unrelated images or volumes. After successful recovery, remove that run's private `runtime.env`; retain its sanitized report.

## Ingestion and preservation

Full mode uses the selected target suite's `verify` export with the built CLI, installed TypeScript consumer, service handles and raw-response helper. It fails before service startup when a requested target suite is not implemented. Run the Elasticsearch suite from the repository root:

```sh
node --env-file=test/siem/.env.example test/siem/run.mjs --target elasticsearch
```

The suite creates indices using `hdf-converters/shared/ecs-bundle-mapping.json`: ordinary stored `_source`, with `hdf.source` mapped as an object with `enabled: false`. Elasticsearch retains that preservation payload without dynamically indexing its members. Normal finding fields remain searchable. This mapping must be supplied when creating an index for these exports; the converter does not configure a server. Synthetic `_source` is outside the accepted preservation contract.

The existing legacy `hdf.tags` copy remains dynamically indexed, including schema-open tag members. Conflicting types there can still reject an event; disabling indexing for `hdf.source` does not change legacy exporter defaults.

Impact and effective impact use explicit `double` mappings; CVSS base score uses the [ECS 9.4.0-defined `float` type](https://github.com/elastic/ecs/blob/v9.4.0/schemas/vulnerability.yml). Letting Elasticsearch infer these types from an initial integer value can silently truncate later fractional values and produce incorrect numeric query results, even when `_source` remains intact.

Each CLI and installed TypeScript case is ingested as raw NDJSON. The suite checks every bulk item, retrieves every occurrence through the raw `_source` endpoint, and uses the existing resolver to compare the full requirement and baseline while recovering byte-exact source data. Source expectations drive count, outcome, raw status, impact and CVE severity queries. Occurrence IDs used for test ingestion keep duplicate requirement IDs distinct.

CLI exports supply an evidence-package archive. TypeScript exports are packaged with the existing `hdf evidence build`, `add-evidence` and `bundle` commands. Readback checks all three selected artifact checksums through the installed engine and exercises package-first CLI recovery. Missing or altered source/events/manifest files, ambiguous references and changed carried records must fail. Embedded signatures are preserved; these tests do not authenticate their signers.

Per-case report entries include source fingerprints, finding/query counts and the byte sizes of events, source, manifest, evidence package, their uncompressed total and the ZIP archive. Bulk requests are accumulated in approximately 5 MiB batches; a single larger event stays intact. The HTTP helper bounds responses at 128 MiB. These are harness limits, not production capacity claims. The large assessment checks every finding and can take several minutes per producer.

Existing source fixtures are referenced through `test/siem/cases.json`, without copying or rewriting them. Their provenance distinguishes real output with schema adaptations from authored schema-confirmed cases. The matrix includes the large InSpec assessment, CVE, waiver, risk adjustment and negative zero. Runtime adaptations add duplicate IDs, an empty assessment, signature carriage, null/absent members, Unicode, large strings and a numeric token beyond JavaScript's safe integer range. The current CLI validates each generated document before conversion; `test/siem/provenance.txt` records those adaptations. They are not captured scanner output.

### Splunk ingestion and retrieval

After the same terms and optional emulation opt-ins, run:

```sh
node --env-file=test/siem/.env.example test/siem/run.mjs --target splunk
```

The suite installs the repository's existing `Splunk_TA_hdf` into the disposable container and restarts it through Testcontainers. It checks the effective `KV_MODE=json` and `TRUNCATE=0` settings, submits the original HEC envelopes with a test-index routing field, and polls search visibility. It uses the supported v2 search-result endpoints; the older event/result endpoints are disabled in current Splunk releases.

Each retrieved `_raw` string is wrapped as an HEC `event` without parsing and reserializing its inner JSON. The same package/source/record checks used by Elasticsearch then verify every occurrence. Native status, suppression and severity queries, event types and tags are checked against source expectations. The harness also requires every present indexed scalar to remain single-valued and every returned value to match the exported payload exactly, including multiline titles. This verifies the add-on's tag eligibility; it does not install the separate CIM add-on or claim accelerated Vulnerabilities data-model verification.

HEC already indexes the exporter's flat native `fields`. JSON extraction can add duplicate values from the payload and make grouped statistics count a finding twice; multiline titles can also appear as both whitespace-normalized and original strings. The add-on's native `EVAL-<field> = spath(_raw,"<field>")` calculated fields read each scalar from the original event JSON after extraction. The tests keep ordinary grouped queries, explicit multiplicity checks and exact-value comparisons; they do not compensate with query-level deduplication. Indexed-only queries such as `tstats` are unaffected by these search-time calculations.

Requests use approximately 5 MiB batches while keeping each event intact, and raw retrieval uses pages of 100 events. Reports record observed HTTP content and JSON extraction limits, plus the HEC event-size setting when explicitly configured. An unset event-size setting is reported as such alongside the vendor's documented 5 MB default, not as a measured override. The boundary fixture exercises an event larger than 4 MiB. Disposable test indices use 100-year retention so the original fixture timestamps remain searchable as the tests age; teardown removes those indices with their containers. These settings qualify this test environment, not arbitrary production deployments.

Vendor references: [HEC inputs and event limits](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/inputs.conf), [search endpoints](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions), and [index retention](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/indexes.conf).
