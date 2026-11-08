---
title: Local SIEM integration testing
description: Start isolated Elasticsearch and Splunk test services with Testcontainers and verify current HDF artifacts.
---

# Local SIEM integration testing

Use this development harness to qualify real SIEM services before testing HDF export preservation. Testcontainers Node manages a shared Docker Compose definition; each run uses a private directory and matching project name with a 128-bit lowercase random identifier, plus generated credentials. Published HDF packages do not depend on Testcontainers.

The environment smoke test is implemented. Elasticsearch 9.5.6 and the pinned Splunk image (reporting version 10.6.1.1) passed authenticated readiness, license checks and cleanup together. The current CLI build and packed TypeScript consumer also passed. Target ingestion/readback suites remain separate work; environment readiness alone is not preservation verification.

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
node --test test/siem/run.test.mjs test/siem/harness.test.mjs
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

## Reports and cleanup

Private run directories live under the ignored `test/siem/.runs/` directory. Each contains a sanitized `report.json`; full runs also retain their local package artifacts. Runtime passwords are generated per run and written to a private environment file. The file is removed after successful cleanup and retained privately if cleanup fails so the project can be recovered. Do not share it or raw Docker configuration output.

Normal cleanup removes only resources labelled for that run's Compose project. If a process terminates unexpectedly, verify resource-reaper cleanup. If cleanup fails, the report identifies the project. Use that exact project and its private `runtime.env` with the repository's Compose file for a project-scoped `docker compose down --volumes`; do not prune the Docker daemon or remove unrelated images or volumes.

## Ingestion and preservation

Full mode uses the selected target suite's `verify` export with the built CLI, installed TypeScript consumer, service handles and raw-response helper. It fails before service startup when a requested target suite is not implemented. The Elasticsearch and Splunk target suites are separate implementation work; no live ingestion/readback PASS is claimed by this environment page.

Existing source fixtures are referenced through `test/siem/cases.json`, without copying or rewriting them. Their provenance distinguishes real output with schema adaptations from authored schema-confirmed cases. Artifact preparation validates inputs and records their SHA256 and byte length. Target tests must still prove exact preserved-record retrieval, artifact integrity, native queries, limits and explicit rejection of tampering.
