// Splunk fetcher — auth-agnostic TS API.
//
// Per the project rule (see `/build-fetcher` and `fetchers/README.md`):
// this library accepts a pre-authenticated `splunkjs.Service` instance.
// Callers (heimdall2, saf-cli) configure auth their way and pass the
// resulting Service in. The library never sees username/password/token.

import type { Service } from 'splunk-sdk';
import { convertHdfToSplunk } from '../../../converters/hdf-to-splunk/typescript/converter.js';
import { convertSplunkToHdf } from '../../../converters/splunk-to-hdf/typescript/converter.js';

const PUSH_SOURCETYPE = 'HDF2Splunk';
const PUSH_RECEIVER_PATH = 'receivers/simple';
const PUSH_CHUNK_SIZE = 100;

export interface FetchOptions {
  index: string;
  guid: string;
}

export interface PushOptions {
  index: string;
  /** Override the default `sourcetype=HDF2Splunk` query param. */
  sourcetype?: string;
}

/**
 * Returns true if the Service can authenticate against the server.
 * Returns false on 401/403; throws on transport errors.
 */
export async function verifySplunkCredentials(service: Service): Promise<boolean> {
  try {
    const resp = await service.serverInfo();
    return isSuccess(resp.status);
  } catch (err: unknown) {
    if (isAuthError(err)) return false;
    throw err;
  }
}

/**
 * Search a Splunk index for HDF events tagged with the given GUID and
 * convert the result through `splunk-to-hdf`. Returns the HDF Results JSON.
 *
 * The query mirrors the heimdall2 read path: `search index=<index>
 * meta.guid=<guid> | fields _raw`.
 */
export async function fetchSplunkToHdf(service: Service, opts: FetchOptions): Promise<string> {
  assertSafeIdentifier('index', opts.index);
  assertSafeIdentifier('guid', opts.guid);

  // Service.post-with-blocking-search returns once the search has run.
  // The body has `entry[].content` per the Splunk REST convention.
  const body = await postJSON(service, 'search/jobs', {
    exec_mode: 'blocking',
    search: `search index=${q(opts.index)} meta.guid=${q(opts.guid)} | fields _raw`,
    output_mode: 'json',
  });
  const sid = extractSearchSID(body);
  if (!sid) throw new Error('splunk: search submission returned no SID');

  const results = await getJSON(service, `search/v2/jobs/${encodeURIComponent(sid)}/results`, {
    output_mode: 'json_rows',
    count: 100000,
  });

  const events = extractRawEvents(results);
  return convertSplunkToHdf(JSON.stringify(events));
}

/**
 * Convert HDF Results to Splunk records via `hdf-to-splunk` and upload them
 * to the configured index. Uploads use the `/services/receivers/simple`
 * endpoint to match the heimdall2 wire contract.
 */
export async function pushHdfToSplunk(
  service: Service,
  hdfBytes: string,
  opts: PushOptions,
): Promise<void> {
  assertSafeIdentifier('index', opts.index);

  // Convert first so a malformed HDF input fails fast (before the
  // pre-flight network round-trip).
  const splunkPayload = convertHdfToSplunk(hdfBytes);
  let parsed: { reports: unknown[]; profiles: unknown[]; controls: unknown[] };
  try {
    parsed = JSON.parse(splunkPayload) as typeof parsed;
  } catch (err: unknown) {
    throw new Error(`splunk: parsing converted records: ${errMessage(err)}`);
  }

  await assertIndexExists(service, opts.index);

  const sourcetype = opts.sourcetype ?? PUSH_SOURCETYPE;
  const baseParams = { sourcetype, index: opts.index, output_mode: 'json' };

  // Report: one POST per record (typically one record total).
  for (const r of parsed.reports) {
    await postNDJSON(service, PUSH_RECEIVER_PATH, [r], baseParams);
  }

  // Profiles: one POST with all records as NDJSON.
  if (parsed.profiles.length > 0) {
    await postNDJSON(service, PUSH_RECEIVER_PATH, parsed.profiles, baseParams);
  }

  // Controls: chunk by PUSH_CHUNK_SIZE.
  for (let i = 0; i < parsed.controls.length; i += PUSH_CHUNK_SIZE) {
    const chunk = parsed.controls.slice(i, i + PUSH_CHUNK_SIZE);
    await postNDJSON(service, PUSH_RECEIVER_PATH, chunk, baseParams);
  }
}

// ---- helpers ----

// Same regex as the Go side: identifiers must be alphanumeric + _.- and
// start with alphanumeric. Prevents SPL injection / path traversal.
const SAFE_IDENT = /^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$/;

function assertSafeIdentifier(name: string, value: string): void {
  if (!value) throw new Error(`splunk: ${name} is required`);
  if (!SAFE_IDENT.test(value)) {
    throw new Error(
      `splunk: ${name} contains invalid characters: only alphanumeric, underscore, dot, and hyphen allowed`,
    );
  }
}

function q(s: string): string {
  // s is pre-validated by assertSafeIdentifier so JSON.stringify is sufficient.
  return JSON.stringify(s);
}

async function assertIndexExists(service: Service, index: string): Promise<void> {
  try {
    const resp = await service.get(`data/indexes/${encodeURIComponent(index)}`, {
      output_mode: 'json',
    });
    if (!isSuccess(resp.status)) {
      throw new Error(`splunk: index preflight returned HTTP ${resp.status}`);
    }
  } catch (err: unknown) {
    if (isNotFound(err)) {
      throw new Error(
        `splunk: index "${index}" does not exist on the target Splunk instance`,
      );
    }
    throw err;
  }
}

async function postNDJSON(
  service: Service,
  path: string,
  records: unknown[],
  params: Record<string, unknown>,
): Promise<void> {
  if (records.length === 0) return;
  const body = records.map((r) => JSON.stringify(r)).join('\n');
  const resp = await service.post(path, { ...params, body });
  if (!isSuccess(resp.status)) {
    throw new Error(`splunk receivers/simple returned HTTP ${resp.status}`);
  }
}

async function postJSON(
  service: Service,
  path: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const resp = await service.post(path, params);
  if (!isSuccess(resp.status)) {
    throw new Error(`splunk ${path} returned HTTP ${resp.status}`);
  }
  return resp.body;
}

async function getJSON(
  service: Service,
  path: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const resp = await service.get(path, params);
  if (!isSuccess(resp.status)) {
    throw new Error(`splunk ${path} returned HTTP ${resp.status}`);
  }
  return resp.body;
}

function isSuccess(status: number): boolean {
  return status >= 200 && status < 300;
}

function isAuthError(err: unknown): boolean {
  const status = (err as { status?: number })?.status;
  return status === 401 || status === 403;
}

function isNotFound(err: unknown): boolean {
  return (err as { status?: number })?.status === 404;
}

function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function extractSearchSID(body: unknown): string | undefined {
  if (typeof body !== 'object' || body === null) return undefined;
  const v = (body as { sid?: unknown }).sid;
  return typeof v === 'string' ? v : undefined;
}

function extractRawEvents(body: unknown): unknown[] {
  if (typeof body !== 'object' || body === null) return [];
  const { fields, rows } = body as { fields?: unknown; rows?: unknown };
  if (!Array.isArray(fields) || !Array.isArray(rows)) return [];
  const rawIdx = fields.findIndex(
    (f) => typeof f === 'object' && f !== null && (f as { name?: string }).name === '_raw',
  );
  if (rawIdx < 0) return [];
  const events: unknown[] = [];
  for (const row of rows) {
    if (!Array.isArray(row) || rawIdx >= row.length) continue;
    const cell = row[rawIdx];
    if (typeof cell !== 'string') continue;
    try {
      events.push(JSON.parse(cell));
    } catch {
      // Skip un-parseable _raw cells (matches the Go side's json.Valid guard).
    }
  }
  return events;
}
