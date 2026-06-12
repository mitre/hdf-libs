// Tenable.SC fetcher — auth-agnostic TS API.
//
// Per the project rule (see `fetchers/README.md`): this library accepts a
// caller-supplied `authFetch` callable that pre-injects the x-apikey
// header. The library never sees access keys, secret keys, or any other
// credential material.
//
// The caller (heimdall2, saf-cli) is responsible for constructing the
// authFetch:
//
//   const authFetch: TenableSCAuthFetch = (path, init = {}) =>
//     fetch(new URL(path, 'https://tsc.example.com'), {
//       ...init,
//       headers: {
//         ...init.headers,
//         'x-apikey': `accesskey=${ak}; secretkey=${sk}`,
//       },
//     });

import { unzipSync, strFromU8 } from 'fflate';
import { convertNessusToHdf } from '../../../converters/nessus-to-hdf/typescript/converter.js';
import type { HDFResults } from '@mitre/hdf-schema';

/** Caller-supplied transport that already carries auth headers. */
export type TenableSCAuthFetch = (
  path: string,
  init?: RequestInit,
) => Promise<Response>;

/** A single usable scan result returned by ListScans. */
export interface TenableScanResult {
  id: string;
  name: string;
  description?: string;
  details?: string;
  scannedIPs: string;
  totalChecks?: string;
  startTime: string;
  finishTime: string;
  status: string;
}

export interface ListScansOptions {
  /** Unix seconds. Defaults to 0 (no lower bound). */
  startTime?: number;
  /** Unix seconds. Defaults to "now" at call time. */
  endTime?: number;
}

const LIST_FIELDS =
  'name,description,details,scannedIPs,totalChecks,startTime,finishTime,status';

// Positive integer with no leading zero, up to 18 digits (int64 fit).
const SCAN_ID_PATTERN = /^[1-9][0-9]{0,17}$/;

const ZIP_LOCAL_FILE_MAGIC = [0x50, 0x4b, 0x03, 0x04];
const ZIP_EOCD_MAGIC = [0x50, 0x4b, 0x05, 0x06];

/**
 * Verifies that the supplied authFetch can authenticate against the
 * Tenable.SC server. Returns true on 200, false on 401/403. Other status
 * codes throw — they indicate a network or server problem, not an auth
 * decision.
 */
export async function verifyTenableSCCredentials(
  authFetch: TenableSCAuthFetch,
): Promise<boolean> {
  const resp = await authFetch('/rest/currentUser', { method: 'GET' });
  if (resp.status === 200) return true;
  if (resp.status === 401 || resp.status === 403) return false;
  throw new Error(`tenable.sc verify returned unexpected HTTP ${resp.status}`);
}

/**
 * Lists usable scan results in the configured time window.
 */
export async function listTenableSCScans(
  authFetch: TenableSCAuthFetch,
  opts: ListScansOptions = {},
): Promise<TenableScanResult[]> {
  const startTime = opts.startTime ?? 0;
  const endTime = opts.endTime ?? Math.floor(Date.now() / 1000);

  const path = `/rest/scanResult?fields=${LIST_FIELDS}&startTime=${startTime}&endTime=${endTime}`;
  const resp = await authFetch(path, { method: 'GET' });

  if (resp.status === 401 || resp.status === 403) {
    throw new Error(`tenable.sc list unauthorized (HTTP ${resp.status})`);
  }
  if (resp.status !== 200) {
    throw new Error(`tenable.sc list returned HTTP ${resp.status}`);
  }

  let envelope: { response?: { usable?: TenableScanResult[] } };
  try {
    envelope = (await resp.json()) as typeof envelope;
  } catch (err) {
    throw new Error(`tenable.sc list response: invalid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  return envelope.response?.usable ?? [];
}

/**
 * Downloads a scan result (downloadType=v2) and pipes the extracted
 * .nessus XML through nessus-to-hdf. The response may be either a raw
 * XML body or a zip wrapping a single XML entry; both shapes are
 * handled via magic-byte sniffing on the response bytes.
 */
export async function fetchTenableSCScanToHdf(
  authFetch: TenableSCAuthFetch,
  scanId: string,
): Promise<HDFResults> {
  assertValidScanID(scanId);

  const resp = await authFetch(
    `/rest/scanResult/${scanId}/download?downloadType=v2`,
    { method: 'POST' },
  );

  if (resp.status === 401) {
    throw new Error('tenable.sc download unauthorized (HTTP 401)');
  }
  if (resp.status === 403) {
    throw new Error(
      'tenable.sc download forbidden (HTTP 403) — scan may be incomplete or credentials lack download permission',
    );
  }
  if (resp.status === 404) {
    throw new Error(`tenable.sc scan ${scanId} not found (HTTP 404)`);
  }
  if (resp.status !== 200) {
    throw new Error(`tenable.sc scan ${scanId} download returned HTTP ${resp.status}`);
  }

  const bytes = new Uint8Array(await resp.arrayBuffer());
  const xml = extractNessusXML(bytes);
  return convertNessusToHdf(xml);
}

// ---- helpers ----

function assertValidScanID(scanId: string): void {
  if (!scanId) {
    throw new Error('tenable.sc scan ID is required');
  }
  if (!SCAN_ID_PATTERN.test(scanId)) {
    throw new Error(`tenable.sc scan ID "${scanId}" is invalid: must be a positive integer`);
  }
}

function bytesStartWith(buf: Uint8Array, prefix: number[]): boolean {
  if (buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (buf[i] !== prefix[i]) return false;
  }
  return true;
}

function looksLikeZip(buf: Uint8Array): boolean {
  return bytesStartWith(buf, ZIP_LOCAL_FILE_MAGIC) || bytesStartWith(buf, ZIP_EOCD_MAGIC);
}

function extractNessusXML(buf: Uint8Array): string {
  if (!looksLikeZip(buf)) {
    return strFromU8(buf);
  }

  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(buf);
  } catch (err) {
    throw new Error(`tenable.sc download: invalid zip: ${err instanceof Error ? err.message : String(err)}`);
  }

  const names = Object.keys(entries);
  if (names.length === 0) {
    throw new Error('tenable.sc download: zip is empty');
  }
  // Heimdall2 takes the first entry regardless of name; mirror that
  // and let the nessus converter fail if it isn't XML.
  return strFromU8(entries[names[0]]);
}
