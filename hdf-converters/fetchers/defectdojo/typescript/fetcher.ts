// DefectDojo fetcher (TypeScript) — auth-agnostic.
//
// Per the fetchers README security contract, this library never receives
// credentials, env lookups, or TLS config. The caller supplies a
// pre-authenticated transport (`authFetch`) that injects the DefectDojo
// `Authorization: Token …` header. The fetcher paginates /api/v2/findings/
// and pipes the assembled bytes through the defectdojo-to-hdf converter.

import {convertDefectDojoToHdf} from '../../../converters/defectdojo-to-hdf/typescript/converter.js';

/** A pre-authenticated transport: resolves a path against the DefectDojo base URL and injects auth. */
export type AuthFetch = (path: string, init?: RequestInit) => Promise<Response>;

export interface DefectDojoFetchOptions {
  productName?: string;
  engagementId?: string;
  testId?: string;
  /** Pagination cap (default 200). */
  maxPages?: number;
  converterVersion?: string;
}

const PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 200;

interface FindingsPage {
  next?: string | null;
  results?: unknown[];
}

function firstPath(options: DefectDojoFetchOptions): string {
  const q = new URLSearchParams({related_fields: 'true', limit: String(PAGE_SIZE)});
  if (options.productName) q.set('product_name', options.productName);
  if (options.engagementId) q.set('test__engagement', options.engagementId);
  if (options.testId) q.set('test', options.testId);
  return `/api/v2/findings/?${q.toString()}`;
}

/** Reduce a DefectDojo `next` link (a full URL) to a path the transport can resolve. */
function nextPath(next: string): string {
  try {
    const u = new URL(next);
    return u.pathname + u.search;
  } catch {
    return next; // already a path
  }
}

/**
 * Fetch every page of DefectDojo findings and convert to HDF Results.
 * The caller-supplied `authFetch` owns credentials and transport.
 */
export async function fetchDefectDojoToHdf(authFetch: AuthFetch, options: DefectDojoFetchOptions = {}): Promise<string> {
  const maxPages = options.maxPages && options.maxPages > 0 ? options.maxPages : DEFAULT_MAX_PAGES;
  const results: unknown[] = [];

  let path: string | null = firstPath(options);
  for (let page = 0; path !== null; page++) {
    if (page >= maxPages) {
      throw new Error(`defectdojo: exceeded maximum page limit (${maxPages})`);
    }
    const resp = await authFetch(path);
    if (!resp.ok) {
      throw new Error(`defectdojo: unexpected status ${resp.status}`);
    }
    const pageData = (await resp.json()) as FindingsPage;
    if (Array.isArray(pageData.results)) results.push(...pageData.results);
    path = pageData.next ? nextPath(pageData.next) : null;
  }

  const assembled = JSON.stringify({results});
  return convertDefectDojoToHdf(assembled, options.converterVersion);
}

/** Verify credentials with a single lightweight request (backs `--check`). */
export async function verifyDefectDojoCredentials(authFetch: AuthFetch): Promise<void> {
  const resp = await authFetch('/api/v2/user_profile/');
  if (!resp.ok) {
    throw new Error(`defectdojo: credential verification failed (status ${resp.status})`);
  }
}
