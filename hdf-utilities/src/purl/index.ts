/**
 * Package URL (PURL) parser for SBOM and CVE-scanner ingestion.
 *
 * PURL is the canonical package identifier used by CycloneDX, SPDX, OSV,
 * GitHub Advisory Database, and most modern scanners. Spec:
 * https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst
 *
 * Grammar: `pkg:type/namespace/name@version?qualifiers#subpath`
 *
 * This parser is intentionally accept-and-warn. Scanners occasionally emit
 * slightly malformed PURLs (qualifier with no `=`, missing name, etc.) and
 * we'd rather record a warning than fail ingestion.
 */

/**
 * Result of parsing a PURL string.
 */
export interface ParsedPurl {
  /** Original input string, unmodified. */
  raw: string;
  /** Package type (e.g., "npm", "rpm", "pypi", "maven"). Lowercased. */
  type: string;
  /** Namespace segment (e.g., "redhat" for RPM, "org.apache..." for Maven). */
  namespace: string | null;
  /** Package name. Empty string (with a warning) if the input lacks one. */
  name: string;
  /** Version after the `@` separator. URL-decoded. */
  version: string | null;
  /** Qualifier key-value pairs from the `?` segment. */
  qualifiers: Map<string, string>;
  /** Subpath from the `#` fragment. */
  subpath: string | null;
  /** Deviations or oddities encountered during parsing. */
  warnings: string[];
}

const PURL_PREFIX = 'pkg:';

/**
 * Parse a Package URL string.
 *
 * Returns `null` only when the input is missing the mandatory `pkg:` prefix
 * or the type segment. Other deviations are surfaced via `warnings` on the
 * returned object.
 *
 * @param purlStr - PURL string, e.g. `pkg:npm/lodash@4.17.21`
 * @returns Parsed PURL or `null` if the input is unrecoverably malformed
 *
 * @example
 * ```typescript
 * const r = parsePurl('pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64');
 * r?.type;                    // "rpm"
 * r?.namespace;               // "redhat"
 * r?.name;                    // "openssl"
 * r?.qualifiers.get('arch');  // "x86_64"
 * ```
 */
export function parsePurl(purlStr: string): ParsedPurl | null {
  if (!purlStr || !purlStr.startsWith(PURL_PREFIX)) {
    return null;
  }

  const raw = purlStr;
  const warnings: string[] = [];

  // Strip prefix. Per spec, scheme is case-insensitive but only `pkg:` is
  // valid; we already matched it.
  let remainder = purlStr.slice(PURL_PREFIX.length);

  // Per spec, leading slashes after the scheme are stripped. This also means
  // `pkg:/foo` and `pkg:foo` are equivalent, but `pkg:/` with no following
  // type segment is still invalid.
  while (remainder.startsWith('/')) {
    remainder = remainder.slice(1);
  }

  if (remainder.length === 0) {
    return null;
  }

  // Extract subpath (fragment). Per spec, the fragment is everything after
  // the first `#`. Splitting before qualifiers keeps `#` inside qualifier
  // values out of scope (which is fine — qualifier values do not legally
  // contain raw `#`; they would be percent-encoded).
  let subpath: string | null = null;
  const hashIdx = remainder.indexOf('#');
  if (hashIdx !== -1) {
    subpath = remainder.slice(hashIdx + 1);
    remainder = remainder.slice(0, hashIdx);
    if (subpath.length === 0) {
      subpath = null;
    }
  }

  // Extract qualifiers (query string). Everything after the first `?`.
  const qualifiers = new Map<string, string>();
  const qIdx = remainder.indexOf('?');
  if (qIdx !== -1) {
    const qStr = remainder.slice(qIdx + 1);
    remainder = remainder.slice(0, qIdx);
    parseQualifiers(qStr, qualifiers, warnings);
  }

  // Strip a trailing slash from the path portion. Spec allows it; we silently
  // normalize.
  while (remainder.endsWith('/')) {
    remainder = remainder.slice(0, -1);
  }

  // Type is everything up to the first `/`.
  const firstSlash = remainder.indexOf('/');
  let type: string;
  let pathPart: string;
  if (firstSlash === -1) {
    type = remainder;
    pathPart = '';
  } else {
    type = remainder.slice(0, firstSlash);
    pathPart = remainder.slice(firstSlash + 1);
  }

  if (type.length === 0) {
    return null;
  }
  type = type.toLowerCase();

  // Split version off the path part. Per spec, the version separator is the
  // LAST `@` in the path — names may contain `@` (e.g., npm scoped packages
  // when not percent-encoded).
  let version: string | null = null;
  const lastAt = pathPart.lastIndexOf('@');
  let nameAndNs = pathPart;
  if (lastAt !== -1) {
    version = pathPart.slice(lastAt + 1);
    nameAndNs = pathPart.slice(0, lastAt);
    version = safeDecode(version);
  }

  // Namespace is everything before the last `/` in the name+namespace
  // section; the final segment is the name.
  let namespace: string | null = null;
  let name: string;
  const lastSlash = nameAndNs.lastIndexOf('/');
  if (lastSlash === -1) {
    name = nameAndNs;
  } else {
    namespace = nameAndNs.slice(0, lastSlash);
    name = nameAndNs.slice(lastSlash + 1);
  }

  // Decode percent-encoded segments.
  if (namespace !== null) {
    // Decode each path segment independently to preserve embedded `/`.
    namespace = namespace.split('/').map(safeDecode).join('/');
  }
  name = safeDecode(name);

  if (name.length === 0) {
    warnings.push('PURL is missing the name segment');
  }

  // Normalize empty namespace to null.
  if (namespace !== null && namespace.length === 0) {
    namespace = null;
  }

  // Normalize empty version to null.
  if (version !== null && version.length === 0) {
    version = null;
  }

  return {
    raw,
    type,
    namespace,
    name,
    version,
    qualifiers,
    subpath,
    warnings,
  };
}

/**
 * Parse the `?key=value&key=value` qualifier string. Empty segments are
 * skipped silently; segments with no `=` are recorded with empty value and
 * a warning. Values are URL-decoded.
 */
function parseQualifiers(
  qStr: string,
  out: Map<string, string>,
  warnings: string[],
): void {
  const parts = qStr.split('&');
  for (const part of parts) {
    if (part.length === 0) {
      continue;
    }
    const eq = part.indexOf('=');
    if (eq === -1) {
      out.set(part, '');
      warnings.push(`qualifier "${part}" has no value`);
      continue;
    }
    const key = part.slice(0, eq);
    const value = part.slice(eq + 1);
    out.set(key, safeDecode(value));
  }
}

/**
 * decodeURIComponent that returns the original string on failure rather than
 * throwing. PURLs in the wild occasionally contain stray `%` characters that
 * aren't legitimate percent-encoding.
 */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
