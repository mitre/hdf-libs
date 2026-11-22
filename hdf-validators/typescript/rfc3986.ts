/**
 * RFC 3986 `uri` and `uri-reference`, transcribed from the ABNF.
 *
 * §2 fixes the characters a URI may contain and §3 to §4.2 the grammar they have to
 * form, and neither shipped library implements both halves. ajv-formats applies a
 * character-level regex that misses §4.2's rule against a colon in a relative
 * reference's first segment, so it accepts git@github.com:mitre/x.git; the Go
 * engine's net/url accepts a space, '<', '|', '^', a backtick, braces and non-ASCII
 * that §2 excludes. Matching either would import its errors, so both are replaced.
 */

const UNRESERVED = String.raw`A-Za-z0-9\-._~`;
const SUB_DELIMS = "!$&'()*+,;=";
const PCT_ENCODED = String.raw`(?:%[0-9A-Fa-f]{2})`;
const PCHAR = `(?:[${UNRESERVED}${SUB_DELIMS}:@]|${PCT_ENCODED})`;
const SEGMENT = `${PCHAR}*`;
const SEGMENT_NZ = `${PCHAR}+`;
/** §4.2: the first segment of a relative path excludes the colon, so a reader cannot
 * mistake it for a scheme. */
const SEGMENT_NZ_NC = `(?:[${UNRESERVED}${SUB_DELIMS}@]|${PCT_ENCODED})+`;
const SCHEME = String.raw`[A-Za-z][A-Za-z0-9+\-.]*`;
const USERINFO = `(?:[${UNRESERVED}${SUB_DELIMS}:]|${PCT_ENCODED})*`;
const REG_NAME = `(?:[${UNRESERVED}${SUB_DELIMS}]|${PCT_ENCODED})*`;
/** What sits between the brackets is settled by validIpLiteral; the grammar only has
 * to find its extent. */
const IP_LITERAL = String.raw`\[[^\[\]]*\]`;
const HOST = `(?:${IP_LITERAL}|${REG_NAME})`;
const AUTHORITY = `(?:${USERINFO}@)?${HOST}(?::[0-9]*)?`;
const PATH_ABEMPTY = `(?:/${SEGMENT})*`;
const PATH_ABSOLUTE = `/(?:${SEGMENT_NZ}(?:/${SEGMENT})*)?`;
const PATH_ROOTLESS = `${SEGMENT_NZ}(?:/${SEGMENT})*`;
const PATH_NOSCHEME = `${SEGMENT_NZ_NC}(?:/${SEGMENT})*`;
const QUERY_OR_FRAGMENT = `(?:${PCHAR}|[/?])*`;
const HIER_PART = `(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_ROOTLESS}|)`;
const RELATIVE_PART = `(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_NOSCHEME}|)`;
const TAIL = String.raw`(?:\?${QUERY_OR_FRAGMENT})?(?:#${QUERY_OR_FRAGMENT})?`;
const URI = `${SCHEME}:${HIER_PART}${TAIL}`;
const RELATIVE_REF = `${RELATIVE_PART}${TAIL}`;

const RX_URI = new RegExp(`^(?:${URI})$`);
const RX_URI_REFERENCE = new RegExp(`^(?:${URI}|${RELATIVE_REF})$`);
const RX_SCHEME = new RegExp(`^${SCHEME}$`);
const RX_IPV_FUTURE = new RegExp(`^[vV][0-9A-Fa-f]+\\.[${UNRESERVED}${SUB_DELIMS}:]+$`);
const RX_IPV6_GROUP = /^[0-9A-Fa-f]{1,4}$/;
const RX_IPV4 =
  /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/;

/** Whether value satisfies RFC 3986 §3's URI production. */
export function isUri(value: string): boolean {
  return RX_URI.test(value) && validIpLiteral(value);
}

/** Whether value satisfies §4.1: a URI or a relative reference. */
export function isUriReference(value: string): boolean {
  return RX_URI_REFERENCE.test(value) && validIpLiteral(value);
}

/**
 * Settles the bracketed host, which §3.2.2 restricts to an IPv6 address or an
 * IPvFuture. Finding it means stepping past a scheme and into the authority, because
 * a colon or a `//` elsewhere in the value is not one.
 */
function validIpLiteral(value: string): boolean {
  let rest = value;
  const colon = rest.indexOf(':');
  if (colon >= 0 && RX_SCHEME.test(rest.slice(0, colon))) rest = rest.slice(colon + 1);
  if (!rest.startsWith('//')) return true;
  let authority = rest.slice(2);
  const pathStart = authority.search(/[/?#]/);
  if (pathStart >= 0) authority = authority.slice(0, pathStart);
  // Only an authority that does NOT open with the bracket can carry userinfo: §3.2.1
  // excludes '@' and '[' from it, so an '@' between brackets belongs to the host, and
  // stripping at it skipped this check altogether.
  if (!authority.startsWith('[')) {
    const at = authority.indexOf('@');
    if (at >= 0) authority = authority.slice(at + 1);
  }
  if (!authority.startsWith('[')) return true;
  const end = authority.indexOf(']');
  // Unreachable while the pattern requires the closing bracket; kept so a looser
  // pattern cannot turn this into a slice of the wrong extent.
  if (end < 0) return false;
  const body = authority.slice(1, end);
  if (body.startsWith('v') || body.startsWith('V')) return RX_IPV_FUTURE.test(body);
  return validIpv6(body);
}

/**
 * RFC 4291 §2.2: eight 16-bit groups, at most one `::` run standing for one or more
 * zero groups, and an optional dotted quad standing for the last two. The Go peer
 * counts the same way, so the two cannot drift.
 */
function validIpv6(value: string): boolean {
  const halves = value.split('::');
  if (halves.length > 2) return false;
  let total = 0;
  for (const [i, half] of halves.entries()) {
    const count = ipv6GroupCount(half, i === halves.length - 1);
    if (count === undefined) return false;
    total += count;
  }
  return halves.length === 2 ? total <= 7 : total === 8;
}

/** Groups on one side of the elision, or undefined if one is malformed; a dotted quad
 * counts for two. ls32 is the address's LAST 32 bits, so it is accepted only in the
 * trailing half — counting it on the left made 1.2.3.4::1 valid. */
function ipv6GroupCount(part: string, trailing: boolean): number | undefined {
  if (part === '') return 0;
  const groups = part.split(':');
  let count = 0;
  for (const [i, group] of groups.entries()) {
    if (trailing && i === groups.length - 1 && RX_IPV4.test(group)) {
      count += 2;
      continue;
    }
    if (!RX_IPV6_GROUP.test(group)) return undefined;
    count += 1;
  }
  return count;
}
