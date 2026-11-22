package hdfvalidators

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/xeipuuv/gojsonschema"
)

// gojsonschema's built-in uuid and date-time checkers disagree with every other
// validator in this repo, and with the RFCs. Its uuid pattern is anchored to
// lowercase hex, so it rejects 3F2504E0-… even though RFC 4122 §3 requires
// readers to accept either case. Its date-time checker rejects a lowercase `t`
// and a leap second, both of which RFC 3339 §5.6 and §5.7 permit, and accepts a
// bare date as a date-time, which is not one. Since hdf-validators and the
// TypeScript validator are a public API pair, that made `hdf validate` disagree
// with validateResults about whether a document is valid HDF, at 48 uuid and 113
// date-time sites across the schemas.
//
// These replacements match ajv-formats, which the TypeScript half uses, so the
// two agree. Both languages' verdicts are pinned by ../testdata/shipped-format-cases.json.

var (
	// Case-insensitive, and the urn:uuid: prefix ajv also accepts. Version and
	// variant nibbles are deliberately not enforced: ajv does not enforce them,
	// and a validator that rejected a v8 or Nil UUID would reject valid input.
	rxRFC4122 = regexp.MustCompile(`(?i)^(?:urn:uuid:)?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

	rxRFC3339Date = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
	// The offset is required — RFC 3339 date-time has no floating form — but its
	// shape is deliberately looser than the RFC: ajv-formats accepts an hour-only
	// "+05" and a basic-format "+0530", so rejecting them here would make the
	// shipped Go validator disagree with its TypeScript peer, which is the
	// divergence this file exists to close. Both shapes are pinned in
	// ../testdata/shipped-format-cases.json.
	rxRFC3339Time = regexp.MustCompile(`(?i)^(\d\d):(\d\d):(\d\d(?:\.\d+)?)(?:(z)|([+-])(\d\d):?(\d\d)?)$`)

	daysInMonth = [...]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

	registerOnce sync.Once
)

// RegisterRFCFormatCheckers replaces gojsonschema's uuid and date-time checkers
// with RFC-correct ones. gojsonschema keeps format checkers in a process-global
// registry, so this affects every gojsonschema consumer in the process — which is
// the intent: the alternative is one library in this repo calling a document valid
// while another calls it invalid. It is idempotent, and the package registers on
// init so simply importing hdf-validators is enough.
func RegisterRFCFormatCheckers() {
	registerOnce.Do(func() {
		gojsonschema.FormatCheckers.
			Add("uuid", rfc4122Checker{}).
			Add("date-time", rfc3339Checker{})
	})
}

func init() { RegisterRFCFormatCheckers() }

type rfc4122Checker struct{}

func (rfc4122Checker) IsFormat(input any) bool {
	s, ok := input.(string)
	return ok && IsUUID(s)
}

// IsUUID reports whether s satisfies the schemas' `format: uuid`, so a caller can
// refuse a value before writing it into a document that would then fail validation.
func IsUUID(s string) bool {
	return rxRFC4122.MatchString(s)
}

type rfc3339Checker struct{}

// IsFormat splits the date from the time and validates each half; splitting
// rather than matching one pattern is what lets the leap-second rule see the
// offset it needs. RFC 3339 §5.6 permits a space in place of the T "by mutual
// agreement", and ajv-formats takes it — but HDF's canonical timestamp does not,
// so every validator in this repo requires the separator. The TypeScript peers
// are tightened to match rather than the reverse, because a document this
// accepts must be one every HDF producer here would emit.
func (rfc3339Checker) IsFormat(input any) bool {
	s, ok := input.(string)
	if !ok {
		return false
	}
	i := strings.IndexAny(s, "Tt")
	if i < 0 {
		return false
	}
	return validRFC3339Date(s[:i]) && validRFC3339Time(s[i+1:])
}

func validRFC3339Date(s string) bool {
	m := rxRFC3339Date.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	if month < 1 || month > 12 || day < 1 {
		return false
	}
	if month == 2 && !isLeapYear(year) {
		return day <= 28
	}
	return day <= daysInMonth[month]
}

func isLeapYear(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}

// validRFC3339Time accepts second 60 only where a leap second can occur: the
// instant must be 23:59:60 in UTC once the offset is applied.
func validRFC3339Time(s string) bool {
	m := rxRFC3339Time.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	hour, _ := strconv.Atoi(m[1])
	minute, _ := strconv.Atoi(m[2])
	sec, _ := strconv.ParseFloat(m[3], 64)
	offsetHour, _ := strconv.Atoi(m[6])
	offsetMinute, _ := strconv.Atoi(m[7])
	if hour > 23 || minute > 59 || offsetHour > 23 || offsetMinute > 59 {
		return false
	}
	if sec < 60 {
		return true
	}
	if sec >= 61 {
		return false
	}
	sign := 1
	if m[5] == "-" {
		sign = -1
	}
	utcMinute := minute - offsetMinute*sign
	utcHour := hour - offsetHour*sign
	if utcMinute < 0 {
		utcHour--
	}
	return (utcHour == 23 || utcHour == -1) && (utcMinute == 59 || utcMinute == -1)
}

func registerModernFormats(compiler *jsonschema.Compiler) {
	for name, accepts := range map[string]func(string) bool{
		"uuid":          IsUUID,
		"date-time":     func(s string) bool { return rfc3339Checker{}.IsFormat(s) },
		"uri":           IsURI,
		"uri-reference": IsURIReference,
	} {
		compiler.RegisterFormat(&jsonschema.Format{Name: name, Validate: func(value any) error {
			s, ok := value.(string)
			if !ok {
				return nil
			}
			if accepts(s) {
				return nil
			}
			return fmt.Errorf("invalid %s", name)
		}})
	}
}

// RFC 3986 §2 fixes the characters a URI may contain and §3 to §4.2 the grammar
// they have to form; neither shipped library implements both halves. The modern Go
// engine hands the value to net/url, which accepts a space, '<', '|', '^', a
// backtick, braces and non-ASCII that §2 excludes. ajv-formats applies a
// character-level regex that misses §4.2's rule against a colon in a relative
// reference's first segment, so it accepts git@github.com:mitre/x.git. The two lean
// opposite ways, so matching either would import its errors rather than reconcile
// the pair. These patterns transcribe the ABNF instead, and the verdicts are pinned
// for both languages by ../testdata/shipped-format-cases.json.
const (
	cUnreserved = `A-Za-z0-9\-._~`
	cSubDelims  = `!$&'()*+,;=`
	pPctEncoded = `(?:%[0-9A-Fa-f]{2})`
	pPchar      = `(?:[` + cUnreserved + cSubDelims + `:@]|` + pPctEncoded + `)`
	pSegment    = pPchar + `*`
	pSegmentNz  = pPchar + `+`
	// §4.2: the first segment of a relative path excludes the colon, so a reader
	// cannot mistake it for a scheme.
	pSegmentNzNc = `(?:[` + cUnreserved + cSubDelims + `@]|` + pPctEncoded + `)+`
	pScheme      = `[A-Za-z][A-Za-z0-9+\-.]*`
	pUserinfo    = `(?:[` + cUnreserved + cSubDelims + `:]|` + pPctEncoded + `)*`
	pRegName     = `(?:[` + cUnreserved + cSubDelims + `]|` + pPctEncoded + `)*`
	// What sits between the brackets is settled by validIPLiteral; the grammar only
	// has to find the extent, which keeps the pattern backtracking-free.
	pIPLiteral    = `\[[^\[\]]*\]`
	pHost         = `(?:` + pIPLiteral + `|` + pRegName + `)`
	pAuthority    = `(?:` + pUserinfo + `@)?` + pHost + `(?::[0-9]*)?`
	pPathAbempty  = `(?:/` + pSegment + `)*`
	pPathAbsolute = `/(?:` + pSegmentNz + `(?:/` + pSegment + `)*)?`
	pPathRootless = pSegmentNz + `(?:/` + pSegment + `)*`
	pPathNoscheme = pSegmentNzNc + `(?:/` + pSegment + `)*`
	pQueryOrFrag  = `(?:` + pPchar + `|[/?])*`
	pHierPart     = `(?://` + pAuthority + pPathAbempty + `|` + pPathAbsolute + `|` + pPathRootless + `|)`
	pRelativePart = `(?://` + pAuthority + pPathAbempty + `|` + pPathAbsolute + `|` + pPathNoscheme + `|)`
	pTail         = `(?:\?` + pQueryOrFrag + `)?(?:#` + pQueryOrFrag + `)?`
	pURI          = pScheme + `:` + pHierPart + pTail
	pRelativeRef  = pRelativePart + pTail
)

var (
	rxURI       = regexp.MustCompile(`\A(?:` + pURI + `)\z`)
	rxURIRef    = regexp.MustCompile(`\A(?:` + pURI + `|` + pRelativeRef + `)\z`)
	rxScheme    = regexp.MustCompile(`\A` + pScheme + `\z`)
	rxIPvFuture = regexp.MustCompile(`\A[vV][0-9A-Fa-f]+\.[` + cUnreserved + cSubDelims + `:]+\z`)
	rxIPv6Group = regexp.MustCompile(`\A[0-9A-Fa-f]{1,4}\z`)
	rxIPv4      = regexp.MustCompile(
		`\A(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}` +
			`(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\z`)
)

// IsURI reports whether s satisfies RFC 3986 §3's URI production, so a caller can refuse
// a value before writing it into a document that would then fail validation.
func IsURI(s string) bool { return rxURI.MatchString(s) && validIPLiteral(s) }

// IsURIReference reports whether s satisfies §4.1: a URI or a relative reference. The
// same purpose as IsURI — a producer recording a reference checks it before writing.
func IsURIReference(s string) bool { return rxURIRef.MatchString(s) && validIPLiteral(s) }

// validIPLiteral settles the bracketed host, which §3.2.2 restricts to an IPv6
// address or an IPvFuture. Finding it means stepping past a scheme and into the
// authority, because a colon or a `//` elsewhere in the value is not one.
func validIPLiteral(s string) bool {
	rest := s
	if i := strings.Index(rest, ":"); i >= 0 && rxScheme.MatchString(rest[:i]) {
		rest = rest[i+1:]
	}
	if !strings.HasPrefix(rest, "//") {
		return true
	}
	authority := rest[2:]
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	// Only an authority that does NOT open with the bracket can carry userinfo: §3.2.1
	// excludes "@" and "[" from it, so an "@" between brackets belongs to the host, and
	// stripping at it skipped this check altogether.
	if !strings.HasPrefix(authority, "[") {
		if i := strings.Index(authority, "@"); i >= 0 {
			authority = authority[i+1:]
		}
	}
	if !strings.HasPrefix(authority, "[") {
		return true
	}
	end := strings.Index(authority, "]")
	// Unreachable while the pattern requires the closing bracket; kept because a looser
	// pattern would make the slice below panic.
	if end < 0 {
		return false
	}
	body := authority[1:end]
	if body != "" && (body[0] == 'v' || body[0] == 'V') {
		return rxIPvFuture.MatchString(body)
	}
	return validIPv6(body)
}

// validIPv6 implements RFC 4291 §2.2: eight 16-bit groups, at most one `::` run
// standing for one or more zero groups, and an optional dotted quad standing for
// the last two. The TypeScript peer counts the same way, so the two cannot drift.
func validIPv6(s string) bool {
	halves := strings.SplitN(s, "::", 3)
	if len(halves) > 2 {
		return false
	}
	total := 0
	for i, half := range halves {
		n, ok := ipv6GroupCount(half, i == len(halves)-1)
		if !ok {
			return false
		}
		total += n
	}
	if len(halves) == 2 {
		return total <= 7
	}
	return total == 8
}

// ipv6GroupCount counts the groups on one side of the elision, reporting false on a
// malformed one; a dotted quad counts for two. ls32 is the address's LAST 32 bits, so it
// is accepted only in the trailing half — counting it on the left made 1.2.3.4::1 valid.
func ipv6GroupCount(part string, trailing bool) (int, bool) {
	if part == "" {
		return 0, true
	}
	groups := strings.Split(part, ":")
	count := 0
	for i, g := range groups {
		if trailing && i == len(groups)-1 && rxIPv4.MatchString(g) {
			count += 2
			continue
		}
		if !rxIPv6Group.MatchString(g) {
			return 0, false
		}
		count++
	}
	return count, true
}
