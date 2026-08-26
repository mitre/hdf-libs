package hdfvalidators

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

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
	// The offset is required here: RFC 3339 date-time has no floating form.
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
	return ok && rxRFC4122.MatchString(s)
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
