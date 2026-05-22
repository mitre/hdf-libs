package checklist

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// normalizeStatusKey lowercases and strips spaces/underscores so the various
// spellings (CKL "Not_Applicable", CKLB "not_applicable", "Not Applicable")
// collapse to a single lookup key.
func normalizeStatusKey(s string) string {
	r := strings.ToLower(strings.TrimSpace(s))
	r = strings.ReplaceAll(r, "_", "")
	r = strings.ReplaceAll(r, " ", "")
	return r
}

var statusByKey = map[string]CheckStatus{
	"open":          StatusOpen,
	"notafinding":   StatusNotAFinding,
	"notreviewed":   StatusNotReviewed,
	"notapplicable": StatusNotApplicable,
}

// ParseStatus maps any CKL/CKLB status spelling to the canonical CheckStatus.
// Unknown or empty values map to Not_Reviewed (an unrecorded status is, by
// definition, not yet reviewed).
func ParseStatus(s string) CheckStatus {
	if cs, ok := statusByKey[normalizeStatusKey(s)]; ok {
		return cs
	}
	return StatusNotReviewed
}

// CKLString returns the CKL (STIG Viewer 2.x XML) spelling.
func (s CheckStatus) CKLString() string {
	if s == "" {
		return string(StatusNotReviewed)
	}
	return string(s)
}

// CKLBString returns the CKLB (STIG Viewer 3.x JSON) snake_case spelling.
func (s CheckStatus) CKLBString() string {
	switch s {
	case StatusOpen:
		return "open"
	case StatusNotAFinding:
		return "not_a_finding"
	case StatusNotApplicable:
		return "not_applicable"
	default:
		return "not_reviewed"
	}
}

// ToHDF maps the canonical status to an HDF Result_Status.
func (s CheckStatus) ToHDF() hdf.ResultStatus {
	switch s {
	case StatusOpen:
		return hdf.Failed
	case StatusNotAFinding:
		return hdf.Passed
	case StatusNotApplicable:
		return hdf.NotApplicable
	default:
		return hdf.NotReviewed
	}
}

// StatusFromHDF maps an HDF Result_Status back to a canonical CheckStatus.
// error maps to Open (a checklist has no error state; a tooling error is most
// conservatively surfaced as an open finding for an assessor to inspect).
func StatusFromHDF(s hdf.ResultStatus) CheckStatus {
	switch s {
	case hdf.Passed:
		return StatusNotAFinding
	case hdf.Failed, hdf.Error:
		return StatusOpen
	case hdf.NotApplicable:
		return StatusNotApplicable
	default:
		return StatusNotReviewed
	}
}
