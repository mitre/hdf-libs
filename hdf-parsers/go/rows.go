package hdfparsers

import (
	"strconv"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Row is a flat, row-per-requirement projection of an HDF Results document,
// keyed by column name. A column is omitted (not present in the map) when
// no value is available. Values are stringified for downstream CSV / wide-JSON
// emission; numeric and boolean source data are formatted without trailing
// zeros.
type Row map[string]string

// FlattenToRows expands an HDF Results document into a slice of rows — one
// per requirement, per baseline, in input order. CVE-ecosystem columns
// (cvss_base_score, cvss_computed_score, epss_score, epss_percentile,
// kev_in_kev, cwe, affected_packages) are populated from the structured
// fields on Evaluated_Requirement; cvss_base_score also falls back to the
// legacy scalar tags.cvss_base_score for back-compat with files emitted by
// older converters.
func FlattenToRows(results hdf.HDFResults) []Row {
	var rows []Row
	for _, b := range results.Baselines {
		for _, r := range b.Requirements {
			row := Row{
				"id":       r.ID,
				"baseline": b.Name,
			}
			fillCveColumns(row, r)
			rows = append(rows, row)
		}
	}
	return rows
}

// fillCveColumns adds CVE-ecosystem columns from the structured fields on
// the requirement. Falls back to tags.cvss_base_score for legacy data.
func fillCveColumns(row Row, r hdf.EvaluatedRequirement) {
	// cvss[] — first entry drives cvss_base_score / cvss_computed_score.
	if len(r.Cvss) > 0 {
		first := r.Cvss[0]
		if first.BaseScore != nil {
			row["cvss_base_score"] = strconv.FormatFloat(*first.BaseScore, 'f', -1, 64)
		}
		if first.ComputedScore != nil {
			row["cvss_computed_score"] = strconv.FormatFloat(*first.ComputedScore, 'f', -1, 64)
		}
	}

	// Legacy fallback: only if structured cvss[].baseScore did not populate.
	if _, has := row["cvss_base_score"]; !has && r.Tags != nil {
		if raw, ok := r.Tags["cvss_base_score"]; ok {
			if v, ok := scalarString(raw); ok {
				row["cvss_base_score"] = v
			}
		}
	}

	// epss
	if r.Epss != nil {
		row["epss_score"] = strconv.FormatFloat(r.Epss.Score, 'f', -1, 64)
		row["epss_percentile"] = strconv.FormatFloat(r.Epss.Percentile, 'f', -1, 64)
	}

	// kev
	if r.Kev != nil {
		row["kev_in_kev"] = strconv.FormatBool(r.Kev.InKev)
	}

	// cwe[] — joined with ";"
	if len(r.Cwe) > 0 {
		row["cwe"] = strings.Join(r.Cwe, ";")
	}

	// affectedPackages[] — joined "name@version;name@version".
	// Fall back to purl or cpe when name+version aren't both set, since
	// the loosened Affected_Package schema permits identifier-only entries.
	if len(r.AffectedPackages) > 0 {
		parts := make([]string, 0, len(r.AffectedPackages))
		for _, p := range r.AffectedPackages {
			if p.Name != nil && *p.Name != "" {
				if p.Version != nil && *p.Version != "" {
					parts = append(parts, *p.Name+"@"+*p.Version)
				} else {
					parts = append(parts, *p.Name)
				}
				continue
			}
			if p.Purl != nil && *p.Purl != "" {
				parts = append(parts, *p.Purl)
				continue
			}
			if p.Cpe != nil && *p.Cpe != "" {
				parts = append(parts, *p.Cpe)
			}
		}
		if len(parts) > 0 {
			row["affected_packages"] = strings.Join(parts, ";")
		}
	}
}

// scalarString stringifies a scalar tag value (numeric / string / bool).
// Used for the legacy tags.cvss_base_score fallback, where the value may
// arrive as a string ("6.4") or a number (6.4) depending on the converter.
func scalarString(v interface{}) (string, bool) {
	switch n := v.(type) {
	case nil:
		return "", false
	case string:
		if n == "" {
			return "", false
		}
		return n, true
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(n), 'f', -1, 64), true
	case int:
		return strconv.Itoa(n), true
	case int64:
		return strconv.FormatInt(n, 10), true
	case bool:
		return strconv.FormatBool(n), true
	default:
		return "", false
	}
}
