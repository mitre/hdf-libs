package shared

import (
	"math"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// cvssSchemaVersions maps the CVSS version strings hdf-utilities reports to
// the schema Version enum.
var cvssSchemaVersions = map[string]hdf.Version{
	"2.0": hdf.The20,
	"3.0": hdf.The30,
	"3.1": hdf.The31,
	"4.0": hdf.The40,
}

// CvssVersionFromVector returns the schema CVSS Version enum for a vector
// string, read through hdfutil.ParseCvssVector: the version a CVSS: prefix
// names, CVSS 2.0 for a prefix-less vector carrying the 2.0-only Au metric, and
// otherwise the fallback (3.1 when omitted; historical Nessus output with no
// prefix passes 3.0).
func CvssVersionFromVector(vector string, fallback ...hdf.Version) hdf.Version {
	def := hdf.The31
	if len(fallback) > 0 {
		def = fallback[0]
	}
	version, metrics := hdfutil.ParseCvssVector(vector)
	if !strings.HasPrefix(strings.TrimLeft(vector, "/"), "CVSS:") {
		if _, ok := metrics["Au"]; ok {
			return hdf.The20
		}
		return def
	}
	if v, ok := cvssSchemaVersions[version]; ok {
		return v
	}
	return def
}

// CvssVersionFromString maps a bare CVSS version number ("2.0", "3.0", "3.1",
// "4.0") — as emitted in a structured version field rather than a vector
// prefix — to the schema Version enum. Unrecognized values default to "3.1".
func CvssVersionFromString(v string) hdf.Version {
	if version, ok := cvssSchemaVersions[v]; ok {
		return version
	}
	return hdf.The31
}

// CvssSeverityFromScore maps a CVSS score of the given version to the schema
// CVSSSeverity enum through hdfutil.CvssSeverityForVersion, the one place the
// per-version scales live (NVD's v2 ranges for 2.0, the specification scale for
// 3.x and 4.0). A score with no rating maps to "none".
func CvssSeverityFromScore(version hdf.Version, score float64) hdf.CVSSSeverity {
	switch hdfutil.CvssSeverityForVersion(string(version), score) {
	case "critical":
		return hdf.CVSSSeverityCritical
	case "high":
		return hdf.CVSSSeverityHigh
	case "medium":
		return hdf.CVSSSeverityMedium
	case "low":
		return hdf.CVSSSeverityLow
	default:
		return hdf.None
	}
}

// CvssInput carries the base-metric fields a converter provides for a single
// Cvss entry. Empty/nil fields are omitted from the assembled entry, so each
// converter can produce exactly the shape it produces today (some set a
// BaseVector and Source, some do not).
type CvssInput struct {
	Version    hdf.Version
	BaseScore  *float64
	BaseVector string
	Source     string
}

// BuildCvss assembles an hdf.Cvss from the base-metric fields a converter
// provides. Version is always set. BaseScore is the source's score, read as
// absent when it is not finite; without one it is computed from BaseVector
// through hdfutil.ComputeCvssScore when the vector scores and its version is
// the entry's version, and is otherwise absent. BaseSeverity follows BaseScore
// on the entry's version's scale. BaseVector and Source are set only when
// non-empty. Consumers needing threat/environmental/computed enrichment set
// those fields themselves.
func BuildCvss(in CvssInput) hdf.Cvss {
	cv := hdf.Cvss{Version: in.Version}
	score := in.BaseScore
	// A non-finite score has no severity band and no JSON form: json.Marshal
	// refuses one, which would fail the whole document over a single entry.
	if score != nil && (math.IsNaN(*score) || math.IsInf(*score, 0)) {
		score = nil
	}
	if score == nil && in.BaseVector != "" {
		if s, err := hdfutil.ComputeCvssScore(in.BaseVector); err == nil && s.Version == string(in.Version) {
			score = &s.BaseScore
		}
	}
	if score != nil {
		base := *score
		cv.BaseScore = &base
		sev := CvssSeverityFromScore(in.Version, base)
		cv.BaseSeverity = &sev
	}
	if in.BaseVector != "" {
		bv := in.BaseVector
		cv.BaseVector = &bv
	}
	if in.Source != "" {
		src := in.Source
		cv.Source = &src
	}
	return cv
}
