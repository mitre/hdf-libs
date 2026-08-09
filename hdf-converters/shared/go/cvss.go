package shared

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// CvssVersionFromVector returns the schema CVSS Version enum corresponding to a
// vector string prefix (CVSS:2.0/, CVSS:3.0/, CVSS:4.0/). When the prefix is
// absent or unrecognized (including the CVSS:3.1/ prefix), it defaults to "3.1"
// — the version modern scanners emit most often.
func CvssVersionFromVector(vector string) hdf.Version {
	switch {
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		return hdf.The20
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return hdf.The30
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return hdf.The40
	default:
		return hdf.The31
	}
}

// CvssVersionFromString maps a bare CVSS version number ("2.0", "3.0", "3.1",
// "4.0") — as emitted in a structured version field rather than a vector
// prefix — to the schema Version enum. Unrecognized values default to "3.1".
func CvssVersionFromString(v string) hdf.Version {
	switch v {
	case "2.0":
		return hdf.The20
	case "3.0":
		return hdf.The30
	case "4.0":
		return hdf.The40
	default:
		return hdf.The31
	}
}

// CvssSeverityFromScore maps a CVSS base/computed score to the schema
// CVSSSeverity enum via the shared band thresholds in hdfutil. Scores below the
// low threshold (and non-finite inputs, per hdfutil) map to the "none" band.
func CvssSeverityFromScore(score float64) hdf.CVSSSeverity {
	switch hdfutil.CvssScoreToSeverity(score) {
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
// provides. Version is always set. BaseScore (and its derived BaseSeverity) is
// set only when non-nil; BaseVector and Source are set only when non-empty.
// Consumers needing threat/environmental/computed enrichment set those fields
// on the returned value themselves.
func BuildCvss(in CvssInput) hdf.Cvss {
	cv := hdf.Cvss{Version: in.Version}
	if in.BaseScore != nil {
		score := *in.BaseScore
		cv.BaseScore = &score
		sev := CvssSeverityFromScore(score)
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
