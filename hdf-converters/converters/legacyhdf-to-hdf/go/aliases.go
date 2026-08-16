package legacyhdf

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// Deprecated aliases for the pre-3.6 version-baked public API. The converter
// upgrades legacy HDF (InSpec exec-json) to the current HDF schema; the old
// names hard-coded "V1"/"V2" schema versions, which drift on every schema bump.
// These aliases keep external consumers building across the rename and are
// scheduled for removal in a future major (breaking change); tracked in the
// issue tracker.

// Deprecated: use LegacyHDFResults.
type HDFV1Results = LegacyHDFResults

// Deprecated: use ConvertLegacyHDF.
func ConvertV1ToV2(v1 *LegacyHDFResults, converterVersion string) *hdf.HDFResults {
	return ConvertLegacyHDF(v1, converterVersion)
}

// Deprecated: use IsLegacyHDF.
func IsHDFV1(data []byte) bool {
	return IsLegacyHDF(data)
}

// Deprecated: use IsLegacyHDFFromMap.
func IsHDFV1FromMap(obj map[string]interface{}) bool {
	return IsLegacyHDFFromMap(obj)
}
