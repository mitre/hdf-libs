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

// Deprecated input-type aliases. The legacyhdf package is importable via `go get`,
// so these exported struct names are public API even without a barrel; the aliases
// keep external Go consumers building across the rename.

// Deprecated: use LegacyResult.
type V1Result = LegacyResult

// Deprecated: use LegacySourceLocation.
type V1SourceLocation = LegacySourceLocation

// Deprecated: use LegacyDescription.
type V1Description = LegacyDescription

// Deprecated: use LegacyControl.
type V1Control = LegacyControl

// Deprecated: use LegacyGroup.
type V1Group = LegacyGroup

// Deprecated: use LegacyDependency.
type V1Dependency = LegacyDependency

// Deprecated: use LegacyProfile.
type V1Profile = LegacyProfile

// Deprecated: use LegacyPlatform.
type V1Platform = LegacyPlatform

// Deprecated: use LegacyStatistics.
type V1Statistics = LegacyStatistics

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
