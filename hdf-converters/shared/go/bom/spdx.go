// SPDX SBOM -> normalized HDF BillOfMaterials.
//
// Maps packages[] to normalized SBOM packages. purl comes from an externalRefs
// entry with referenceType "purl"; licenses come from licenseConcluded /
// licenseDeclared with NOASSERTION/NONE sentinels filtered out.

package bom

import shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"

var spdxLicenseFields = []string{"licenseConcluded", "licenseDeclared"}

// purlFromExternalRefs returns the first externalRefs[].referenceLocator whose
// referenceType is "purl".
func purlFromExternalRefs(refs any) string {
	entries, ok := refs.([]any)
	if !ok {
		return ""
	}
	for _, ref := range entries {
		r := asRecord(ref)
		if r != nil && r["referenceType"] == "purl" {
			if locator := asString(r["referenceLocator"]); locator != "" {
				return locator
			}
		}
	}
	return ""
}

func extractSPDXLicenses(pkg map[string]any) []string {
	out := []string{}
	for _, field := range spdxLicenseFields {
		license := cleanLicense(pkg[field])
		if license == "" {
			continue
		}
		if !contains(out, license) {
			out = append(out, license)
		}
	}
	return out
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func packageToPackage(source any) (SBOMPackage, bool) {
	p := asRecord(source)
	name := asString(p["name"])
	if p == nil || name == "" {
		return SBOMPackage{}, false
	}

	pkg := SBOMPackage{Name: name}
	if version := asString(p["versionInfo"]); version != "" {
		pkg.Version = strPtr(version)
	}
	if purl := purlFromExternalRefs(p["externalRefs"]); purl != "" {
		pkg.Purl = strPtr(purl)
	}
	if licenses := extractSPDXLicenses(p); len(licenses) > 0 {
		pkg.Licenses = licenses
	}

	enrichFromPurl(&pkg)
	return pkg, true
}

// ParseSPDX normalizes an SPDX SBOM object into an sbom BillOfMaterials.
func ParseSPDX(obj map[string]any) *NormalizedBom {
	sourcePackages, _ := obj["packages"].([]any)
	packages := []SBOMPackage{}
	for _, source := range sourcePackages {
		if pkg, ok := packageToPackage(source); ok {
			packages = append(packages, pkg)
		}
	}

	return normalized(BuildBom(BuildBomParts{
		BOMType:  BOMTypeSbom,
		Format:   FormatSPDX,
		Packages: shared.LimitSliceWithWarning(packages, maxPackages, "package"),
		UniqueID: strPtr(asString(obj["documentNamespace"])),
	}))
}
