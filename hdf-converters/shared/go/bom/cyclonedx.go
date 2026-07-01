// CycloneDX SBOM -> normalized HDF BillOfMaterials.
//
// Flattens the top-level components[] into SBOM packages. Nested subcomponents
// (metadata.component.components[]) are the tool's own assembly tree and are
// intentionally not treated as inventory packages here.

package bom

import shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"

// extractCycloneDXLicenses pulls license identifiers/expressions from a
// CycloneDX licenses[] array.
func extractCycloneDXLicenses(raw any) []string {
	entries, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, entry := range entries {
		e := asRecord(entry)
		if e == nil {
			continue
		}
		var id string
		if license := asRecord(e["license"]); license != nil {
			id = asString(license["id"])
			if id == "" {
				id = asString(license["name"])
			}
		}
		value := id
		if value == "" {
			value = asString(e["expression"])
		}
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func componentToPackage(component any) (SBOMPackage, bool) {
	c := asRecord(component)
	name := asString(c["name"])
	if c == nil || name == "" {
		return SBOMPackage{}, false
	}

	pkg := SBOMPackage{Name: name}
	if version := asString(c["version"]); version != "" {
		pkg.Version = strPtr(version)
	}
	if purl := asString(c["purl"]); purl != "" {
		pkg.Purl = strPtr(purl)
	}
	if licenses := extractCycloneDXLicenses(c["licenses"]); len(licenses) > 0 {
		pkg.Licenses = licenses
	}

	enrichFromPurl(&pkg)
	return pkg, true
}

// ParseCycloneDX normalizes a CycloneDX SBOM object into an sbom BillOfMaterials.
func ParseCycloneDX(obj map[string]any) *NormalizedBom {
	components, _ := obj["components"].([]any)
	packages := []SBOMPackage{}
	for _, component := range components {
		if pkg, ok := componentToPackage(component); ok {
			packages = append(packages, pkg)
		}
	}

	return normalized(BuildBom(BuildBomParts{
		BOMType:  BOMTypeSbom,
		Format:   FormatCycloneDX,
		Packages: shared.LimitSliceWithWarning(packages, maxPackages, "package"),
		UniqueID: strPtr(asString(obj["serialNumber"])),
	}))
}
