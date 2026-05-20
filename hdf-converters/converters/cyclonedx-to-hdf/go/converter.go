package cyclonedx_to_hdf

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// CycloneDXBom is the top-level CycloneDX BOM structure.
type CycloneDXBom struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Metadata        *CDXMetadata       `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities"`
}

// CDXMetadata holds BOM metadata.
type CDXMetadata struct {
	Timestamp string                `json:"timestamp"`
	Component *CDXMetadataComponent `json:"component"`
}

// CDXMetadataComponent describes the top-level project component.
type CDXMetadataComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	BomRef  string `json:"bom-ref"`
}

// CDXComponent represents a single CycloneDX component.
type CDXComponent struct {
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	Group      string         `json:"group"`
	BomRef     string         `json:"bom-ref"`
	Components []CDXComponent `json:"components"`
}

// CDXVulnerability represents a single vulnerability entry.
type CDXVulnerability struct {
	ID             string       `json:"id"`
	Source         *CDXSource   `json:"source"`
	Ratings        []CDXRating  `json:"ratings"`
	CWEs           []int        `json:"cwes"`
	Description    string       `json:"description"`
	Detail         string       `json:"detail"`
	Recommendation string       `json:"recommendation"`
	Affects        []CDXAffect  `json:"affects"`
	Analysis       *CDXAnalysis `json:"analysis"`
}

// CDXSource identifies the advisory source.
type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CDXRating holds a vulnerability rating (CVSS score and/or severity).
type CDXRating struct {
	Source   *CDXSource `json:"source"`
	Score    *float64   `json:"score"`
	Severity string     `json:"severity"`
	Method   string     `json:"method"`
	Vector   string     `json:"vector"`
}

// CDXAffect identifies a component affected by a vulnerability.
type CDXAffect struct {
	Ref string `json:"ref"`
}

// CDXAnalysis holds the vulnerability analysis (VEX).
type CDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"`
	Detail        string   `json:"detail"`
}

// severityToImpact maps CycloneDX severity strings to HDF impact values.
// Standard mappings cover critical, high, medium, low, info, none.
// "unknown" and unrecognized values default to 0.5.
func severityToImpact(severity string) float64 {
	return hdfutil.SeverityToImpact(severity, 0.5)
}

var cvssMethods = map[string]bool{
	"CVSSv2":  true,
	"CVSSv3":  true,
	"CVSSv31": true,
	"CVSSv4":  true,
}

// maxImpact computes the maximum impact across all ratings for a vulnerability.
// Prefers CVSS score/10 when available, falls back to severityToImpact().
func maxImpact(ratings []CDXRating) float64 {
	if len(ratings) == 0 {
		return 0.5
	}

	maxVal := 0.0
	for _, r := range ratings {
		var impact float64
		if cvssMethods[r.Method] && r.Score != nil {
			impact = *r.Score / 10
		} else {
			sev := r.Severity
			if sev == "" {
				sev = "medium"
			}
			impact = severityToImpact(sev)
		}
		if impact > maxVal {
			maxVal = impact
		}
	}
	return maxVal
}

// NOTE: heimdall2 mapped info/unknown severity to NotReviewed status.
// We intentionally do NOT replicate that behavior — a vulnerability is a
// finding regardless of severity confidence. Info/unknown severity vulns
// are Failed with impact derived from the severity mapping (info→0.1,
// unknown→0.5). NotReviewed means "not evaluated" which is incorrect
// when a scanner has identified a CVE.

// formatRatingsTag formats ratings as a human-readable tag string.
func formatRatingsTag(ratings []CDXRating) string {
	parts := make([]string, len(ratings))
	for i, r := range ratings {
		source := "Unknown"
		if r.Source != nil && r.Source.Name != "" {
			source = r.Source.Name
		}
		sev := r.Severity
		if sev == "" {
			sev = "unrated"
		}
		parts[i] = fmt.Sprintf("%s - %s", source, sev)
	}
	return strings.Join(parts, ", ")
}

// formatCodeDesc formats a component reference as a code_desc string.
func formatCodeDesc(componentLookup map[string]CDXComponent, ref string) string {
	comp, found := componentLookup[ref]
	if !found {
		// VEX case: no matching component, use the ref directly
		return fmt.Sprintf("Component %s is vulnerable", ref)
	}

	var name string
	if comp.Group != "" {
		name = comp.Group + "/"
	}
	name += comp.Name
	if comp.Version != "" {
		name += "@" + comp.Version
	}
	return fmt.Sprintf("Component %s is vulnerable", name)
}

// flattenComponents flattens nested CycloneDX components into a single slice.
func flattenComponents(components []CDXComponent) []CDXComponent {
	var result []CDXComponent
	for _, comp := range components {
		result = append(result, comp)
		if len(comp.Components) > 0 {
			result = append(result, flattenComponents(comp.Components)...)
		}
	}
	return result
}

// ConvertCycloneDXToHDF converts CycloneDX SBOM/VEX JSON to HDF format.
func ConvertCycloneDXToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("cyclonedx: empty input")
	}
	if err := shared.ValidateJSONSize(input, "cyclonedx", 0); err != nil {
		return nil, fmt.Errorf("cyclonedx: %w", err)
	}

	var bom CycloneDXBom
	if err := json.Unmarshal(input, &bom); err != nil {
		return nil, fmt.Errorf("cyclonedx: invalid JSON: %w", err)
	}

	if bom.BomFormat != "CycloneDX" {
		return nil, fmt.Errorf("cyclonedx: missing or invalid bomFormat (expected \"CycloneDX\", got %q)", bom.BomFormat)
	}

	if len(bom.Components) == 0 && len(bom.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("cyclonedx: input has neither components nor vulnerabilities")
	}

	if len(bom.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("cyclonedx: this file is an SBOM inventory with no vulnerabilities; " +
			"to import SBOM data into a system document, use:\n" +
			"  hdf system create --from <sbom-file> --component-name <name>")
	}

	checksum := shared.InputChecksum(input)

	// Flatten nested components and build lookup by bom-ref
	allComponents := flattenComponents(bom.Components)
	componentLookup := make(map[string]CDXComponent, len(allComponents))
	for _, comp := range allComponents {
		if comp.BomRef != "" {
			componentLookup[comp.BomRef] = comp
		}
	}

	limitedVulns := shared.LimitSliceWithWarning(bom.Vulnerabilities, 0, "vulnerability")
	requirements := make([]hdf.EvaluatedRequirement, 0, len(limitedVulns))

	for _, vuln := range limitedVulns {
		ratings := vuln.Ratings
		impact := maxImpact(ratings)
		cweStrs := make([]string, len(vuln.CWEs))
		for i, c := range vuln.CWEs {
			cweStrs[i] = fmt.Sprintf("%d", c)
		}
		nist := shared.MapCWEToNIST(cweStrs, shared.DefaultStaticAnalysisNIST)
		cciTags := cci.NISTToCCI(nist)

		extras := map[string]interface{}{}
		if len(vuln.CWEs) > 0 {
			cweids := make([]string, len(vuln.CWEs))
			for i, c := range vuln.CWEs {
				cweids[i] = fmt.Sprintf("CWE-%d", c)
			}
			extras["cweid"] = cweids
		}
		if len(ratings) > 0 {
			extras["ratings"] = formatRatingsTag(ratings)
		}
		tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

		// Build descriptions (must always include a 'default' label per HDF schema)
		descriptions := []hdf.Description{}

		// Default description: description + detail
		var defaultParts []string
		if vuln.Description != "" {
			defaultParts = append(defaultParts, fmt.Sprintf("Description: %s", vuln.Description))
		}
		if vuln.Detail != "" {
			defaultParts = append(defaultParts, fmt.Sprintf("Detail: %s", vuln.Detail))
		}
		if len(defaultParts) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  strings.Join(defaultParts, "\n\n"),
			})
		} else {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  vuln.ID,
			})
		}

		// Fix description: recommendation + workaround from analysis
		var fixParts []string
		if vuln.Recommendation != "" {
			fixParts = append(fixParts, vuln.Recommendation)
		}
		if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
			fixParts = append(fixParts, fmt.Sprintf("Workaround: %s", vuln.Analysis.Detail))
		}
		if len(fixParts) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "fix",
				Data:  strings.Join(fixParts, "\n\n"),
			})
		}

		// Build results: one per affected component.
		// All vulnerabilities are Failed — info/unknown severity affects impact
		// score but not status (a vuln is a finding regardless of severity confidence).
		var results []hdf.RequirementResult
		if len(vuln.Affects) > 0 {
			for _, affect := range vuln.Affects {
				results = append(results, hdf.RequirementResult{
					Status:   hdf.Failed,
					CodeDesc: formatCodeDesc(componentLookup, affect.Ref),
				})
			}
		} else {
			results = append(results, hdf.RequirementResult{
				Status:   hdf.Failed,
				CodeDesc: fmt.Sprintf("Vulnerability %s", vuln.ID),
			})
		}

		title := vuln.ID
		if vuln.Source != nil && vuln.Source.Name != "" {
			title = fmt.Sprintf("%s (%s)", vuln.ID, vuln.Source.Name)
		}

		// verificationMethod is intentionally NOT set. CycloneDX carries both
		// machine-generated SBOM vulnerability data and human-authored VEX
		// statements (analyst assertions about CVE exploitability). The
		// converter cannot reliably distinguish the two, so stamping
		// "automated" would misclassify VEX-derived requirements.
		requirements = append(requirements, hdf.EvaluatedRequirement{
			ID:           vuln.ID,
			Title:        &title,
			Impact:       impact,
			Tags:         tags,
			ControlType:  shared.DeriveControlTypeFromTags(nist),
			Descriptions: descriptions,
			Results:      results,
		})
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "CycloneDX Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	now := time.Now().UTC()

	comp := hdf.Component{
		Type: hdf.CopyrightApplication,
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		comp.Name = bom.Metadata.Component.Name
		if bom.Metadata.Component.Version != "" {
			comp.Version = &bom.Metadata.Component.Version
		}
	}

	// Embed the raw CycloneDX SBOM into the component
	var rawSbom interface{}
	if err := json.Unmarshal(input, &rawSbom); err == nil {
		sbomFmt := hdf.Cyclonedx
		comp.Sbom = rawSbom
		comp.SbomFormat = &sbomFmt
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "cyclonedx-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "CycloneDX",
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{comp},
		Timestamp:        &now,
	}), nil
}
