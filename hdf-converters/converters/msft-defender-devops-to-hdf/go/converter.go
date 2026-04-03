package msftdefenderdevops

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// --- MSDO-specific SARIF struct definitions ---
// These capture fields that the generic SARIF converter ignores.

type msdoSarif struct {
	Runs []msdoRun `json:"runs"`
}

type msdoRun struct {
	Tool                     msdoTool                   `json:"tool"`
	VersionControlProvenance []VersionControlProvenance `json:"versionControlProvenance"`
	Policies                 []Policy                   `json:"policies"`
	Results                  []msdoResult               `json:"results"`
}

type msdoTool struct {
	Driver msdoDriver `json:"driver"`
}

type msdoDriver struct {
	Name         string                 `json:"name"`
	Organization string                 `json:"organization"`
	Product      string                 `json:"product"`
	FullName     string                 `json:"fullName"`
	Properties   map[string]interface{} `json:"properties"`
}

// VersionControlProvenance captures repository info from MSDO SARIF runs.
type VersionControlProvenance struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId"`
	Branch        string `json:"branch"`
}

// Policy captures MSDO security policy metadata.
type Policy struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type msdoResult struct {
	RuleID     string                 `json:"ruleId"`
	Properties map[string]interface{} `json:"properties"`
}

// runEnrichment holds MSDO-specific data for a single SARIF run.
type runEnrichment struct {
	toolTags  map[string]interface{}
	policyTag string
	// resultProps maps ruleId to a list of result-level property maps.
	// Each entry corresponds to one SARIF result for that rule.
	resultProps map[string][]map[string]interface{}
}

// ConvertMsftDefenderDevopsToHDF converts Microsoft Defender for DevOps SARIF output to HDF format.
// It delegates base conversion to the generic SARIF converter and enriches the output with
// MSDO-specific metadata (repository targets, tool metadata, security policies, result properties).
func ConvertMsftDefenderDevopsToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("msft-defender-devops: empty input")
	}
	if err := shared.ValidateJSONSize(input, "msft-defender-devops", 0); err != nil {
		return nil, fmt.Errorf("msft-defender-devops: %w", err)
	}

	// 1. Parse raw SARIF to extract MSDO-specific fields
	var raw msdoSarif
	if err := json.Unmarshal(input, &raw); err != nil {
		return nil, fmt.Errorf("msft-defender-devops: invalid JSON: %w", err)
	}
	targets, runEnrichments := extractEnrichments(raw)

	// 2. Delegate to the generic SARIF converter for base HDF
	result, err := sarif.ConvertSarifToHDF(input, converterVersion)
	if err != nil {
		return nil, fmt.Errorf("msft-defender-devops: %w", err)
	}

	// 3. Apply enrichments
	applyEnrichments(result, targets, runEnrichments)

	// 4. Override generator name and tool
	if result.Generator != nil {
		result.Generator.Name = "msft-defender-devops-to-hdf"
	}
	if result.Tool != nil {
		name := "Microsoft Defender for DevOps"
		result.Tool.Name = &name
	}

	return result, nil
}

// extractEnrichments parses all MSDO-specific data from the raw SARIF.
func extractEnrichments(raw msdoSarif) ([]hdf.Component, []runEnrichment) {
	var targets []hdf.Component
	seenRepos := make(map[string]bool)
	runEnrichments := make([]runEnrichment, len(raw.Runs))

	for runIdx, run := range raw.Runs {
		// Extract repository targets from versionControlProvenance
		for _, vcp := range run.VersionControlProvenance {
			if vcp.RepositoryURI != "" && !seenRepos[vcp.RepositoryURI] {
				seenRepos[vcp.RepositoryURI] = true
				target := hdf.Component{
					Name: repoNameFromURI(vcp.RepositoryURI),
					Type: hdf.Repository,
					URL:  shared.Ptr(vcp.RepositoryURI),
				}
				if vcp.Branch != "" {
					target.Branch = shared.Ptr(vcp.Branch)
				}
				if vcp.RevisionID != "" {
					target.Commit = shared.Ptr(vcp.RevisionID)
				}
				targets = append(targets, target)
			}
		}

		// Extract tool metadata tags
		tags := make(map[string]interface{})
		driver := run.Tool.Driver
		if driver.Organization != "" {
			tags["msdo_organization"] = driver.Organization
		}
		if driver.Product != "" {
			tags["msdo_product"] = driver.Product
		}
		if driver.FullName != "" {
			tags["msdo_fullName"] = driver.FullName
		}
		if rawName, ok := driver.Properties["RawName"]; ok {
			tags["msdo_rawName"] = rawName
		}
		if isPreview, ok := driver.Properties["IsPreview"]; ok {
			tags["msdo_isPreview"] = isPreview
		}

		// Extract policy tags
		policyStr := ""
		if len(run.Policies) > 0 {
			parts := make([]string, len(run.Policies))
			for i, p := range run.Policies {
				parts[i] = fmt.Sprintf("%s %s", p.Name, p.Version)
			}
			policyStr = strings.Join(parts, ", ")
		}

		// Extract result-level properties, keyed by ruleId
		resultProps := make(map[string][]map[string]interface{})
		for _, res := range run.Results {
			if len(res.Properties) > 0 {
				resultProps[res.RuleID] = append(resultProps[res.RuleID], res.Properties)
			}
		}

		runEnrichments[runIdx] = runEnrichment{
			toolTags:    tags,
			policyTag:   policyStr,
			resultProps: resultProps,
		}
	}

	return targets, runEnrichments
}

// applyEnrichments merges MSDO-specific data into the HDF result.
func applyEnrichments(result *hdf.HDFResults, targets []hdf.Component, runEnrichments []runEnrichment) {
	// Add targets
	if len(targets) > 0 {
		result.Components = targets
	}

	// Apply per-baseline (per-run) enrichments
	for i := range result.Baselines {
		if i >= len(runEnrichments) {
			break
		}
		re := runEnrichments[i]

		for j := range result.Baselines[i].Requirements {
			req := &result.Baselines[i].Requirements[j]
			if req.Tags == nil {
				req.Tags = make(map[string]interface{})
			}

			// Add tool metadata tags
			for k, v := range re.toolTags {
				req.Tags[k] = v
			}

			// Add policy tag
			if re.policyTag != "" {
				req.Tags["msdo_policy"] = re.policyTag
			}

			// Add result-level properties for this requirement's ruleId
			if props, ok := re.resultProps[req.ID]; ok && len(props) > 0 {
				// Store the first result's properties as representative
				req.Tags["msdo_properties"] = props[0]
			}
		}
	}
}

// repoNameFromURI extracts the repository name from a URI.
// "https://github.com/org/repo" → "repo"
func repoNameFromURI(uri string) string {
	name := path.Base(uri)
	if name == "" || name == "." || name == "/" {
		return uri
	}
	return name
}
