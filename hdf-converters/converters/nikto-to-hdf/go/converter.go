package nikto_to_hdf

import (
	"encoding/json"
	"fmt"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nikto"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Nikto JSON input structures

type NiktoReport struct {
	Banner          string               `json:"banner,omitempty"`
	Host            string               `json:"host,omitempty"`
	IP              string               `json:"ip,omitempty"`
	Port            string               `json:"port,omitempty"`
	Vulnerabilities []NiktoVulnerability `json:"vulnerabilities"`
}

type NiktoVulnerability struct {
	OSVDB  string `json:"OSVDB,omitempty"`
	ID     string `json:"id"`
	Method string `json:"method,omitempty"`
	Msg    string `json:"msg"`
	URL    string `json:"url,omitempty"`
}

func buildNistTags(niktoID string) []string {
	control := nikto.NISTControl(niktoID)
	if control != "" {
		return []string{control}
	}
	return shared.DefaultStaticAnalysisNIST
}

func buildCodeDesc(vuln NiktoVulnerability) string {
	result := ""
	if vuln.URL != "" {
		result = fmt.Sprintf("URL: %s", vuln.URL)
	}
	if vuln.Method != "" {
		if result != "" {
			result += " "
		}
		result += fmt.Sprintf("Method: %s", vuln.Method)
	}
	return result
}

func convertVulnToRequirement(vuln NiktoVulnerability) hdf.EvaluatedRequirement {
	nistTags := buildNistTags(vuln.ID)
	cciTags := cci.NISTToCCI(nistTags)

	zeroTime := time.Time{}
	result := hdf.RequirementResult{
		Status:    hdf.Failed,
		CodeDesc:  buildCodeDesc(vuln),
		StartTime: zeroTime,
	}

	// Build tags with NIST/CCI and optional osvdb extra
	var extras map[string]interface{}
	if vuln.OSVDB != "" && vuln.OSVDB != "0" {
		extras = map[string]interface{}{"osvdb": vuln.OSVDB}
	}
	tags := shared.BuildNISTCCITagsWithExtras(nistTags, cciTags, extras)

	return hdf.EvaluatedRequirement{
		ID:      vuln.ID,
		Title:   &vuln.Msg,
		Impact:  0.5,
		Results: []hdf.RequirementResult{result},
		Tags:    tags,
		Descriptions: []hdf.Description{
			{Label: "default", Data: vuln.Msg},
		},
		ControlType:        shared.DeriveControlTypeFromTags(nistTags),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// ConvertNiktoToHDF converts Nikto JSON to HDF
func ConvertNiktoToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("nikto: empty input")
	}
	if err := shared.ValidateJSONSize(input, "nikto", 0); err != nil {
		return nil, fmt.Errorf("nikto: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var niktoData NiktoReport
	if err := json.Unmarshal(input, &niktoData); err != nil {
		return nil, fmt.Errorf("invalid Nikto JSON: %w", err)
	}

	// Group vulnerabilities by ID to handle duplicates
	type vulnGroup struct {
		primary NiktoVulnerability
		extras  []NiktoVulnerability
	}
	groups := make(map[string]*vulnGroup)
	var order []string // Preserve insertion order

	limitedVulns := shared.LimitSliceWithWarning(niktoData.Vulnerabilities, 0, "vulnerability")
	for _, vuln := range limitedVulns {
		if g, ok := groups[vuln.ID]; ok {
			g.extras = append(g.extras, vuln)
		} else {
			groups[vuln.ID] = &vulnGroup{primary: vuln}
			order = append(order, vuln.ID)
		}
	}

	requirements := []hdf.EvaluatedRequirement{}
	zeroTime := time.Time{}
	for _, id := range order {
		g := groups[id]
		req := convertVulnToRequirement(g.primary)
		for _, extra := range g.extras {
			req.Results = append(req.Results, hdf.RequirementResult{
				Status:    hdf.Failed,
				CodeDesc:  buildCodeDesc(extra),
				StartTime: zeroTime,
			})
		}
		requirements = append(requirements, req)
	}

	// Build target name
	targetName := ""
	if niktoData.Host != "" {
		targetName = fmt.Sprintf("Host: %s", niktoData.Host)
	}
	if niktoData.Port != "" {
		if targetName != "" {
			targetName += " "
		}
		targetName += fmt.Sprintf("Port: %s", niktoData.Port)
	}
	if targetName == "" {
		targetName = "Nikto Scan"
	}

	baselineTitle := fmt.Sprintf("Nikto Target: %s", targetName)
	banner := niktoData.Banner

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"nikto-no-findings",
				fmt.Sprintf("Nikto scanned %s and reported zero findings.", targetName),
				time.Now().UTC(),
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            targetName,
		Title:           &baselineTitle,
		Summary:         &banner,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	target := hdf.Component{
		Name: targetName,
		Type: hdf.Application,
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "nikto-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Nikto",
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
	})

	return hdfResult, nil
}
