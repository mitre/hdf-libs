package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-schema"
)

// SARIF file structure
type SarifFile struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    *SarifTool    `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver *SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
}

type SarifResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   SarifMessage      `json:"message"`
	Locations []SarifLocation   `json:"locations"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

type SarifLocation struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation"`
	Region           *Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

var impactMapping = map[string]float64{
	"error":   0.7,
	"warning": 0.5,
	"note":    0.3,
}

const defaultStaticAnalysisNistTag = "SI-10"

// ConvertSarifToHDF converts SARIF JSON to HDF format
func ConvertSarifToHDF(input []byte) ([]byte, error) {
	// Calculate checksum of source scan data for integrity verification
	hash := sha256.Sum256(input)
	resultsChecksum := &hdf.Checksum{
		Algorithm: hdf.Sha256,
		Value:     hex.EncodeToString(hash[:]),
	}

	var sarif SarifFile
	if err := json.Unmarshal(input, &sarif); err != nil {
		return nil, fmt.Errorf("invalid SARIF JSON: %w", err)
	}

	if len(sarif.Runs) == 0 {
		return nil, fmt.Errorf("invalid SARIF structure: missing or empty runs field")
	}

	// Build HDF
	timestamp := time.Now()
	baselines := make([]hdf.EvaluatedBaseline, 0, len(sarif.Runs))

	for _, run := range sarif.Runs {
		baseline := convertRun(run, sarif.Version, timestamp, resultsChecksum)
		baselines = append(baselines, baseline)
	}

	hdfResult := hdf.HDFResults{
		Timestamp: &timestamp,
		Baselines: baselines,
		Targets:   []hdf.Target{},
		Generator: &hdf.Generator{
			Name:    "sarif-to-hdf",
			Version: "1.0.0",
		},
	}

	output, err := json.MarshalIndent(hdfResult, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HDF JSON: %w", err)
	}

	return output, nil
}

func convertRun(run SarifRun, version string, timestamp time.Time, resultsChecksum *hdf.Checksum) hdf.EvaluatedBaseline {
	requirements := make([]hdf.EvaluatedRequirement, 0, len(run.Results))

	for _, result := range run.Results {
		req := convertResult(result, timestamp)
		requirements = append(requirements, req)
	}

	return hdf.EvaluatedBaseline{
		Name:            "SARIF",
		Version:         &version,
		Title:           stringPtr("Static Analysis Results Interchange Format"),
		Maintainer:      stringPtr("Static Analysis Tool"),
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}
}

func convertResult(result SarifResult, timestamp time.Time) hdf.EvaluatedRequirement {
	messageText := result.Message.Text

	// Parse title and description from message
	title, description := parseMessage(messageText)

	// Extract CWE IDs from message
	cweIds := extractCweIds(messageText)

	// Use default NIST control for static analysis
	nistControls := []string{defaultStaticAnalysisNistTag}

	// For simplicity, use hardcoded CCI controls that map to SI-10
	// In a full implementation, we would do a reverse lookup
	cciControls := []string{"CCI-003173", "CCI-001643"}

	// Get impact from level
	impact := impactMapping[result.Level]
	if impact == 0 && result.Level != "" {
		impact = 0.1
	} else if impact == 0 {
		impact = 0.1
	}

	// Get source location from first location (only if meaningful data exists)
	var sourceLocationPtr *hdf.SourceLocation
	if len(result.Locations) > 0 {
		sourceLocation := extractSourceLocation(result.Locations[0])
		// Only include if it has meaningful data
		if sourceLocation.Ref != nil || sourceLocation.Line != nil {
			sourceLocationPtr = &sourceLocation
		}
	}

	// Create results for each location
	results := make([]hdf.RequirementResult, 0)
	for _, loc := range result.Locations {
		if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil {
			res := createResult(loc, timestamp)
			results = append(results, res)
		}
	}

	// Build tags
	tags := make(map[string]interface{})
	tags["severity"] = result.Level
	if result.Level == "" {
		tags["severity"] = "none"
	}
	tags["cwe"] = cweIds
	tags["nist"] = nistControls
	tags["cci"] = cciControls

	req := hdf.EvaluatedRequirement{
		ID:    result.RuleID,
		Title: &title,
		Descriptions: []hdf.Description{
			{
				Label: "default",
				Data:  description,
			},
		},
		Impact:         impact,
		Tags:           tags,
		Results:        results,
		SourceLocation: sourceLocationPtr,
	}

	return req
}

func parseMessage(text string) (string, string) {
	colonIndex := strings.Index(text, ":")

	if colonIndex == -1 {
		return text, ""
	}

	return strings.TrimSpace(text[:colonIndex]), strings.TrimSpace(text[colonIndex+1:])
}

func extractCweIds(text string) []string {
	// Look for pattern like (CWE-123, CWE-456) or (CWE-119!/CWE-120)
	cwePattern := regexp.MustCompile(`\(([^)]+)\)`)
	matches := cwePattern.FindAllStringSubmatch(text, -1)

	if len(matches) == 0 {
		return []string{}
	}

	cweIds := []string{}

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		content := match[1]

		// Check if it contains CWE
		if strings.Contains(content, "CWE-") {
			// Split by comma or !/
			parts := regexp.MustCompile(`,\s*|!/`).Split(content, -1)

			for _, part := range parts {
				trimmed := strings.TrimSpace(part)
				if strings.HasPrefix(trimmed, "CWE-") {
					cweIds = append(cweIds, trimmed)
				}
			}
		}
	}

	return cweIds
}

func extractSourceLocation(location SarifLocation) hdf.SourceLocation {
	sourceLocation := hdf.SourceLocation{}

	if location.PhysicalLocation == nil || location.PhysicalLocation.ArtifactLocation == nil {
		return sourceLocation
	}

	uri := location.PhysicalLocation.ArtifactLocation.URI
	line := 0
	if location.PhysicalLocation.Region != nil {
		line = location.PhysicalLocation.Region.StartLine
	}

	if uri != "" {
		sourceLocation.Ref = &uri
	}
	if line != 0 {
		lineFloat := float64(line)
		sourceLocation.Line = &lineFloat
	}

	return sourceLocation
}

func createResult(location SarifLocation, timestamp time.Time) hdf.RequirementResult {
	uri := ""
	line := 0
	column := 0

	if location.PhysicalLocation != nil {
		if location.PhysicalLocation.ArtifactLocation != nil {
			uri = location.PhysicalLocation.ArtifactLocation.URI
		}
		if location.PhysicalLocation.Region != nil {
			line = location.PhysicalLocation.Region.StartLine
			column = location.PhysicalLocation.Region.StartColumn
		}
	}

	codeDesc := fmt.Sprintf("URL : %s LINE : %d COLUMN : %d", uri, line, column)
	status := hdf.Failed

	return hdf.RequirementResult{
		Status:    status,
		CodeDesc:  codeDesc,
		StartTime: timestamp,
		Backtrace: []string{},
	}
}

func stringPtr(s string) *string {
	return &s
}

func floatPtr(f float64) *float64 {
	return &f
}
