package trufflehog

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
	hdf "github.com/mitre/hdf-schema"
)

// TrufflehogFinding represents a single finding from TruffleHog output.
type TrufflehogFinding struct {
	SourceMetadata      SourceMetadata         `json:"SourceMetadata"`
	SourceID            int                    `json:"SourceID"`
	SourceType          int                    `json:"SourceType"`
	SourceName          string                 `json:"SourceName"`
	DetectorType        int                    `json:"DetectorType"`
	DetectorName        string                 `json:"DetectorName"`
	DetectorDescription string                 `json:"DetectorDescription"`
	DecoderName         string                 `json:"DecoderName"`
	Verified            bool                   `json:"Verified"`
	VerificationError   string                 `json:"VerificationError"`
	Raw                 string                 `json:"Raw"`
	RawV2               string                 `json:"RawV2"`
	Redacted            string                 `json:"Redacted"`
	ExtraData           map[string]interface{} `json:"ExtraData"`
	StructuredData      interface{}            `json:"StructuredData"`
}

// SourceMetadata wraps the Data field containing source-specific info.
type SourceMetadata struct {
	Data SourceData `json:"Data"`
}

// SourceData holds the source-type-specific metadata (Git, Filesystem, or Docker).
type SourceData struct {
	Git        *GitSource        `json:"Git,omitempty"`
	Filesystem *FilesystemSource `json:"Filesystem,omitempty"`
	Docker     *DockerSource     `json:"Docker,omitempty"`
}

// GitSource holds Git-specific source metadata.
type GitSource struct {
	Commit     string `json:"commit"`
	File       string `json:"file"`
	Email      string `json:"email"`
	Repository string `json:"repository"`
	Timestamp  string `json:"timestamp"`
	Line       int    `json:"line"`
}

// FilesystemSource holds Filesystem-specific source metadata.
type FilesystemSource struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// DockerSource holds Docker-specific source metadata.
type DockerSource struct {
	Image string `json:"image"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// Hardcoded NIST/CCI constants for credential exposure findings.
// IA-5(7): "No Embedded Unencrypted Static Authenticators"
var (
	trufflehogNIST = []string{"IA-5 (7)"}
	trufflehogCCI  = []string{"CCI-000202", "CCI-000203", "CCI-002367"}
)

// parseFindings attempts to parse input as JSON array, single object, or NDJSON.
func parseFindings(input []byte) ([]TrufflehogFinding, error) {
	// Try JSON array first
	var findings []TrufflehogFinding
	if err := json.Unmarshal(input, &findings); err == nil {
		return findings, nil
	}

	// Try single JSON object
	var single TrufflehogFinding
	if err := json.Unmarshal(input, &single); err == nil {
		// Validate it looks like a real finding (has DetectorName)
		if single.DetectorName != "" {
			return []TrufflehogFinding{single}, nil
		}
	}

	// Try NDJSON: split on newlines, parse each line
	lines := strings.Split(strings.TrimSpace(string(input)), "\n")
	var ndjsonFindings []TrufflehogFinding
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var finding TrufflehogFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			return nil, fmt.Errorf("trufflehog: failed to parse NDJSON line: %w", err)
		}
		ndjsonFindings = append(ndjsonFindings, finding)
	}
	if len(ndjsonFindings) > 0 {
		return ndjsonFindings, nil
	}

	return nil, fmt.Errorf("trufflehog: unable to parse input as JSON array, single object, or NDJSON")
}

// groupKey returns the grouping key for a finding: "DetectorName DecoderName".
func groupKey(f TrufflehogFinding) string {
	return f.DetectorName + " " + f.DecoderName
}

// groupFindings groups findings by DetectorName+DecoderName, preserving insertion order.
func groupFindings(findings []TrufflehogFinding) ([]string, map[string][]TrufflehogFinding) {
	order := []string{}
	groups := map[string][]TrufflehogFinding{}
	for _, f := range findings {
		key := groupKey(f)
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}
	return order, groups
}

// buildMessage constructs the Result.Message JSON from selected finding fields.
func buildMessage(f TrufflehogFinding) *string {
	msg := map[string]interface{}{
		"Verified": f.Verified,
		"Redacted": f.Redacted,
	}
	if f.VerificationError != "" {
		msg["VerificationError"] = f.VerificationError
	}
	if len(f.ExtraData) > 0 {
		msg["ExtraData"] = f.ExtraData
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	s := string(data)
	return &s
}

// buildCodeDesc constructs the Result.CodeDesc as JSON of SourceMetadata.
func buildCodeDesc(f TrufflehogFinding) string {
	data, err := json.Marshal(f.SourceMetadata)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// getTimestamp extracts a timestamp from a finding's Git source metadata.
func getTimestamp(f TrufflehogFinding) time.Time {
	if f.SourceMetadata.Data.Git != nil && f.SourceMetadata.Data.Git.Timestamp != "" {
		ts := hdfutil.ParseTimestamp(f.SourceMetadata.Data.Git.Timestamp)
		if !ts.IsZero() {
			return ts
		}
		// Try TruffleHog-specific format: "2023-10-19 02:56:37 +0000"
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", f.SourceMetadata.Data.Git.Timestamp); err == nil {
			return t
		}
	}
	return time.Now().UTC()
}

// getSourceFile extracts the file path from any source type.
func getSourceFile(f TrufflehogFinding) string {
	if f.SourceMetadata.Data.Git != nil {
		return f.SourceMetadata.Data.Git.File
	}
	if f.SourceMetadata.Data.Filesystem != nil {
		return f.SourceMetadata.Data.Filesystem.File
	}
	if f.SourceMetadata.Data.Docker != nil {
		return f.SourceMetadata.Data.Docker.File
	}
	return ""
}

// getSourceLine extracts the line number from any source type.
func getSourceLine(f TrufflehogFinding) int {
	if f.SourceMetadata.Data.Git != nil {
		return f.SourceMetadata.Data.Git.Line
	}
	if f.SourceMetadata.Data.Filesystem != nil {
		return f.SourceMetadata.Data.Filesystem.Line
	}
	if f.SourceMetadata.Data.Docker != nil {
		return f.SourceMetadata.Data.Docker.Line
	}
	return 0
}

// buildRequirement converts a group of findings sharing a detector into one EvaluatedRequirement.
func buildRequirement(reqID string, findings []TrufflehogFinding) hdf.EvaluatedRequirement {
	rep := findings[0]
	tags := shared.BuildNISTCCITags(trufflehogNIST, trufflehogCCI)

	title := fmt.Sprintf("Found %s secret using %s decoder", rep.DetectorName, rep.DecoderName)

	descData := rep.DetectorDescription
	if descData == "" {
		descData = fmt.Sprintf("%s secret detected by %s decoder", rep.DetectorName, rep.DecoderName)
	}
	descriptions := []hdf.Description{
		{Label: "default", Data: descData},
	}

	results := make([]hdf.RequirementResult, len(findings))
	for i, f := range findings {
		results[i] = hdf.RequirementResult{
			Status:    hdf.Failed,
			CodeDesc:  buildCodeDesc(f),
			Message:   buildMessage(f),
			StartTime: getTimestamp(f),
		}
	}

	// SourceLocation from first finding
	var sourceLocation *hdf.SourceLocation
	file := getSourceFile(rep)
	if file != "" {
		line := float64(getSourceLine(rep))
		loc := hdf.SourceLocation{Ref: &file}
		if line > 0 {
			loc.Line = &line
		}
		sourceLocation = &loc
	}

	return hdf.EvaluatedRequirement{
		ID:             reqID,
		Title:          &title,
		Impact:         0.5,
		Tags:           tags,
		Descriptions:   descriptions,
		Results:        results,
		SourceLocation: sourceLocation,
	}
}

// findGitRepoURL scans findings for the first Git repository URL.
func findGitRepoURL(findings []TrufflehogFinding) string {
	for _, f := range findings {
		if f.SourceMetadata.Data.Git != nil && f.SourceMetadata.Data.Git.Repository != "" {
			return f.SourceMetadata.Data.Git.Repository
		}
	}
	return ""
}

// firstSourceName returns the SourceName from the first finding, or a default.
func firstSourceName(findings []TrufflehogFinding) string {
	if len(findings) > 0 && findings[0].SourceName != "" {
		return findings[0].SourceName
	}
	return "trufflehog"
}

// ConvertTrufflehogToHDF converts TruffleHog output to HDF format.
// Accepts JSON array, single JSON object, or NDJSON input.
func ConvertTrufflehogToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("trufflehog: empty input")
	}
	if err := shared.ValidateJSONSize(input, "trufflehog", 0); err != nil {
		return nil, fmt.Errorf("trufflehog: %w", err)
	}

	findings, err := parseFindings(input)
	if err != nil {
		return nil, err
	}

	if len(findings) == 0 {
		return nil, fmt.Errorf("trufflehog: no findings in input")
	}

	checksum := shared.InputChecksum(input)

	limitedFindings := shared.LimitSliceWithWarning(findings, 0, "finding")
	order, groups := groupFindings(limitedFindings)

	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, reqID := range order {
		requirements[i] = buildRequirement(reqID, groups[reqID])
	}

	sourceName := firstSourceName(limitedFindings)
	baselineTitle := fmt.Sprintf("TruffleHog Scan (%s)", sourceName)

	baseline := hdf.EvaluatedBaseline{
		Name:            "TruffleHog Scan",
		Title:           &baselineTitle,
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	now := time.Now().UTC()

	// Add target only if a Git repository URL is available
	var targets []hdf.Component
	repoURL := findGitRepoURL(limitedFindings)
	if repoURL != "" {
		targets = []hdf.Component{
			{Name: repoURL, Type: hdf.Repository},
		}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "hdf-converters",
		ConverterVersion: converterVersion,
		ToolName:         "TruffleHog",
		ToolFormat:       "JSON",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        &now,
	}), nil
}
