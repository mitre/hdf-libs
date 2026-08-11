package trufflehog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	trufflehogCCI  = []string{"CCI-004069", "CCI-000202", "CCI-000203", "CCI-002367"}
)

// A verified secret is a confirmed-live credential (TruffleHog reached the
// provider and the credential authenticated) and rates high; an unverified
// candidate rates medium.
const (
	impactVerified   = 0.7
	impactUnverified = 0.5
)

// groupImpact rates a requirement by its strongest signal: any verified finding
// in the group elevates the whole requirement to the verified impact.
func groupImpact(findings []TrufflehogFinding) float64 {
	for _, f := range findings {
		if f.Verified {
			return impactVerified
		}
	}
	return impactUnverified
}

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

// marshalPlain serializes v without Go's default HTML escaping, so `<` and `>`
// survive into the embedded blob as themselves (git author emails carry them).
func marshalPlain(v interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// trufflehogMessage is the embedded Result.Message payload. It is a struct, not
// a map, because the field order is part of the serialized string the snapshot
// compares — a map would emit Go's alphabetical order instead.
//
// Raw/RawV2 (the plaintext live secret) are deliberately withheld for secret
// hygiene — only the masked Redacted form is carried, so the HDF output never
// embeds a usable credential. Do not add them back for heimdall2 parity.
type trufflehogMessage struct {
	Verified          bool                   `json:"Verified"`
	Redacted          string                 `json:"Redacted"`
	VerificationError string                 `json:"VerificationError,omitempty"`
	ExtraData         map[string]interface{} `json:"ExtraData,omitempty"`
}

// buildMessage constructs the Result.Message JSON from selected finding fields.
func buildMessage(f TrufflehogFinding) *string {
	msg := trufflehogMessage{
		Verified:          f.Verified,
		Redacted:          f.Redacted,
		VerificationError: f.VerificationError,
	}
	if len(f.ExtraData) > 0 {
		msg.ExtraData = f.ExtraData
	}
	s, err := marshalPlain(msg)
	if err != nil {
		return nil
	}
	return &s
}

// buildCodeDesc constructs the Result.CodeDesc as JSON of SourceMetadata.
func buildCodeDesc(f TrufflehogFinding) string {
	s, err := marshalPlain(f.SourceMetadata)
	if err != nil {
		return "{}"
	}
	return s
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
			return hdfutil.NormalizeTimestamp(t)
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
		ID:                 reqID,
		Title:              &title,
		Impact:             groupImpact(findings),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(trufflehogNIST),
		Descriptions:       descriptions,
		Results:            results,
		SourceLocation:     sourceLocation,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
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

// trufflehogTarget returns the most specific target identifier available
// (repo URL > source name), or a generic fallback when nothing is available.
func trufflehogTarget(findings []TrufflehogFinding) string {
	if repo := findGitRepoURL(findings); repo != "" {
		return repo
	}
	if len(findings) > 0 && findings[0].SourceName != "" {
		return findings[0].SourceName
	}
	return "the target source"
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
	if err := shared.ValidateJSONSize(input, "trufflehog", 0); err != nil {
		return nil, fmt.Errorf("trufflehog: %w", err)
	}

	// A clean TruffleHog scan emits empty stdout (exit-code-first), not []. Treat
	// empty/whitespace-only input as zero findings, like an explicit [].
	var findings []TrufflehogFinding
	if len(bytes.TrimSpace(input)) > 0 {
		var err error
		findings, err = parseFindings(input)
		if err != nil {
			return nil, err
		}
	}

	checksum := shared.InputChecksum(input)

	limitedFindings := shared.LimitSliceWithWarning(findings, 0, "finding")
	order, groups := groupFindings(limitedFindings)

	requirements := make([]hdf.EvaluatedRequirement, len(order))
	for i, reqID := range order {
		requirements[i] = buildRequirement(reqID, groups[reqID])
	}

	sourceName := firstSourceName(limitedFindings)

	if len(requirements) == 0 {
		target := trufflehogTarget(limitedFindings)
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"trufflehog-no-findings",
				fmt.Sprintf("TruffleHog scanned %s and reported zero findings.", target),
				time.Now().UTC(),
			),
		}
	}

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
		GeneratorName:    "trufflehog-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "TruffleHog",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       targets,
		Timestamp:        &now,
	}), nil
}
