package conveyor

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// conveyorMaxScore is the maximum possible score from Conveyor (used for normalization).
const conveyorMaxScore = 1000

// ConveyorData is the top-level Conveyor JSON output structure.
type ConveyorData struct {
	APIErrorMessage string           `json:"api_error_message"`
	APIResponse     *ConveyorAPIResp `json:"api_response"`
	APIServerVer    string           `json:"api_server_version"`
}

// ConveyorAPIResp is the api_response block in Conveyor output.
type ConveyorAPIResp struct {
	FileTree map[string]FileTreeNode   `json:"file_tree"`
	Results  map[string]ConveyorResult `json:"results"`
	Params   map[string]interface{}    `json:"params"`
	Times    ConveyorTimes             `json:"times"`
	MaxScore float64                   `json:"max_score"`
}

// ConveyorTimes holds the overall submission timing for a Conveyor run.
type ConveyorTimes struct {
	Completed string `json:"completed"`
	Submitted string `json:"submitted"`
}

// FileTreeNode represents a node in the Conveyor file tree.
type FileTreeNode struct {
	Name     []string                `json:"name"`
	SHA256   string                  `json:"sha256"`
	Children map[string]FileTreeNode `json:"children"`
	Score    float64                 `json:"score"`
	Size     float64                 `json:"size"`
	Type     string                  `json:"type"`
}

// ConveyorResult represents a single result entry from Conveyor output.
type ConveyorResult struct {
	SHA256         string        `json:"sha256"`
	Classification string        `json:"classification"`
	Created        string        `json:"created"`
	ExpiryTs       string        `json:"expiry_ts"`
	Response       ConveyorResp  `json:"response"`
	Result         ConveyorScore `json:"result"`
	Size           interface{}   `json:"size"`
	Type           interface{}   `json:"type"`
}

// ConveyorResp is the response metadata for a result.
type ConveyorResp struct {
	ServiceName      string            `json:"service_name"`
	ServiceVersion   string            `json:"service_version"`
	ServiceContext   interface{}       `json:"service_context"`
	ServiceDebugInfo interface{}       `json:"service_debug_info"`
	ServiceToolVer   interface{}       `json:"service_tool_version"`
	Supplementary    interface{}       `json:"supplementary"`
	Milestones       ConveyorMilestone `json:"milestones"`
}

// ConveyorMilestone holds timing data for a service run.
type ConveyorMilestone struct {
	ServiceStarted   string `json:"service_started"`
	ServiceCompleted string `json:"service_completed"`
}

// ConveyorScore is the result block containing the score and sections.
type ConveyorScore struct {
	Score    float64           `json:"score"`
	Sections []ConveyorSection `json:"sections"`
}

// ConveyorSection is a single section within a result.
type ConveyorSection struct {
	TitleText      string      `json:"title_text"`
	Body           interface{} `json:"body"`
	BodyFormat     string      `json:"body_format"`
	Classification string      `json:"classification"`
	Depth          float64     `json:"depth"`
	Heuristic      *Heuristic  `json:"heuristic"`
}

// Heuristic represents the heuristic block within a section.
type Heuristic struct {
	HeurID string  `json:"heur_id"`
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
}

// collateSHAAndFilenames recursively walks the file tree, collecting
// sha256 → filename mappings.
func collateSHAAndFilenames(tree map[string]FileTreeNode) map[string]string {
	result := make(map[string]string)
	for sha, node := range tree {
		if len(node.Name) > 0 {
			result[sha] = node.Name[0]
		}
		if len(node.Children) > 0 {
			for childSHA, childName := range collateSHAAndFilenames(node.Children) {
				result[childSHA] = childName
			}
		}
	}
	return result
}

// determineStatus maps a Conveyor score to an HDF result status.
// Score 0 = Passed, non-zero = Failed.
func determineStatus(score float64) hdf.ResultStatus {
	if score == 0 {
		return hdf.Passed
	}
	return hdf.Failed
}

// computeRunTime returns the elapsed seconds between a service's start and
// completion milestones, or nil when either is missing/unparseable.
func computeRunTime(startedStr, completedStr string) *float64 {
	started := hdfutil.ParseTimestamp(startedStr)
	completed := hdfutil.ParseTimestamp(completedStr)
	if started.IsZero() || completed.IsZero() {
		return nil
	}
	secs := completed.Sub(started).Seconds()
	return &secs
}

// canonicalTimestampTag normalizes a Conveyor timestamp string to HDF's
// canonical trimmed-UTC RFC3339 form (millisecond precision), matching the
// TypeScript converter byte-for-byte. Returns "" when the source is absent or
// unparseable so the caller can omit the tag.
func canonicalTimestampTag(s string) string {
	t := hdfutil.ParseTimestamp(s)
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// scannerTagExtras collects the tool-specific typed tags Conveyor carries per
// result (created/classification/expiry_ts/size/type), omitting any the source
// leaves null or empty. Timestamp tags are canonicalized so Go and TS agree.
func scannerTagExtras(result ConveyorResult) map[string]interface{} {
	extras := make(map[string]interface{})
	if created := canonicalTimestampTag(result.Created); created != "" {
		extras["created"] = created
	}
	if result.Classification != "" {
		extras["classification"] = result.Classification
	}
	if expiry := canonicalTimestampTag(result.ExpiryTs); expiry != "" {
		extras["expiry_ts"] = expiry
	}
	if result.Size != nil {
		extras["size"] = result.Size
	}
	if s, ok := result.Type.(string); ok && s != "" {
		extras["type"] = s
	}
	return extras
}

// scoreToImpact normalizes a Conveyor score (0–1000) to HDF impact (0.0–1.0).
func scoreToImpact(score float64) float64 {
	if score <= 0 {
		return 0.0
	}
	if score >= conveyorMaxScore {
		return 1.0
	}
	return score / conveyorMaxScore
}

// bodyToString extracts a string from a body field that may be null or a string.
func bodyToString(body interface{}) string {
	if body == nil {
		return ""
	}
	if s, ok := body.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", body)
}

// buildCodeDesc creates the code_desc field content from a Conveyor section.
func buildCodeDesc(section ConveyorSection, scannerName string) string {
	var parts []string

	switch scannerName {
	case "Moldy", "Stigma", "Clamav":
		parts = append(parts, fmt.Sprintf("title_text:%s", section.TitleText))
		parts = append(parts, fmt.Sprintf("body:%s", bodyToString(section.Body)))
		parts = append(parts, fmt.Sprintf("body_format:%s", section.BodyFormat))
		parts = append(parts, fmt.Sprintf("classification:%s", section.Classification))
		parts = append(parts, fmt.Sprintf("depth:%.0f", section.Depth))
		if section.Heuristic != nil {
			parts = append(parts, fmt.Sprintf("heuristic_heur_id:%s", section.Heuristic.HeurID))
			parts = append(parts, fmt.Sprintf("heuristic_score:%.0f", section.Heuristic.Score))
			parts = append(parts, fmt.Sprintf("heuristic_name:%s", section.Heuristic.Name))
		}
	case "CodeQuality":
		parts = append(parts, fmt.Sprintf("body:%s", bodyToString(section.Body)))
		parts = append(parts, fmt.Sprintf("body_format:%s", section.BodyFormat))
		parts = append(parts, fmt.Sprintf("classification:%s", section.Classification))
		parts = append(parts, fmt.Sprintf("depth:%.0f", section.Depth))
		parts = append(parts, fmt.Sprintf("title_text:%s", section.TitleText))
	default:
		data, _ := json.Marshal(section)
		return string(data)
	}

	return strings.Join(parts, "\n")
}

// groupResultsByScanner groups Conveyor results by their service (scanner) name.
// Returns scanner names in sorted order and a map from scanner name to results.
// Results within each group are sorted by SHA256 for deterministic output.
func groupResultsByScanner(results map[string]ConveyorResult) ([]string, map[string][]ConveyorResult) {
	groups := make(map[string][]ConveyorResult)

	// Sort map keys for deterministic iteration order
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		result := results[k]
		name := result.Response.ServiceName
		groups[name] = append(groups[name], result)
	}

	scanners := make([]string, 0, len(groups))
	for name := range groups {
		scanners = append(scanners, name)
	}
	sort.Strings(scanners)
	return scanners, groups
}

// firstServiceVersion returns the scanner version to record as tool.version.
// Conveyor's service_tool_version is null in observed output, so the value comes
// from response.service_version. Because that version is per-scanner (it varies
// across results), the first entry in sorted result-key order is taken so Go and
// TypeScript pick the same deterministic value. Returns "" when none is present.
func firstServiceVersion(results map[string]ConveyorResult) string {
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := results[k].Response.ServiceVersion; v != "" {
			return v
		}
	}
	return ""
}

// buildRequirement converts a Conveyor result into an HDF EvaluatedRequirement.
func buildRequirement(result ConveyorResult, filename string) hdf.EvaluatedRequirement {
	nist := shared.DefaultStaticAnalysisNIST
	cciTags := cci.NISTToCCI(nist)
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, scannerTagExtras(result))

	// Build description from sections
	descText := ""
	if len(result.Result.Sections) > 0 {
		var sectionTexts []string
		for _, section := range result.Result.Sections {
			sectionTexts = append(sectionTexts, section.TitleText)
		}
		descText = strings.Join(sectionTexts, "; ")
	}
	if descText == "" {
		descText = fmt.Sprintf("Conveyor scan result for %s", result.SHA256)
	}

	descriptions := []hdf.Description{
		{Label: "default", Data: descText},
	}

	// Build results from sections. start_time is when the scan started
	// (service_started); fall back to the zero time when the source omits it.
	// run_time is the scan's elapsed seconds (service_completed − service_started).
	scannerName := result.Response.ServiceName
	startTime := hdfutil.ParseTimestamp(result.Response.Milestones.ServiceStarted)
	runTime := computeRunTime(result.Response.Milestones.ServiceStarted, result.Response.Milestones.ServiceCompleted)
	score := result.Result.Score
	status := determineStatus(score)

	var results []hdf.RequirementResult
	if len(result.Result.Sections) > 0 {
		for _, section := range result.Result.Sections {
			codeDesc := buildCodeDesc(section, scannerName)
			r := hdf.RequirementResult{
				Status:    status,
				CodeDesc:  codeDesc,
				StartTime: startTime,
				RunTime:   runTime,
			}
			results = append(results, r)
		}
	} else {
		// No sections — still need at least one result
		results = []hdf.RequirementResult{
			{
				Status:    status,
				CodeDesc:  fmt.Sprintf("No sections reported by %s", scannerName),
				StartTime: startTime,
				RunTime:   runTime,
			},
		}
	}

	title := filename
	return hdf.EvaluatedRequirement{
		ID:                 result.SHA256,
		Title:              &title,
		Impact:             scoreToImpact(score),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// buildScannerBaseline creates an HDF baseline for a single scanner's results.
func buildScannerBaseline(scannerName string, results []ConveyorResult, shaMap map[string]string, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	limited := shared.LimitSliceWithWarning(results, 0, "result")

	requirements := make([]hdf.EvaluatedRequirement, len(limited))
	for i, result := range limited {
		filename := shaMap[result.SHA256]
		requirements[i] = buildRequirement(result, filename)
	}

	title := fmt.Sprintf("Conveyor Scan (%s)", scannerName)

	return hdf.EvaluatedBaseline{
		Name:            "Conveyor Scan",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}
}

// ConvertConveyorToHDF converts Conveyor scan results to HDF format.
// Results are grouped by scanner name, producing one baseline per scanner.
func ConvertConveyorToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("conveyor: empty input")
	}
	if err := shared.ValidateJSONSize(input, "conveyor", 0); err != nil {
		return nil, fmt.Errorf("conveyor: %w", err)
	}

	var data ConveyorData
	if err := json.Unmarshal(input, &data); err != nil {
		return nil, fmt.Errorf("conveyor: invalid JSON: %w", err)
	}

	if data.APIResponse == nil {
		return nil, fmt.Errorf("conveyor: missing api_response field")
	}

	if data.APIResponse.Results == nil {
		return nil, fmt.Errorf("conveyor: missing api_response.results field")
	}

	checksum := shared.InputChecksum(input)

	// Build SHA → filename mapping from file tree
	shaMap := collateSHAAndFilenames(data.APIResponse.FileTree)

	// Group results by scanner
	scanners, groups := groupResultsByScanner(data.APIResponse.Results)

	baselines := make([]hdf.EvaluatedBaseline, len(scanners))
	for i, scannerName := range scanners {
		baselines[i] = buildScannerBaseline(scannerName, groups[scannerName], shaMap, checksum)
	}

	// Build target name from params.description
	targetName := "Conveyor Scan"
	if data.APIResponse.Params != nil {
		if desc, ok := data.APIResponse.Params["description"].(string); ok && desc != "" {
			targetName = desc
		}
	}

	now := time.Now().UTC()

	// Prefer the submission's overall completion time; fall back to now() only
	// when the source omits it, so the document timestamp is source-anchored.
	timestamp := now
	if t := hdfutil.ParseTimestamp(data.APIResponse.Times.Completed); !t.IsZero() {
		timestamp = t
	}

	toolVersion := firstServiceVersion(data.APIResponse.Results)

	if len(baselines) == 0 {
		title := "Conveyor Scan (no findings)"
		baselines = []hdf.EvaluatedBaseline{
			{
				Name:            "Conveyor Scan",
				Title:           &title,
				ResultsChecksum: checksum,
				Requirements: []hdf.EvaluatedRequirement{
					shared.BuildNoFindingsRequirement(
						"conveyor-no-findings",
						fmt.Sprintf("Conveyor scanned %s and reported zero findings.", targetName),
						now,
					),
				},
			},
		}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "conveyor-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Conveyor",
		ToolVersion:      toolVersion,
		Baselines:        baselines,
		Components: []hdf.Component{
			{Name: targetName, Type: hdf.Application},
		},
		Timestamp: &timestamp,
	}), nil
}
