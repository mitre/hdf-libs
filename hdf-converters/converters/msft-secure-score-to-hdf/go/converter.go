// Package msftsecurescore converts Microsoft Secure Score JSON to HDF format.
package msftsecurescore

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// CombinedResponse is the top-level input structure combining secure scores and profiles.
type CombinedResponse struct {
	SecureScore SecureScoreResponse `json:"secureScore"`
	Profiles    ProfileResponse     `json:"profiles"`
}

// SecureScoreResponse wraps the MS Graph secureScores response.
type SecureScoreResponse struct {
	ODataContext string        `json:"@odata.context"`
	Value        []SecureScore `json:"value"`
}

// SecureScore represents a single Microsoft Secure Score assessment.
type SecureScore struct {
	ID                       string         `json:"id"`
	AzureTenantID            string         `json:"azureTenantId"`
	ActiveUserCount          int            `json:"activeUserCount"`
	CreatedDateTime          string         `json:"createdDateTime"`
	CurrentScore             float64        `json:"currentScore"`
	EnabledServices          []string       `json:"enabledServices"`
	LicensedUserCount        int            `json:"licensedUserCount"`
	MaxScore                 float64        `json:"maxScore"`
	ControlScores            []ControlScore `json:"controlScores"`
	AverageComparativeScores []interface{}  `json:"averageComparativeScores"`
}

// ControlScore represents a single control's score within a secure score assessment.
type ControlScore struct {
	ControlCategory      string  `json:"controlCategory"`
	ControlName          string  `json:"controlName"`
	Description          string  `json:"description"`
	Score                float64 `json:"score"`
	LastSynced           string  `json:"lastSynced"`
	ImplementationStatus string  `json:"implementationStatus"`
	On                   string  `json:"on"`
	ScoreInPercentage    float64 `json:"scoreInPercentage"`
}

// ProfileResponse wraps the MS Graph secureScoreControlProfiles response.
type ProfileResponse struct {
	ODataContext  string                      `json:"@odata.context"`
	ODataNextLink string                      `json:"@odata.nextLink"`
	Value         []SecureScoreControlProfile `json:"value"`
}

// SecureScoreControlProfile represents a control profile with remediation details.
type SecureScoreControlProfile struct {
	ID                 string      `json:"id"`
	AzureTenantID      string      `json:"azureTenantId"`
	ActionType         string      `json:"actionType"`
	ActionURL          string      `json:"actionUrl"`
	ControlCategory    string      `json:"controlCategory"`
	Title              string      `json:"title"`
	ImplementationCost string      `json:"implementationCost"`
	MaxScore           float64     `json:"maxScore"`
	Rank               interface{} `json:"rank"`
	Remediation        string      `json:"remediation"`
	RemediationImpact  string      `json:"remediationImpact"`
	Service            string      `json:"service"`
	Threats            interface{} `json:"threats"`
	Tier               string      `json:"tier"`
	UserImpact         string      `json:"userImpact"`
}

// getProfiles returns all profiles matching a given control name.
func getProfiles(profiles []SecureScoreControlProfile, controlName string) []SecureScoreControlProfile {
	var matched []SecureScoreControlProfile
	for _, p := range profiles {
		if p.ID == controlName {
			matched = append(matched, p)
		}
	}
	return matched
}

// getTitle returns the profile title if available, otherwise falls back to
// controlCategory:controlName.
func getTitle(profiles []SecureScoreControlProfile, cs ControlScore) string {
	matched := getProfiles(profiles, cs.ControlName)
	titles := make([]string, 0)
	for _, p := range matched {
		if p.Title != "" {
			titles = append(titles, p.Title)
		}
	}
	if len(titles) > 0 {
		return titles[0]
	}
	// Fallback: category:name
	if cs.ControlCategory != "" && cs.ControlName != "" {
		return cs.ControlCategory + ":" + cs.ControlName
	}
	if cs.ControlName != "" {
		return cs.ControlName
	}
	return cs.ControlCategory
}

// getImpact computes impact from the profile maxScore (maxScore / 10.0).
// Falls back to 0.5 when no matching profile exists.
func getImpact(profiles []SecureScoreControlProfile, cs ControlScore) float64 {
	matched := getProfiles(profiles, cs.ControlName)
	if len(matched) == 0 {
		return 0.5
	}
	maxScore := 0.0
	for _, p := range matched {
		if p.MaxScore > maxScore {
			maxScore = p.MaxScore
		}
	}
	impact := maxScore / 10.0
	// Cap at 1.0
	if impact > 1.0 {
		impact = 1.0
	}
	// Round to avoid floating point noise
	return math.Round(impact*100) / 100
}

// getStatus determines the result status based on scoreInPercentage and profile maxScore.
func getStatus(profiles []SecureScoreControlProfile, cs ControlScore) hdf.ResultStatus {
	if cs.ScoreInPercentage == 100 {
		return hdf.Passed
	}
	matched := getProfiles(profiles, cs.ControlName)
	if len(matched) == 0 {
		return hdf.Failed
	}
	maxScore := 0.0
	for _, p := range matched {
		if p.MaxScore > maxScore {
			maxScore = p.MaxScore
		}
	}
	if cs.Score == maxScore {
		return hdf.Passed
	}
	return hdf.Failed
}

// buildRequirement converts a ControlScore to an HDF EvaluatedRequirement.
func buildRequirement(cs ControlScore, profiles []SecureScoreControlProfile, createdDateTime string) hdf.EvaluatedRequirement {
	id := fmt.Sprintf("%s:%s", cs.ControlCategory, cs.ControlName)

	title := getTitle(profiles, cs)
	impact := getImpact(profiles, cs)
	status := getStatus(profiles, cs)

	// Tags: use default static analysis NIST
	nist := shared.DefaultStaticAnalysisNIST
	tags := shared.BuildNISTCCITags(nist, nil)

	// Descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: hdfutil.StripHTML(cs.Description)},
	}

	// Add fix description from profile remediation
	matched := getProfiles(profiles, cs.ControlName)
	var refs []hdf.Reference
	if len(matched) > 0 {
		for _, p := range matched {
			if p.ActionURL != "" {
				url := p.ActionURL
				refs = append(refs, hdf.Reference{URL: &url})
			}
		}
		remediations := make([]string, 0)
		for _, p := range matched {
			if p.Remediation != "" {
				remediations = append(remediations, hdfutil.StripHTML(p.Remediation))
			}
		}
		if len(remediations) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "fix",
				Data:  remediations[0],
			})
		}

		// Add rationale from remediationImpact
		impacts := make([]string, 0)
		for _, p := range matched {
			if p.RemediationImpact != "" {
				impacts = append(impacts, hdfutil.StripHTML(p.RemediationImpact))
			}
		}
		if len(impacts) > 0 {
			descriptions = append(descriptions, hdf.Description{
				Label: "rationale",
				Data:  impacts[0],
			})
		}

		// Source categorization/metadata from the matched profile(s). Emit each
		// tag only when a matched profile actually carries the value; preserve the
		// source's natural JSON type (threats array, numeric rank, strings).
		for _, p := range matched {
			if arr, ok := p.Threats.([]interface{}); ok && len(arr) > 0 {
				tags["threats"] = arr
				break
			}
		}
		for _, p := range matched {
			if p.Rank != nil {
				tags["rank"] = p.Rank
				break
			}
		}
		for _, p := range matched {
			if p.Service != "" {
				tags["service"] = p.Service
				break
			}
		}
		for _, p := range matched {
			if p.Tier != "" {
				tags["tier"] = p.Tier
				break
			}
		}
		for _, p := range matched {
			if p.UserImpact != "" {
				tags["user_impact"] = p.UserImpact
				break
			}
		}
		for _, p := range matched {
			if p.ActionType != "" {
				tags["action_type"] = p.ActionType
				break
			}
		}
		for _, p := range matched {
			if p.ImplementationCost != "" {
				tags["implementation_cost"] = p.ImplementationCost
				break
			}
		}
	}

	// `on` is carried on the control score itself as a "true"/"false" string
	// (null/absent when Microsoft reports no enablement state). Map to a boolean;
	// omit when neither literal is present.
	switch cs.On {
	case "true":
		tags["on"] = true
	case "false":
		tags["on"] = false
	}

	// CodeDesc from implementationStatus
	codeDesc := cs.ImplementationStatus
	if codeDesc == "" {
		codeDesc = "No implementation status provided"
	}

	// StartTime: the control's own lastSynced (when Microsoft last evaluated it).
	// Fall back to the score snapshot's createdDateTime when a control carries no
	// sync time (startTime is schema-required).
	startTime := hdfutil.ParseTimestamp(cs.LastSynced)
	if startTime.IsZero() {
		startTime = hdfutil.ParseTimestamp(createdDateTime)
	}

	results := []hdf.RequirementResult{
		{
			Status:    status,
			CodeDesc:  codeDesc,
			StartTime: startTime,
		},
	}

	return hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Impact:             impact,
		Tags:               tags,
		Descriptions:       descriptions,
		Refs:               refs,
		Results:            results,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}
}

// ConvertMsftSecureScoreToHDF converts Microsoft Secure Score JSON to HDF format.
// Input is the combined JSON containing both secureScore and profiles data
// from the Microsoft Graph API.
func ConvertMsftSecureScoreToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("msft-secure-score: empty input")
	}
	if err := shared.ValidateJSONSize(input, "msft-secure-score", 0); err != nil {
		return nil, fmt.Errorf("msft-secure-score: %w", err)
	}

	var combined CombinedResponse
	if err := json.Unmarshal(input, &combined); err != nil {
		return nil, fmt.Errorf("msft-secure-score: invalid JSON: %w", err)
	}

	// Validate required fields
	if combined.SecureScore.Value == nil {
		return nil, fmt.Errorf("msft-secure-score: missing secureScore.value")
	}
	if combined.Profiles.Value == nil {
		return nil, fmt.Errorf("msft-secure-score: missing profiles.value")
	}
	if len(combined.SecureScore.Value) == 0 {
		return nil, fmt.Errorf("msft-secure-score: secureScore.value is empty")
	}

	checksum := shared.InputChecksum(input)

	// Process each secureScore entry as a separate baseline
	// (typically there's only one, but the API can return multiple)
	baselines := make([]hdf.EvaluatedBaseline, 0, len(combined.SecureScore.Value))
	profiles := combined.Profiles.Value

	var tenantID string
	for _, ss := range combined.SecureScore.Value {
		if tenantID == "" {
			tenantID = ss.AzureTenantID
		}

		controlScores := shared.LimitSliceWithWarning(ss.ControlScores, 0, "controlScore")

		requirements := make([]hdf.EvaluatedRequirement, len(controlScores))
		for i, cs := range controlScores {
			requirements[i] = buildRequirement(cs, profiles, ss.CreatedDateTime)
		}

		title := fmt.Sprintf("Azure Secure Score report - Tenant ID: %s - Run ID: %s", ss.AzureTenantID, ss.ID)

		baseline := hdf.EvaluatedBaseline{
			Name:            "Microsoft Secure Score",
			Title:           &title,
			Requirements:    requirements,
			ResultsChecksum: checksum,
		}

		baselines = append(baselines, baseline)
	}

	// Top-level timestamp: the score snapshot's createdDateTime (when Microsoft
	// generated this Secure Score), not wall-clock now — keeps conversion
	// deterministic. Fall back to now only when the snapshot carries no time.
	timestamp := hdfutil.ParseTimestamp(combined.SecureScore.Value[0].CreatedDateTime)
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	// Target: cloud account
	provider := hdf.Azure
	targetName := fmt.Sprintf("Azure Tenant: %s", tenantID)

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "msft-secure-score-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Microsoft Secure Score",
		Baselines:        baselines,
		Components: []hdf.Component{
			{
				Name:     targetName,
				Type:     hdf.CloudAccount,
				Provider: &provider,
				Labels: map[string]string{
					"account":  tenantID,
					"provider": "azure",
				},
			},
		},
		Timestamp: &timestamp,
	}), nil
}
