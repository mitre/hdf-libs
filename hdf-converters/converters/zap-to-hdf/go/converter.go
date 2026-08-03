package zap_to_hdf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- ZAP JSON input structures ---

// ZapReport is the top-level ZAP JSON object.
type ZapReport struct {
	Generated string    `json:"@generated,omitempty"`
	Version   string    `json:"@version,omitempty"`
	Site      []ZapSite `json:"site"`
}

// ZapSite represents one scanned site.
type ZapSite struct {
	Host   string     `json:"@host,omitempty"`
	Name   string     `json:"@name,omitempty"`
	Port   string     `json:"@port,omitempty"`
	SSL    string     `json:"@ssl,omitempty"`
	Alerts []ZapAlert `json:"alerts"`
}

// ZapAlert is a single alert (finding) within a site.
type ZapAlert struct {
	PluginID   string        `json:"pluginid"`
	AlertName  string        `json:"name"`
	Alert      string        `json:"alert,omitempty"`
	CweID      string        `json:"cweid,omitempty"`
	WascID     string        `json:"wascid,omitempty"`
	RiskCode   string        `json:"riskcode,omitempty"`
	RiskDesc   string        `json:"riskdesc,omitempty"`
	Confidence string        `json:"confidence,omitempty"`
	Count      string        `json:"count,omitempty"`
	Desc       string        `json:"desc,omitempty"`
	Solution   string        `json:"solution,omitempty"`
	OtherInfo  string        `json:"otherinfo,omitempty"`
	Reference  string        `json:"reference,omitempty"`
	SourceID   string        `json:"sourceid,omitempty"`
	Instances  []ZapInstance `json:"instances"`
}

// ZapInstance is one occurrence of an alert.
type ZapInstance struct {
	URI      string `json:"uri,omitempty"`
	Method   string `json:"method,omitempty"`
	Param    string `json:"param,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Attack   string `json:"attack,omitempty"`
}

// --- ZAP timestamp parsing ---

// parseZapTimestamp parses ZAP's timestamp format "Thu, 6 Dec 2018 10:53:11"
// which is RFC1123-like but without timezone and allows single-digit day.
// Falls back to hdfutil.ParseTimestamp for other formats.
func parseZapTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// ZAP-specific format: "Mon, 2 Jan 2006 15:04:05"
	if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05", s); err == nil {
		return hdfutil.NormalizeTimestamp(t)
	}
	return hdfutil.ParseTimestamp(s)
}

// --- Risk code to impact ---
// ZAP uses numeric risk codes (0-3), not standard severity labels.

var zapAliases = map[string]float64{
	"0": 0.3,
	"1": 0.3,
	"2": 0.5,
	"3": 0.7,
}

func riskCodeToImpact(riskCode string) float64 {
	return hdfutil.SeverityToImpactWithAliases(riskCode, zapAliases, 0.5)
}

// --- NIST tag building ---

func buildNistTags(cweid string) []string {
	if cweid != "" && cweid != "0" {
		controls := cwe.NISTControls(cweid)
		if len(controls) > 0 {
			return controls
		}
	}
	return shared.DefaultStaticAnalysisNIST
}

// buildCwe promotes a ZAP alert cweid to a first-class requirement.cwe entry
// in the canonical "CWE-N" form (no leading zeros). Returns nil when the alert
// carries no usable CWE ("", "0", or a non-numeric value).
func buildCwe(cweid string) []string {
	if n := parseCweID(cweid); n != 0 {
		return []string{fmt.Sprintf("CWE-%d", n)}
	}
	return nil
}

// --- Instance to code desc ---

func buildCodeDesc(instance ZapInstance) string {
	result := ""
	if instance.URI != "" {
		result = fmt.Sprintf("URI: %s", instance.URI)
	}
	if instance.Method != "" {
		if result != "" {
			result += " | "
		}
		result += fmt.Sprintf("Method: %s", instance.Method)
	}
	if instance.Param != "" {
		if result != "" {
			result += " | "
		}
		result += fmt.Sprintf("Param: %s", instance.Param)
	}
	if instance.Evidence != "" {
		if result != "" {
			result += " | "
		}
		result += fmt.Sprintf("Evidence: %s", instance.Evidence)
	}
	return result
}

// --- Requirement code (CODE tab) synthesis ---

// representativeInstance picks the instance best representing the alert for the
// CODE tab: the first instance carrying an attack payload, falling back to the
// first instance when none do. Returns false when there are no instances.
func representativeInstance(instances []ZapInstance) (ZapInstance, bool) {
	if len(instances) == 0 {
		return ZapInstance{}, false
	}
	for _, inst := range instances {
		if inst.Attack != "" {
			return inst, true
		}
	}
	return instances[0], true
}

// buildRequirementCode synthesizes requirement.code for a DAST finding from the
// HTTP request context of the representative instance: "<METHOD> <uri>" plus an
// optional "Param:" line and an optional "Attack:" line. ZAP has no source code,
// so this reconstructs the request/payload that triggered the alert. Returns nil
// when the alert carries no instances or no request context (NOT-IN-SOURCE).
func buildRequirementCode(alert ZapAlert) *string {
	inst, ok := representativeInstance(alert.Instances)
	if !ok {
		return nil
	}
	var parts []string
	if requestLine := strings.TrimSpace(inst.Method + " " + inst.URI); requestLine != "" {
		parts = append(parts, requestLine)
	}
	if inst.Param != "" {
		parts = append(parts, "Param: "+inst.Param)
	}
	if inst.Attack != "" {
		parts = append(parts, "Attack: "+inst.Attack)
	}
	if len(parts) == 0 {
		return nil
	}
	code := strings.Join(parts, "\n")
	return &code
}

// --- Build check description ---

func buildCheckDescription(alert ZapAlert) string {
	result := ""
	if alert.Solution != "" {
		stripped := hdfutil.StripHTML(alert.Solution)
		if stripped != "" {
			result = stripped
		}
	}
	if alert.OtherInfo != "" {
		stripped := hdfutil.StripHTML(alert.OtherInfo)
		if stripped != "" {
			if result != "" {
				result += "\n"
			}
			result += stripped
		}
	}
	return result
}

// --- Per-site labeling ---

// siteLabel returns a stable, human-readable label identifying a site, used to
// build a unique per-site baseline name. Prefers the host, then the site name
// (URL), then a positional fallback so a nameless site still gets a unique name.
func siteLabel(site *ZapSite, index int) string {
	if site.Host != "" {
		return site.Host
	}
	if site.Name != "" {
		return site.Name
	}
	return fmt.Sprintf("site %d", index+1)
}

// buildSiteRequirements converts one site's alerts into requirements, applying
// the per-site pluginid dedup (duplicates within the site get .1, .2, ...).
// Dedup is scoped to the site so the same pluginid on two different hosts stays
// intact in each host's baseline.
func buildSiteRequirements(site *ZapSite) []hdf.EvaluatedRequirement {
	pluginIDCount := make(map[string]int)
	limitedAlerts := shared.LimitSliceWithWarning(site.Alerts, 0, "alert")
	zeroTime := time.Time{}

	var requirements []hdf.EvaluatedRequirement
	for _, alert := range limitedAlerts {
		// Deduplicate
		count := pluginIDCount[alert.PluginID]
		pluginIDCount[alert.PluginID] = count + 1
		reqID := alert.PluginID
		if count > 0 {
			reqID = fmt.Sprintf("%s.%d", alert.PluginID, count)
		}

		// Build NIST tags
		nistTags := buildNistTags(alert.CweID)
		cciTags := cci.NISTToCCI(nistTags)

		// Build extra tags. The CWE is promoted to first-class requirement.cwe[]
		// below and no longer duplicated into tags; wascid stays a tag.
		extras := make(map[string]interface{})
		if alert.WascID != "" {
			extras["wascid"] = alert.WascID
		}
		if alert.RiskDesc != "" {
			extras["riskdesc"] = alert.RiskDesc
		}
		if alert.Confidence != "" {
			extras["confidence"] = alert.Confidence
		}
		var tags map[string]interface{}
		if len(extras) > 0 {
			tags = shared.BuildNISTCCITagsWithExtras(nistTags, cciTags, extras)
		} else {
			tags = shared.BuildNISTCCITags(nistTags, cciTags)
		}

		// Build results from instances
		var results []hdf.RequirementResult
		if len(alert.Instances) > 0 {
			limitedInstances := shared.LimitSliceWithWarning(alert.Instances, 0, "instance")
			for _, inst := range limitedInstances {
				result := hdf.RequirementResult{
					Status:    hdf.Failed,
					CodeDesc:  buildCodeDesc(inst),
					StartTime: zeroTime,
				}
				if inst.Attack != "" {
					result.Message = &inst.Attack
				}
				results = append(results, result)
			}
		}

		// Build descriptions
		var descriptions []hdf.Description
		if alert.Desc != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "default",
				Data:  hdfutil.StripHTML(alert.Desc),
			})
		}
		checkDesc := buildCheckDescription(alert)
		if checkDesc != "" {
			descriptions = append(descriptions, hdf.Description{
				Label: "check",
				Data:  checkDesc,
			})
		}

		impact := riskCodeToImpact(alert.RiskCode)

		req := hdf.EvaluatedRequirement{
			ID:                 reqID,
			Title:              &alert.AlertName,
			Impact:             impact,
			Results:            results,
			Tags:               tags,
			Cwe:                buildCwe(alert.CweID),
			ControlType:        shared.DeriveControlTypeFromTags(nistTags),
			Code:               buildRequirementCode(alert),
			Descriptions:       descriptions,
			VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		}

		requirements = append(requirements, req)
	}
	return requirements
}

// ConvertZapToHDF converts OWASP ZAP JSON to HDF Results.
// If the input is detected as SARIF, it delegates to the SARIF converter.
//
// Every site[] entry is converted to its own baseline plus an Application
// component; multi-host ZAP reports are represented as multiple baselines (one
// per host) rather than a single merged baseline. HDF Results carries no
// per-requirement componentId, and ZAP reuses pluginids across hosts (e.g. the
// same informational alert on several origins), so a single merged baseline
// could neither attribute a finding to its host nor keep the per-site dedup
// intact. One baseline per host — linked to its component via the "component"
// label — is the lossless, attributable representation.
func ConvertZapToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("zap: empty input")
	}
	if err := shared.ValidateJSONSize(input, "zap", 0); err != nil {
		return nil, fmt.Errorf("zap: %w", err)
	}

	// SARIF routing — delegate to the shared SARIF converter
	if result := registry.DetectConverter(input); result != nil && result.Fingerprint.ID == "sarif-to-hdf" {
		return sarif.ConvertSarifToHDF(input, converterVersion)
	}

	resultsChecksum := shared.InputChecksum(input)

	var zapData ZapReport
	if err := json.Unmarshal(input, &zapData); err != nil {
		return nil, fmt.Errorf("invalid ZAP JSON: %w", err)
	}

	summary := fmt.Sprintf("ZAP Version %s", zapData.Version)
	multiSite := len(zapData.Site) > 1

	var baselines []hdf.EvaluatedBaseline
	var components []hdf.Component

	for i := range zapData.Site {
		site := &zapData.Site[i]

		targetName := "Unknown Host"
		if site.Host != "" {
			targetName = site.Host
		}
		siteName := site.Name

		requirements := buildSiteRequirements(site)
		if len(requirements) == 0 {
			target := siteName
			if target == "" {
				target = targetName
			}
			if target == "" || target == "Unknown Host" {
				target = "the target site"
			}
			requirements = []hdf.EvaluatedRequirement{
				shared.BuildNoFindingsRequirement(
					"zap-no-findings",
					fmt.Sprintf("OWASP ZAP scanned %s and reported zero findings.", target),
					time.Now().UTC(),
				),
			}
		}

		baselineTitle := "OWASP ZAP Scan"
		if siteName != "" {
			baselineTitle = fmt.Sprintf("OWASP ZAP Scan of %s", siteName)
		}

		// Single-site reports keep the legacy fixed baseline name; multi-site
		// reports get a host-scoped, unique name so baselines stay identifiable.
		scanLabel := "OWASP ZAP Scan"
		if multiSite {
			scanLabel = fmt.Sprintf("OWASP ZAP Scan: %s", siteLabel(site, i))
		}

		baseline := hdf.EvaluatedBaseline{
			Name:            scanLabel,
			Title:           &baselineTitle,
			Summary:         &summary,
			Requirements:    requirements,
			ResultsChecksum: resultsChecksum,
		}
		// Link the baseline to its host component for explicit attribution.
		if site.Host != "" {
			baseline.Labels = map[string]string{"component": site.Host}
		}
		baselines = append(baselines, baseline)

		// Build the component — ZAP is a DAST tool scanning web applications.
		if siteName != "" {
			url := siteName
			components = append(components, hdf.Component{
				Name: targetName,
				Type: hdf.Application,
				URL:  &url,
			})
		} else if targetName != "Unknown Host" {
			components = append(components, hdf.Component{
				Name: targetName,
				Type: hdf.Application,
			})
		}
	}

	// No sites at all — synthesize a single no-findings baseline.
	if len(baselines) == 0 {
		title := "OWASP ZAP Scan"
		baselines = append(baselines, hdf.EvaluatedBaseline{
			Name:    "OWASP ZAP Scan",
			Title:   &title,
			Summary: &summary,
			Requirements: []hdf.EvaluatedRequirement{
				shared.BuildNoFindingsRequirement(
					"zap-no-findings",
					"OWASP ZAP scanned the target site and reported zero findings.",
					time.Now().UTC(),
				),
			},
			ResultsChecksum: resultsChecksum,
		})
	}

	// Compute timestamp before building results
	var timestamp *time.Time
	if zapData.Generated != "" {
		ts := parseZapTimestamp(zapData.Generated)
		if !ts.IsZero() {
			timestamp = &ts
		}
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "zap-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "OWASP ZAP",
		ToolVersion:      zapData.Version,
		Baselines:        baselines,
		Components:       components,
		Timestamp:        timestamp,
	})

	return hdfResult, nil
}

// deduplicateID returns the deduplicated requirement ID given a
// pluginid and the number of times it has been seen before.
func deduplicateID(pluginID string, count int) string {
	if count == 0 {
		return pluginID
	}
	return fmt.Sprintf("%s.%d", pluginID, count)
}

// parseCweID attempts to parse a CWE ID string to an integer.
// Returns 0 if the string is empty or invalid.
func parseCweID(cweid string) int {
	if cweid == "" || cweid == "0" {
		return 0
	}
	n, err := strconv.Atoi(cweid)
	if err != nil {
		return 0
	}
	return n
}
