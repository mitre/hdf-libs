package zap_to_hdf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	sarif "github.com/mitre/hdf-converters/converters/sarif-to-hdf/go"
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
	"github.com/mitre/hdf-mappings/go/cci"
	"github.com/mitre/hdf-mappings/go/cwe"
	hdf "github.com/mitre/hdf-schema"
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
// Falls back to shared.ParseTimestamp for other formats.
func parseZapTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// ZAP-specific format: "Mon, 2 Jan 2006 15:04:05"
	if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05", s); err == nil {
		return t
	}
	return shared.ParseTimestamp(s)
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
	return shared.SeverityToImpactWithAliases(riskCode, zapAliases, 0.5)
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

// --- Build check description ---

func buildCheckDescription(alert ZapAlert) string {
	result := ""
	if alert.Solution != "" {
		stripped := shared.StripHTML(alert.Solution)
		if stripped != "" {
			result = stripped
		}
	}
	if alert.OtherInfo != "" {
		stripped := shared.StripHTML(alert.OtherInfo)
		if stripped != "" {
			if result != "" {
				result += "\n"
			}
			result += stripped
		}
	}
	return result
}

// --- Select site with most alerts ---

func selectSite(sites []ZapSite) *ZapSite {
	if len(sites) == 0 {
		return nil
	}
	best := &sites[0]
	for i := 1; i < len(sites); i++ {
		if len(sites[i].Alerts) > len(best.Alerts) {
			best = &sites[i]
		}
	}
	return best
}

// ConvertZapToHDF converts OWASP ZAP JSON to HDF Results.
// If the input is detected as SARIF, it delegates to the SARIF converter.
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

	// Select site with most alerts
	site := selectSite(zapData.Site)

	var requirements []hdf.EvaluatedRequirement
	targetName := "Unknown Host"
	siteName := ""

	if site != nil {
		if site.Host != "" {
			targetName = site.Host
		}
		siteName = site.Name

		// Deduplicate pluginids
		pluginIDCount := make(map[string]int)

		limitedAlerts := shared.LimitSliceWithWarning(site.Alerts, 0, "alert")

		zeroTime := time.Time{}

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

			// Build extra tags
			extras := make(map[string]interface{})
			if alert.CweID != "" {
				extras["cweid"] = alert.CweID
			}
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
					Data:  shared.StripHTML(alert.Desc),
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
				ID:           reqID,
				Title:        &alert.AlertName,
				Impact:       impact,
				Results:      results,
				Tags:         tags,
				Descriptions: descriptions,
			}

			requirements = append(requirements, req)
		}
	}

	baselineName := "OWASP ZAP Scan"
	if siteName != "" {
		baselineName = fmt.Sprintf("OWASP ZAP Scan of %s", siteName)
	}
	summary := fmt.Sprintf("ZAP Version %s", zapData.Version)

	scanLabel := "OWASP ZAP Scan"
	baseline := hdf.EvaluatedBaseline{
		Name:            scanLabel,
		Title:           &baselineName,
		Summary:         &summary,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Build targets — ZAP is a DAST tool scanning web applications
	var targets []hdf.Component
	if siteName != "" {
		targets = append(targets, hdf.Component{
			Name: targetName,
			Type: hdf.CopyrightApplication,
			URL:  &siteName,
		})
	} else if targetName != "Unknown Host" {
		targets = append(targets, hdf.Component{
			Name: targetName,
			Type: hdf.CopyrightApplication,
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
		GeneratorName:     "zap-to-hdf",
		ConverterVersion:  converterVersion,
		ToolName:          "OWASP ZAP",
		ToolVersion:       zapData.Version,
		ToolFormat:        "JSON",
		Baselines:         []hdf.EvaluatedBaseline{baseline},
		Components:           targets,
		Timestamp:         timestamp,
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
