// Package hdftosplunk exports HDF Results as Splunk HEC-envelope NDJSON,
// normalized to the Common Information Model (CIM).
//
// One HEC event is emitted per Evaluated_Requirement, in the hybrid shape from
// ADR-0004: flat CIM-named scalars (signature/signature_id/cve/cvss/severity/
// dest/vendor_product/category) are promoted to the top of the event payload,
// the hot query scalars among them (signature/signature_id/dest/severity/cve/
// cvss + hdf_status + suppressed) are additionally mirrored into the HEC indexed
// `fields` so they survive Splunk's ~5000-char extraction cutoff, and a lossless
// hdf.* block preserves the full requirement. Output is plain NDJSON (one HEC
// object per line, LF-delimited, trailing newline).
//
// Status is raw-primary: hdf_status carries the RAW verdict (a waived failure is
// still failed), and suppressed is the separate acceptance axis (raw-failing but
// accepted via waiver/falsePositive/attestation). The companion TA
// (Splunk_TA_hdf) tags failed/error/CVE findings into the CIM Vulnerabilities
// data model but excludes suppressed=true, so a waived control drops out while a
// risk-adjusted still-failing control stays in. The canonical "still actionable"
// query is hdf_status=failed suppressed=false.
//
// Generic JSON access, the status roll-up, field extraction, the lossless hdf.*
// block, and the canonical byte-identical line encoder are shared with the
// other exporters via the exportmap package; only Splunk/CIM-specific shaping
// lives here.
package hdftosplunk

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	sourcetype = "hdf:results"
	source     = "hdf-exporter"
)

// ConvertHDFToSplunk converts an HDF Results document to Splunk HEC NDJSON.
func ConvertHDFToSplunk(input []byte, converterVersion string) ([]byte, error) {
	return exportmap.Export(input, "hdf-to-splunk",
		func(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{} {
			return buildHECEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion)
		})
}

// buildHECEvent maps one Evaluated_Requirement to a single HEC event envelope.
func buildHECEvent(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}, converterVersion string) map[string]interface{} {
	st := exportmap.StatusOf(req)
	title := exportmap.GetStr(req, "title")
	controlID := exportmap.GetStr(req, "id")

	// CIM scalars
	signature := title
	if signature == "" {
		signature = controlID
	}
	dest := destHost(component)
	severity := severity(req)
	cvss, hasCVSS := maxCVSS(req)
	cvssListForCVE, _ := exportmap.AsSlice(req["cvss"])
	cve := exportmap.FirstCVE(cvssListForCVE)
	category := firstCWE(req)
	vendorProduct := exportmap.GetStr(tool, "name")

	event := map[string]interface{}{
		"signature":  signature,
		"hdf_status": st.Raw,
		"suppressed": st.Suppressed,
		"hdf":        exportmap.BuildHDFBlock(req, baseline, st.Raw, st.Overridden, st.Suppressed, generator, tool, converterVersion),
	}
	exportmap.SetIf(event, "signature_id", controlID)
	exportmap.SetIf(event, "dest", dest)
	exportmap.SetIf(event, "severity", severity)
	exportmap.SetIf(event, "cve", cve)
	exportmap.SetIf(event, "category", category)
	exportmap.SetIf(event, "vendor_product", vendorProduct)
	if hasCVSS {
		event["cvss"] = cvss
	}

	// indexed fields: flat copy of the hot CIM scalars (beats the 5000-char cutoff)
	fields := map[string]interface{}{
		"signature":  signature,
		"hdf_status": st.Raw,
		"suppressed": st.Suppressed,
	}
	exportmap.SetIf(fields, "signature_id", controlID)
	exportmap.SetIf(fields, "dest", dest)
	exportmap.SetIf(fields, "severity", severity)
	exportmap.SetIf(fields, "cve", cve)
	if hasCVSS {
		fields["cvss"] = cvss
	}

	hec := map[string]interface{}{
		"source":     source,
		"sourcetype": sourcetype,
		"event":      event,
		"fields":     fields,
	}
	if sec, ok := exportmap.EpochSeconds(exportmap.FirstResultStartTime(req, docTimestamp)); ok {
		hec["time"] = sec
	}
	exportmap.SetIf(hec, "host", dest)
	return hec
}

// destHost returns the target host: fqdn, else name, else ipAddress.
func destHost(component map[string]interface{}) string {
	if component == nil {
		return ""
	}
	if v := exportmap.GetStr(component, "fqdn"); v != "" {
		return v
	}
	if v := exportmap.GetStr(component, "name"); v != "" {
		return v
	}
	return exportmap.GetStr(component, "ipAddress")
}

// severity maps an HDF requirement to the CIM severity enum
// (critical|high|medium|low|informational), preferring the numeric impact and
// falling back to a source severity string.
func severity(req map[string]interface{}) string {
	if impact, ok := req["impact"].(float64); ok {
		return hdfutil.ImpactToSeverity(impact)
	}
	return normalizeSeverity(exportmap.GetStr(req, "severity"))
}

// normalizeSeverity coerces an arbitrary severity string onto the CIM enum;
// anything outside the CIM set (including empty) falls back to informational.
func normalizeSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "informational":
		return s
	default:
		return "informational"
	}
}

// maxCVSS returns the maximum baseScore across the requirement's cvss[] and
// whether any was present.
func maxCVSS(req map[string]interface{}) (float64, bool) {
	list, _ := exportmap.AsSlice(req["cvss"])
	var maxScore float64
	found := false
	for _, c := range list {
		if m, ok := exportmap.AsMap(c); ok {
			if bs, ok := m["baseScore"].(float64); ok {
				if !found || bs > maxScore {
					maxScore = bs
				}
				found = true
			}
		}
	}
	return maxScore, found
}

// firstCWE returns the first cwe[] id (the finding classification), or "".
func firstCWE(req map[string]interface{}) string {
	list, _ := exportmap.AsSlice(req["cwe"])
	for _, c := range list {
		if s, ok := c.(string); ok && s != "" {
			return s
		}
	}
	return ""
}
