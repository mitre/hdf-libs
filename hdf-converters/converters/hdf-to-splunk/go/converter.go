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
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	sourcetype = "hdf:results"
	source     = "hdf-exporter"
)

// ConvertHDFToSplunk converts an HDF Results document to Splunk HEC NDJSON.
func ConvertHDFToSplunk(input []byte, converterVersion string) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-splunk: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-splunk", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-splunk: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("hdf-to-splunk: invalid HDF JSON: %w", err)
	}
	baselines, ok := exportmap.AsSlice(doc["baselines"])
	if !ok {
		return nil, fmt.Errorf("hdf-to-splunk: invalid HDF structure: missing baselines field")
	}

	docTimestamp := exportmap.GetStr(doc, "timestamp")
	tool, _ := exportmap.AsMap(doc["tool"])
	generator, _ := exportmap.AsMap(doc["generator"])
	component := exportmap.FirstComponent(doc)

	var out []byte
	for _, bRaw := range baselines {
		baseline, ok := exportmap.AsMap(bRaw)
		if !ok {
			continue
		}
		reqs, _ := exportmap.AsSlice(baseline["requirements"])
		for _, rRaw := range reqs {
			req, ok := exportmap.AsMap(rRaw)
			if !ok {
				continue
			}
			hecEvent := buildHECEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion)
			line, err := exportmap.EncodeLine(hecEvent)
			if err != nil {
				return nil, fmt.Errorf("hdf-to-splunk: encode: %w", err)
			}
			out = append(out, line...)
		}
	}
	return out, nil
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
	cve := firstCVE(req)
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
	if t := epochSeconds(exportmap.FirstResultStartTime(req, docTimestamp)); t != nil {
		hec["time"] = *t
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
		switch {
		case impact >= 0.9:
			return "critical"
		case impact >= 0.7:
			return "high"
		case impact >= 0.4:
			return "medium"
		case impact >= 0.1:
			return "low"
		default:
			return "informational"
		}
	}
	return normalizeSeverity(exportmap.GetStr(req, "severity"))
}

// normalizeSeverity coerces an arbitrary severity string onto the CIM enum.
func normalizeSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "informational":
		return s
	case "none", "info", "informational ", "unknown", "":
		return "informational"
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

// firstCVE returns the first CVE-shaped cvss[].source, or "".
func firstCVE(req map[string]interface{}) string {
	list, _ := exportmap.AsSlice(req["cvss"])
	for _, c := range list {
		if m, ok := exportmap.AsMap(c); ok {
			if src := exportmap.GetStr(m, "source"); strings.HasPrefix(strings.ToUpper(src), "CVE-") {
				return src
			}
		}
	}
	return ""
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

// epochSeconds parses an HDF RFC3339 timestamp into integer epoch seconds via
// the canonical parser, returning nil when empty/unparseable (HEC then stamps
// receive-time). Integer seconds keep Go and TypeScript byte-identical.
func epochSeconds(s string) *int64 {
	t := hdfutil.ParseTimestamp(s)
	if t.IsZero() {
		return nil
	}
	sec := t.Unix()
	return &sec
}
