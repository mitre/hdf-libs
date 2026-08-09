// Package hdftoasff exports HDF Results as AWS Security Finding Format (ASFF)
// findings — the reverse of asff-to-hdf. Output is the standard
// {"Findings": [...]} envelope that Security Hub's BatchImportFindings accepts
// and that asff-to-hdf reads back.
//
// One ASFF finding is emitted per Evaluated_Requirement (per-requirement
// granularity, matching hdf-to-ocsf and the exportmap harness): a requirement's
// results roll up to one Compliance.Status via the shared StatusOf. The mapping
// is deliberately LOSSY and standard-compliant — HDF structure that ASFF has no
// field for is dropped, NOT crammed into Types[] (heimdall2's rejected
// Types-string encoding). A small amount of provenance rides ProductFields
// (ASFF's official string map), never the Types taxonomy. See the converter
// README for the round-trip fidelity table.
//
// ProductArn / AwsAccountId / Region are ASFF-required but absent from HDF: the
// account is recovered from a cloudAccount component when present (the clean
// reverse of asff-to-hdf's AwsAccountId -> component mapping), otherwise a
// documented placeholder is emitted. The Security Hub push path (a separate
// bead) overrides all three with the caller's registered integration before
// upload.
package hdftoasff

import (
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	converterName     = "hdf-to-asff"
	asffSchemaVersion = "2018-10-08"

	// Placeholder identity emitted offline; the push path overrides ProductArn,
	// AwsAccountId and Region with the caller's registered Security Hub product.
	placeholderRegion    = "us-east-1"
	placeholderAccountID = "000000000000"
	// defaultPartition matches the arn:aws:... ProductArn; the push path overrides
	// it (with Region) for aws-cn / aws-us-gov targets.
	defaultPartition = "aws"

	// ASFF field length caps (AWS Security Hub, string constraints).
	maxTitle       = 256
	maxDescription = 1024

	epochSentinel = "1970-01-01T00:00:00Z"
)

// ConvertHDFToASFF converts an HDF Results document to an ASFF findings envelope.
func ConvertHDFToASFF(input []byte, converterVersion string) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("%s: empty input", converterName)
	}
	if err := shared.ValidateJSONSize(input, converterName, 0); err != nil {
		return nil, fmt.Errorf("%s: %w", converterName, err)
	}
	var doc map[string]interface{}
	if err := shared.DecodeHDF(input, &doc); err != nil {
		return nil, fmt.Errorf("%s: invalid HDF JSON: %w", converterName, err)
	}
	baselines, ok := exportmap.AsSlice(doc["baselines"])
	if !ok {
		return nil, fmt.Errorf("%s: invalid HDF structure: missing baselines field", converterName)
	}

	docTimestamp := exportmap.GetStr(doc, "timestamp")
	component := exportmap.FirstComponent(doc)
	tool, _ := exportmap.AsMap(doc["tool"])
	generator, _ := exportmap.AsMap(doc["generator"])
	toolName := exportmap.GetStr(tool, "name")
	generatorName := exportmap.GetStr(generator, "name")
	accountID := recoverAccountID(doc)
	productArn := fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/default", placeholderRegion, accountID, accountID)

	findings := []interface{}{}
	for _, bRaw := range baselines {
		baseline, ok := exportmap.AsMap(bRaw)
		if !ok {
			continue
		}
		baselineName := exportmap.GetStr(baseline, "name")
		baselineVersion := exportmap.GetStr(baseline, "version")
		reqs, _ := exportmap.AsSlice(baseline["requirements"])
		for _, rRaw := range reqs {
			req, ok := exportmap.AsMap(rRaw)
			if !ok {
				continue
			}
			findings = append(findings, buildFinding(req, findingContext{
				baselineName:    baselineName,
				baselineVersion: baselineVersion,
				toolName:        toolName,
				generatorName:   generatorName,
				docTimestamp:    docTimestamp,
				component:       component,
				accountID:       accountID,
				productArn:      productArn,
				exporterVersion: converterVersion,
			}))
		}
	}
	return exportmap.EncodeLine(map[string]interface{}{"Findings": findings})
}

// findingContext carries the doc-/baseline-level values one finding needs beyond
// its own requirement, keeping buildFinding's signature stable as fields grow.
type findingContext struct {
	baselineName    string
	baselineVersion string
	toolName        string
	generatorName   string
	docTimestamp    string
	component       map[string]interface{}
	accountID       string
	productArn      string
	exporterVersion string
}

// recoverAccountID reads AwsAccountId back out of a cloudAccount component (the
// reverse of asff-to-hdf's AwsAccountId -> component mapping), falling back to a
// placeholder when the source HDF has no cloud-account identity.
func recoverAccountID(doc map[string]interface{}) string {
	comps, _ := exportmap.AsSlice(doc["components"])
	for _, cRaw := range comps {
		c, ok := exportmap.AsMap(cRaw)
		if !ok {
			continue
		}
		if exportmap.GetStr(c, "type") != "cloudAccount" {
			continue
		}
		// asff-to-hdf stores the account id as the component's accountId (preferred)
		// or name; accept either.
		if id := exportmap.GetStr(c, "accountId"); id != "" {
			return id
		}
		if id := exportmap.GetStr(c, "name"); id != "" {
			return id
		}
	}
	return placeholderAccountID
}

// buildFinding maps one Evaluated_Requirement to a single ASFF finding.
func buildFinding(req map[string]interface{}, ctx findingContext) map[string]interface{} {
	controlID := exportmap.GetStr(req, "id")
	st := exportmap.StatusOf(req)

	title := exportmap.GetStr(req, "title")
	if title == "" {
		title = controlID
	}
	desc := exportmap.DefaultDescription(req)
	if desc == "" {
		desc = title
	}

	cvssList, hasCVSS := exportmap.AsSlice(req["cvss"])
	hasCVSS = hasCVSS && len(cvssList) > 0

	ts := canonicalTime(exportmap.FirstResultStartTime(req, ctx.docTimestamp))
	id := findingID(ctx.accountID, ctx.baselineName, controlID)

	finding := map[string]interface{}{
		"SchemaVersion": asffSchemaVersion,
		"Id":            id,
		"ProductArn":    ctx.productArn,
		"GeneratorId":   controlID,
		"AwsAccountId":  ctx.accountID,
		"CreatedAt":     ts,
		"UpdatedAt":     ts,
		"Title":         truncate(title, maxTitle),
		"Description":   truncate(desc, maxDescription),
		"Types":         asffTypes(hasCVSS),
		"Severity":      severity(req),
		"Resources":     resources(ctx.component, id),
		"RecordState":   "ACTIVE",
		"Compliance":    complianceBlock(req, st.Rollup),
	}
	// The acceptance axis (waiver / falsePositive / attestation drove a failing
	// result non-failing) maps to Security Hub's SUPPRESSED workflow state.
	if st.Suppressed {
		finding["Workflow"] = map[string]interface{}{"Status": "SUPPRESSED"}
	}
	if pf := productFields(ctx, controlID); len(pf) > 0 {
		finding["ProductFields"] = pf
	}
	if rem := remediation(req); rem != nil {
		finding["Remediation"] = rem
	}
	// Vulnerabilities[] carries the structured CVSS/CVE data (and any additional
	// reference URLs) so asff-to-hdf reconstructs requirement.cvss[], the CVE, and
	// the full refs[]. Extra refs ride the first vuln's ReferenceUrls; when a
	// requirement carries refs but no CVSS, the first ref falls back to SourceUrl.
	vulns := vulnerabilities(req)
	if refs := allRefURLs(req); len(refs) > 0 {
		if len(vulns) > 0 {
			vulns[0]["ReferenceUrls"] = refs
		} else {
			finding["SourceUrl"] = refs[0]
		}
	}
	if len(vulns) > 0 {
		finding["Vulnerabilities"] = vulns
	}
	return finding
}

// complianceBlock builds the ASFF Compliance object: the rolled-up status, the
// NIST/CCI control ids as RelatedRequirements, and the parsed status-reason
// message as StatusReasons (the reverse of asff-to-hdf's statusReason flatten).
func complianceBlock(req map[string]interface{}, rollup string) map[string]interface{} {
	comp := map[string]interface{}{"Status": complianceStatus(rollup)}
	if rr := relatedRequirements(req); len(rr) > 0 {
		comp["RelatedRequirements"] = rr
	}
	if sr := statusReasons(req); len(sr) > 0 {
		comp["StatusReasons"] = sr
	}
	return comp
}

// relatedRequirements collects a requirement's NIST controls and CCI ids (in
// that order) for ASFF Compliance.RelatedRequirements — the standard's field for
// related control-framework requirements.
func relatedRequirements(req map[string]interface{}) []string {
	tags, ok := exportmap.AsMap(req["tags"])
	if !ok {
		return nil
	}
	var out []string
	for _, key := range []string{"nist", "cci"} {
		for _, id := range exportmap.StringSlice(tags[key]) {
			if id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

// statusReasons parses the first result message shaped as "ReasonCode: X" /
// "Description: Y" lines back into ASFF Compliance.StatusReasons[] — the exact
// inverse of asff-to-hdf's statusReason flatten, so the pair round-trips. A
// free-form message (no ReasonCode/Description prefixes) yields nothing.
func statusReasons(req map[string]interface{}) []map[string]interface{} {
	msg := firstResultMessage(req)
	if msg == "" {
		return nil
	}
	var out []map[string]interface{}
	var cur map[string]interface{}
	for _, line := range strings.Split(msg, "\n") {
		switch {
		case strings.HasPrefix(line, "ReasonCode: "):
			cur = map[string]interface{}{"ReasonCode": strings.TrimPrefix(line, "ReasonCode: ")}
			out = append(out, cur)
		case strings.HasPrefix(line, "Description: "):
			desc := strings.TrimPrefix(line, "Description: ")
			if cur == nil {
				cur = map[string]interface{}{}
				out = append(out, cur)
			}
			cur["Description"] = desc
		}
	}
	return out
}

// firstResultMessage returns the first non-empty results[].message.
func firstResultMessage(req map[string]interface{}) string {
	results, _ := exportmap.AsSlice(req["results"])
	for _, rRaw := range results {
		if r, ok := exportmap.AsMap(rRaw); ok {
			if m := exportmap.GetStr(r, "message"); m != "" {
				return m
			}
		}
	}
	return ""
}

// vulnerabilities builds ASFF Vulnerabilities[] from requirement.cvss[]: one
// vulnerability per CVSS entry, its Id the CVSS source (the CVE id) and its
// Cvss[] the structured version/base-score/vector/source. asff-to-hdf reads these
// back into requirement.cvss[] and the CVE, closing the round-trip.
func vulnerabilities(req map[string]interface{}) []map[string]interface{} {
	cvssList, _ := exportmap.AsSlice(req["cvss"])
	var out []map[string]interface{}
	for _, cRaw := range cvssList {
		c, ok := exportmap.AsMap(cRaw)
		if !ok {
			continue
		}
		cvssEntry := map[string]interface{}{}
		exportmap.SetIf(cvssEntry, "Version", exportmap.GetStr(c, "version"))
		if bs, ok := c["baseScore"]; ok && bs != nil {
			cvssEntry["BaseScore"] = bs
		}
		exportmap.SetIf(cvssEntry, "BaseVector", exportmap.GetStr(c, "baseVector"))
		exportmap.SetIf(cvssEntry, "Source", exportmap.GetStr(c, "source"))
		vuln := map[string]interface{}{"Cvss": []interface{}{cvssEntry}}
		exportmap.SetIf(vuln, "Id", exportmap.GetStr(c, "source"))
		out = append(out, vuln)
	}
	return out
}

// allRefURLs returns every requirement.refs[].url (deduped, source order).
func allRefURLs(req map[string]interface{}) []string {
	refs, _ := exportmap.AsSlice(req["refs"])
	var out []string
	seen := map[string]bool{}
	for _, rRaw := range refs {
		if r, ok := exportmap.AsMap(rRaw); ok {
			if url := exportmap.GetStr(r, "url"); url != "" && !seen[url] {
				seen[url] = true
				out = append(out, url)
			}
		}
	}
	return out
}

// findingID is a deterministic, per-finding unique id.
func findingID(accountID, baselineName, controlID string) string {
	return strings.Join([]string{accountID, placeholderRegion, baselineName, controlID}, "/")
}

// asffTypes returns the ASFF Types taxonomy: a CVE-bearing requirement is a
// vulnerability finding, everything else a configuration/compliance check.
func asffTypes(hasCVSS bool) []interface{} {
	if hasCVSS {
		return []interface{}{"Software and Configuration Checks/Vulnerabilities/CVE"}
	}
	return []interface{}{"Software and Configuration Checks"}
}

// complianceStatus inverts asff-to-hdf's mapComplianceStatus.
func complianceStatus(status string) string {
	switch status {
	case "passed":
		return "PASSED"
	case "failed":
		return "FAILED"
	case "notApplicable":
		return "NOT_AVAILABLE"
	case "notReviewed", "error":
		return "WARNING"
	default:
		return "WARNING"
	}
}

// severity maps an HDF requirement to an ASFF Severity object, preferring the
// numeric impact (0.0-1.0) that asff-to-hdf produced.
func severity(req map[string]interface{}) map[string]interface{} {
	label := "INFORMATIONAL"
	normalized := 0
	if impact, ok := req["impact"].(float64); ok {
		label = strings.ToUpper(hdfutil.ImpactToSeverity(impact))
		normalized = int(impact * 100)
	}
	return map[string]interface{}{"Label": label, "Normalized": normalized}
}

// resources builds the ASFF Resources array (at least one is required). HDF
// components have no clean AWS resource-type analog, so a generic "Other"
// resource carries the component identity in Details.Other.
func resources(component map[string]interface{}, id string) []interface{} {
	res := map[string]interface{}{
		"Type":      "Other",
		"Id":        id,
		"Partition": defaultPartition,
		"Region":    placeholderRegion,
	}
	if component != nil {
		details := map[string]interface{}{}
		exportmap.SetIf(details, "Name", exportmap.GetStr(component, "name"))
		exportmap.SetIf(details, "Type", exportmap.GetStr(component, "type"))
		exportmap.SetIf(details, "IpAddress", exportmap.GetStr(component, "ipAddress"))
		exportmap.SetIf(details, "OsName", exportmap.GetStr(component, "osName"))
		if len(details) > 0 {
			res["Details"] = map[string]interface{}{"Other": details}
		}
	}
	return []interface{}{res}
}

// productFields carries HDF provenance on ASFF's official string map — NOT the
// Types taxonomy. These are informational only; asff-to-hdf does not read them.
// The source tool/generator identity and baseline version preserve the
// originating scanner that HDF records at the document/baseline level.
func productFields(ctx findingContext, controlID string) map[string]interface{} {
	pf := map[string]interface{}{}
	exportmap.SetIf(pf, "hdf/baseline", ctx.baselineName)
	exportmap.SetIf(pf, "hdf/baseline_version", ctx.baselineVersion)
	exportmap.SetIf(pf, "hdf/control_id", controlID)
	exportmap.SetIf(pf, "hdf/exporter_version", ctx.exporterVersion)
	exportmap.SetIf(pf, "hdf/generator", ctx.generatorName)
	exportmap.SetIf(pf, "hdf/tool", ctx.toolName)
	return pf
}

// remediation surfaces the "fix"-labeled description and/or the first ref URL as
// an ASFF Remediation.Recommendation.
func remediation(req map[string]interface{}) map[string]interface{} {
	fix := ""
	descs, _ := exportmap.AsSlice(req["descriptions"])
	for _, dRaw := range descs {
		if d, ok := exportmap.AsMap(dRaw); ok && exportmap.GetStr(d, "label") == "fix" {
			fix = exportmap.GetStr(d, "data")
			break
		}
	}
	url := exportmap.FirstRefURL(req)
	if fix == "" && url == "" {
		return nil
	}
	rec := map[string]interface{}{}
	exportmap.SetIf(rec, "Text", truncate(fix, maxDescription))
	exportmap.SetIf(rec, "Url", url)
	return map[string]interface{}{"Recommendation": rec}
}

// canonicalTime passes an HDF timestamp through unchanged (HDF startTime is
// already canonical trimmed-UTC RFC3339, and ASFF CreatedAt/UpdatedAt accept it
// verbatim). Passthrough — rather than reformatting — keeps Go and TypeScript
// byte-identical without either side reproducing the other's RFC3339 trailing-
// zero rules. An unparseable/absent time falls back to the epoch sentinel so the
// required field stays schema-valid.
func canonicalTime(s string) string {
	if hdfutil.ParseTimestamp(s).IsZero() {
		return epochSentinel
	}
	return s
}

// truncate caps s at max Unicode code points (not bytes), matching the
// TypeScript side's [...s] slice so the two stay byte-identical on non-ASCII text
// and never split a multi-byte sequence.
func truncate(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit])
}
