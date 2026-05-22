package checklist

import (
	"encoding/json"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleCKL = `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <ROLE>None</ROLE>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <HOST_NAME>EXAMPLE-HOST</HOST_NAME>
    <HOST_IP>192.0.2.10</HOST_IP>
    <HOST_MAC>00:00:00:00:00:00</HOST_MAC>
    <HOST_FQDN>host.example.com</HOST_FQDN>
    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>MOZ_Firefox_STIG</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Mozilla Firefox STIG</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>1</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Release: 7</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>uuid</SID_NAME><SID_DATA>abc-123</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-251545</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SRG-APP-000456</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-251545r1_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>FFOX-00-000001</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Firefox must be supported.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Discussion text.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Check it.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Fix it.</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Weight</VULN_ATTRIBUTE><ATTRIBUTE_DATA>10.0</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-002605</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>Out of date.</FINDING_DETAILS>
        <COMMENTS>Reviewer note.</COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>`

const sampleCKLB = `{
  "title": "Mozilla Firefox STIG",
  "id": "doc-1",
  "cklb_version": "1.0",
  "active": false,
  "target_data": {
    "target_type": "Computing",
    "host_name": "EXAMPLE-HOST",
    "ip_address": "192.0.2.10",
    "mac_address": "00:00:00:00:00:00",
    "fqdn": "host.example.com",
    "role": "None"
  },
  "stigs": [
    {
      "stig_name": "Mozilla Firefox STIG",
      "display_name": "Firefox",
      "stig_id": "MOZ_Firefox_STIG",
      "release_info": "Release: 7",
      "version": "1",
      "uuid": "abc-123",
      "rules": [
        {
          "group_id": "V-251545",
          "group_title": "SRG-APP-000456",
          "rule_id": "SV-251545r1_rule",
          "rule_version": "FFOX-00-000001",
          "rule_title": "Firefox must be supported.",
          "severity": "high",
          "weight": "10.0",
          "check_content": "Check it.",
          "fix_text": "Fix it.",
          "discussion": "Discussion text.",
          "ccis": ["CCI-002605"],
          "status": "open",
          "comments": "Reviewer note.",
          "finding_details": "Out of date."
        }
      ]
    }
  ]
}`

func TestStatusTranslationsRoundTrip(t *testing.T) {
	for _, s := range []CheckStatus{StatusOpen, StatusNotAFinding, StatusNotReviewed, StatusNotApplicable} {
		assert.Equal(t, s, ParseStatus(s.CKLString()), "CKL round-trip %s", s)
		assert.Equal(t, s, ParseStatus(s.CKLBString()), "CKLB round-trip %s", s)
		assert.Equal(t, s, StatusFromHDF(s.ToHDF()), "HDF round-trip %s", s)
	}
	assert.Equal(t, StatusNotReviewed, ParseStatus("bogus"))
	assert.Equal(t, StatusNotReviewed, ParseStatus(""))
	// error -> Open
	assert.Equal(t, StatusOpen, StatusFromHDF(hdf.Error))
}

func TestParseCKL(t *testing.T) {
	cl, err := ParseCKL([]byte(sampleCKL))
	require.NoError(t, err)
	assert.Equal(t, "ckl", cl.Format)
	assert.Equal(t, "EXAMPLE-HOST", cl.Asset.HostName)
	require.Len(t, cl.Stigs, 1)
	assert.Equal(t, "MOZ_Firefox_STIG", cl.Stigs[0].StigID)
	require.Len(t, cl.Stigs[0].Vulns, 1)
	v := cl.Stigs[0].Vulns[0]
	assert.Equal(t, "V-251545", v.VulnNum)
	assert.Equal(t, "SV-251545r1_rule", v.RuleID)
	assert.Equal(t, "high", v.Severity)
	assert.Equal(t, []string{"CCI-002605"}, v.CCIs)
	assert.Equal(t, StatusOpen, v.Status)
	assert.Equal(t, "Out of date.", v.FindingDetails)
}

func TestParseCKLB(t *testing.T) {
	cl, err := ParseCKLB([]byte(sampleCKLB))
	require.NoError(t, err)
	assert.Equal(t, "cklb", cl.Format)
	assert.Equal(t, "1.0", cl.CKLBVersion)
	assert.Equal(t, "EXAMPLE-HOST", cl.Asset.HostName)
	require.Len(t, cl.Stigs, 1)
	require.Len(t, cl.Stigs[0].Vulns, 1)
	v := cl.Stigs[0].Vulns[0]
	assert.Equal(t, "V-251545", v.VulnNum)
	assert.Equal(t, []string{"CCI-002605"}, v.CCIs)
	assert.Equal(t, StatusOpen, v.Status)
}

// CKL and CKLB of the same checklist should produce equivalent models.
func TestCKLandCKLBEquivalentModel(t *testing.T) {
	ckl, err := ParseCKL([]byte(sampleCKL))
	require.NoError(t, err)
	cklb, err := ParseCKLB([]byte(sampleCKLB))
	require.NoError(t, err)

	assert.Equal(t, ckl.Asset.HostName, cklb.Asset.HostName)
	assert.Equal(t, ckl.Stigs[0].StigID, cklb.Stigs[0].StigID)
	cv, bv := ckl.Stigs[0].Vulns[0], cklb.Stigs[0].Vulns[0]
	assert.Equal(t, cv.VulnNum, bv.VulnNum)
	assert.Equal(t, cv.Severity, bv.Severity)
	assert.Equal(t, cv.CCIs, bv.CCIs)
	assert.Equal(t, cv.Status, bv.Status)
	assert.Equal(t, cv.RuleTitle, bv.RuleTitle)
}

func TestChecklistToHDF(t *testing.T) {
	cl, err := ParseCKL([]byte(sampleCKL))
	require.NoError(t, err)
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKL)), "1.0.0")

	require.Len(t, results.Baselines, 1)
	bl := results.Baselines[0]
	assert.Equal(t, "STIG Checklist Scan", bl.Name)
	require.NotNil(t, bl.Title)
	assert.Equal(t, "Mozilla Firefox STIG", *bl.Title)
	assert.Equal(t, "MOZ_Firefox_STIG", bl.Extensions["stigid"])

	require.Len(t, bl.Requirements, 1)
	r := bl.Requirements[0]
	assert.Equal(t, "V-251545", r.ID)
	assert.InDelta(t, 0.7, r.Impact, 0.001)
	assert.Equal(t, hdf.Failed, r.Results[0].Status)
	require.NotNil(t, r.ControlType)
	assert.Equal(t, hdf.Technical, *r.ControlType) // SI-2 -> technical
	assert.Nil(t, r.VerificationMethod)
	assert.Nil(t, r.Applicability)

	require.Len(t, results.Components, 1)
	assert.Equal(t, "EXAMPLE-HOST", results.Components[0].Name)
	assert.Equal(t, "ckl", results.Extensions["checklistFormat"])
}

// Full round-trip: CKL -> HDF -> model -> CKL preserves key fields.
func TestRoundTripCKL(t *testing.T) {
	cl, err := ParseCKL([]byte(sampleCKL))
	require.NoError(t, err)
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKL)), "1.0.0")
	hdfBytes, err := json.Marshal(results)
	require.NoError(t, err)

	rt, err := HDFToChecklist(hdfBytes)
	require.NoError(t, err)

	assert.Equal(t, cl.Asset.HostName, rt.Asset.HostName)
	assert.Equal(t, cl.Asset.HostIP, rt.Asset.HostIP)
	require.Len(t, rt.Stigs, 1)
	assert.Equal(t, cl.Stigs[0].StigID, rt.Stigs[0].StigID)
	assert.Equal(t, cl.Stigs[0].Version, rt.Stigs[0].Version)
	require.Len(t, rt.Stigs[0].Vulns, 1)
	o, n := cl.Stigs[0].Vulns[0], rt.Stigs[0].Vulns[0]
	assert.Equal(t, o.VulnNum, n.VulnNum)
	assert.Equal(t, o.RuleID, n.RuleID)
	assert.Equal(t, o.RuleVer, n.RuleVer)
	assert.Equal(t, o.Severity, n.Severity)
	assert.Equal(t, o.CCIs, n.CCIs)
	assert.Equal(t, o.Status, n.Status)
	assert.Equal(t, o.RuleTitle, n.RuleTitle)

	// And serialize back to valid CKL XML that re-parses.
	out, err := SerializeCKL(rt)
	require.NoError(t, err)
	reparsed, err := ParseCKL(out)
	require.NoError(t, err)
	assert.Equal(t, o.VulnNum, reparsed.Stigs[0].Vulns[0].VulnNum)
	assert.Equal(t, o.Status, reparsed.Stigs[0].Vulns[0].Status)
}

// Round-trip CKLB -> HDF -> model -> CKLB.
func TestRoundTripCKLB(t *testing.T) {
	cl, err := ParseCKLB([]byte(sampleCKLB))
	require.NoError(t, err)
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKLB)), "1.0.0")
	hdfBytes, err := json.Marshal(results)
	require.NoError(t, err)

	rt, err := HDFToChecklist(hdfBytes)
	require.NoError(t, err)
	assert.Equal(t, "cklb", rt.Format)

	out, err := SerializeCKLB(rt)
	require.NoError(t, err)
	reparsed, err := ParseCKLB(out)
	require.NoError(t, err)
	v := reparsed.Stigs[0].Vulns[0]
	assert.Equal(t, "V-251545", v.VulnNum)
	assert.Equal(t, []string{"CCI-002605"}, v.CCIs)
	assert.Equal(t, StatusOpen, v.Status)
	// snake_case status in serialized output
	assert.Contains(t, string(out), `"status": "open"`)
	assert.Contains(t, string(out), `"ccis"`)
}

// Arbitrary HDF with no checklist passthrough still yields a valid checklist,
// reversing nist->cci and synthesizing defaults.
func TestHDFToChecklistSynthesis(t *testing.T) {
	impact := 0.5
	results := hdf.HDFResults{
		Baselines: []hdf.EvaluatedBaseline{{
			Name:  "Some Scan",
			Title: ptr("Some Tool Scan"),
			Requirements: []hdf.EvaluatedRequirement{{
				ID:      "GEN-001",
				Title:   ptr("A finding"),
				Impact:  impact,
				Tags:    map[string]interface{}{"nist": []string{"SI-2 c"}},
				Results: []hdf.RequirementResult{{Status: hdf.Failed}},
			}},
		}},
	}
	b, err := json.Marshal(results)
	require.NoError(t, err)

	cl, err := HDFToChecklist(b)
	require.NoError(t, err)
	require.Len(t, cl.Stigs, 1)
	v := cl.Stigs[0].Vulns[0]
	assert.Equal(t, "GEN-001", v.VulnNum)
	assert.Equal(t, "medium", v.Severity) // impact 0.5
	assert.Equal(t, StatusOpen, v.Status)
	// nist reversed to cci
	assert.NotEmpty(t, v.CCIs)

	// serializes to a valid CKL even from arbitrary HDF
	out, err := SerializeCKL(cl)
	require.NoError(t, err)
	_, err = ParseCKL(out)
	require.NoError(t, err)
}

func TestParseErrors(t *testing.T) {
	_, err := ParseCKL([]byte("not xml"))
	assert.Error(t, err)
	_, err = ParseCKL([]byte(`<?xml version="1.0"?><CHECKLIST></CHECKLIST>`))
	assert.Error(t, err, "no iSTIG should error")
	_, err = ParseCKLB([]byte("not json"))
	assert.Error(t, err)
	_, err = ParseCKLB([]byte(`{"stigs":[]}`))
	assert.Error(t, err, "empty stigs should error")
	_, err = HDFToChecklist([]byte("not json"))
	assert.Error(t, err)
	_, err = HDFToChecklist([]byte(`{"baselines":[]}`))
	assert.Error(t, err, "no baselines should error")
}

// Extra fields, legacy IDs, web/db flag, and asset extras survive a full
// CKL -> HDF -> model round-trip.
func TestRoundTripPreservesExtrasAndAssetFlags(t *testing.T) {
	cl := &Checklist{
		Format: "ckl",
		Asset: Asset{
			HostName: "H", Role: "Member Server", AssetType: "Computing",
			Marking: "CUI", TargetKey: "2350", WebOrDatabase: true, WebDBSite: "site",
		},
		Stigs: []Stig{{
			StigID: "S", Title: "T", Version: "2", UUID: "u-1", ReleaseInfo: "R: 3",
			Vulns: []Vuln{{
				VulnNum: "V-1", RuleID: "SV-1_rule", RuleVer: "X-1", Severity: "low",
				RuleTitle: "t", CCIs: []string{"CCI-000366"}, LegacyIDs: []string{"V-9999"},
				Status: StatusNotAFinding,
				Extra:  map[string]string{"Third_Party_Tools": "blob", "Responsibility": "admin"},
			}},
		}},
	}
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0")
	b, err := json.Marshal(results)
	require.NoError(t, err)
	rt, err := HDFToChecklist(b)
	require.NoError(t, err)

	assert.True(t, rt.Asset.WebOrDatabase)
	assert.Equal(t, "CUI", rt.Asset.Marking)
	assert.Equal(t, "Member Server", rt.Asset.Role)
	v := rt.Stigs[0].Vulns[0]
	assert.Equal(t, []string{"V-9999"}, v.LegacyIDs)
	assert.Equal(t, "blob", v.Extra["Third_Party_Tools"])
	assert.Equal(t, "admin", v.Extra["Responsibility"])
	assert.Equal(t, StatusNotAFinding, v.Status)
}

func TestComponentNameFallback(t *testing.T) {
	mk := func(a Asset) *hdf.Component {
		cl := &Checklist{Asset: a, Stigs: []Stig{{Vulns: []Vuln{{VulnNum: "V-1", Status: StatusOpen}}}}}
		r := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0")
		if len(r.Components) == 0 {
			return nil
		}
		return &r.Components[0]
	}
	// hostname wins
	assert.Equal(t, "H", mk(Asset{HostName: "H", HostIP: "192.0.2.1"}).Name)
	// FQDN fallback when no hostname
	assert.Equal(t, "h.example.com", mk(Asset{HostFQDN: "h.example.com", HostIP: "192.0.2.1"}).Name)
	// IP fallback when neither hostname nor FQDN
	assert.Equal(t, "192.0.2.1", mk(Asset{HostIP: "192.0.2.1"}).Name)
	// no host identity -> no component
	assert.Nil(t, mk(Asset{}))
}

func TestResolveSeverityFromImpact(t *testing.T) {
	mk := func(impact float64) *hdf.EvaluatedRequirement {
		return &hdf.EvaluatedRequirement{Impact: impact, Tags: map[string]interface{}{}}
	}
	assert.Equal(t, "high", resolveSeverity(mk(0.7), map[string]interface{}{}))
	assert.Equal(t, "medium", resolveSeverity(mk(0.5), map[string]interface{}{}))
	assert.Equal(t, "low", resolveSeverity(mk(0.3), map[string]interface{}{}))
	assert.Equal(t, "", resolveSeverity(mk(0.0), map[string]interface{}{}))
	// explicit tag wins
	assert.Equal(t, "high", resolveSeverity(mk(0.0), map[string]interface{}{"severity": "high"}))
}

func TestSerializeCKLBTitleFallback(t *testing.T) {
	out, err := SerializeCKLB(&Checklist{Stigs: []Stig{{Vulns: []Vuln{{VulnNum: "V-1", Status: StatusOpen}}}}})
	require.NoError(t, err)
	assert.Contains(t, string(out), `"title": "STIG Checklist"`)
	assert.Contains(t, string(out), `"cklb_version": "1.0"`)
}

func ptr(s string) *string { return &s }
