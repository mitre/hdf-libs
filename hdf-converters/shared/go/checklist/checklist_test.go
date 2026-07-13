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

// An iSTIG with zero <VULN> rules is rejected — it would otherwise yield a
// baseline with requirements: [], violating the HDF schema's minItems=1.
func TestParseCKLRejectsEmptyIStig(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?><CHECKLIST><STIGS><iSTIG><STIG_INFO></STIG_INFO></iSTIG></STIGS></CHECKLIST>`
	_, err := ParseCKL([]byte(input))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no <VULN> rules")
}

// A CKLB stig with an empty rules[] is rejected for the same reason.
func TestParseCKLBRejectsEmptyRules(t *testing.T) {
	input := `{"cklb_version":"1.0","stigs":[{"stig_id":"x","rules":[]}]}`
	_, err := ParseCKLB([]byte(input))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules[]")
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
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKL)), "1.0.0", "test-converter")

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
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKL)), "1.0.0", "test-converter")
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
	// Text fields must survive the HDF round-trip (regression guard).
	assert.Equal(t, o.VulnDiscuss, n.VulnDiscuss)
	assert.Equal(t, o.CheckContent, n.CheckContent)
	assert.Equal(t, o.FixText, n.FixText)
	// finding_details and comments occupy separate CKL fields and must stay
	// separable through HDF: message carries only finding_details, comments
	// round-trips through tags.
	assert.Equal(t, o.FindingDetails, n.FindingDetails)
	assert.Equal(t, o.Comments, n.Comments)

	// And serialize back to valid CKL XML that re-parses.
	out, err := SerializeCKL(rt)
	require.NoError(t, err)
	reparsed, err := ParseCKL(out)
	require.NoError(t, err)
	rv := reparsed.Stigs[0].Vulns[0]
	assert.Equal(t, o.VulnNum, rv.VulnNum)
	assert.Equal(t, o.Status, rv.Status)
	assert.Equal(t, o.VulnDiscuss, rv.VulnDiscuss)
	assert.Equal(t, o.CheckContent, rv.CheckContent)
	assert.Equal(t, o.FixText, rv.FixText)
	assert.Equal(t, o.FindingDetails, rv.FindingDetails)
	assert.Equal(t, o.Comments, rv.Comments)
}

// Round-trip CKLB -> HDF -> model -> CKLB.
func TestRoundTripCKLB(t *testing.T) {
	cl, err := ParseCKLB([]byte(sampleCKLB))
	require.NoError(t, err)
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte(sampleCKLB)), "1.0.0", "test-converter")
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
	// Text fields must survive the HDF round-trip (regression guard).
	assert.Equal(t, "Discussion text.", v.VulnDiscuss)
	assert.Equal(t, "Check it.", v.CheckContent)
	assert.Equal(t, "Fix it.", v.FixText)
	// finding_details and comments stay in their own fields through HDF.
	assert.Equal(t, "Out of date.", v.FindingDetails)
	assert.Equal(t, "Reviewer note.", v.Comments)
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
	results := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0", "test-converter")
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
		r := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0", "test-converter")
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

// HOST_NAME lands in a dedicated hostname field, not just the overloaded Name.
// The short name must be recoverable independent of the Name display-fallback.
func TestComponentDedicatedHostname(t *testing.T) {
	mk := func(a Asset) *hdf.Component {
		cl := &Checklist{Asset: a, Stigs: []Stig{{Vulns: []Vuln{{VulnNum: "V-1", Status: StatusOpen}}}}}
		r := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0", "test-converter")
		return &r.Components[0]
	}
	// Both HOST_NAME and HOST_FQDN present: hostname holds the short name, fqdn the FQDN.
	c := mk(Asset{HostName: "web01", HostFQDN: "web01.prod.example.com", HostIP: "10.0.1.5"})
	require.NotNil(t, c.Hostname)
	assert.Equal(t, "web01", *c.Hostname)
	require.NotNil(t, c.FQDN)
	assert.Equal(t, "web01.prod.example.com", *c.FQDN)

	// No HOST_NAME: hostname is not fabricated from the FQDN fallback, even though
	// Name still falls back to the FQDN for a usable display identity.
	c = mk(Asset{HostFQDN: "web01.prod.example.com", HostIP: "10.0.1.5"})
	assert.Nil(t, c.Hostname)
	assert.Equal(t, "web01.prod.example.com", c.Name)
}

// A CKL with both HOST_NAME and HOST_FQDN preserves BOTH through HDF, and an
// absent HOST_NAME is not fabricated from the fqdn/ip Name-fallback on export.
func TestRoundTripPreservesHostnameAndFQDN(t *testing.T) {
	rt := func(a Asset) Asset {
		cl := &Checklist{Format: "ckl", Asset: a, Stigs: []Stig{{
			StigID: "S", Title: "T", Version: "1",
			Vulns: []Vuln{{VulnNum: "V-1", RuleID: "SV-1_rule", Severity: "low", Status: StatusOpen}},
		}}}
		results := ChecklistToHDF(cl, shared.InputChecksum([]byte("x")), "1.0.0", "test-converter")
		b, err := json.Marshal(results)
		require.NoError(t, err)
		out, err := HDFToChecklist(b)
		require.NoError(t, err)
		return out.Asset
	}

	// Both present and distinct -> both survive.
	got := rt(Asset{HostName: "web01", HostFQDN: "web01.prod.example.com", HostIP: "10.0.1.5"})
	assert.Equal(t, "web01", got.HostName)
	assert.Equal(t, "web01.prod.example.com", got.HostFQDN)

	// HOST_NAME absent -> not fabricated from the fqdn fallback.
	got = rt(Asset{HostFQDN: "web01.prod.example.com", HostIP: "10.0.1.5"})
	assert.Empty(t, got.HostName)
	assert.Equal(t, "web01.prod.example.com", got.HostFQDN)
}

// Backward-compat: HDF produced before the hostname field existed stored the
// short HOST_NAME in Component.Name (even alongside fqdn). Export must recover
// it from Name, yet still not promote a Name that merely mirrors fqdn/ip.
func TestFromHDFLegacyNameFallback(t *testing.T) {
	build := func(c hdf.Component) Asset {
		results := hdf.HDFResults{
			Components: []hdf.Component{c},
			Baselines: []hdf.EvaluatedBaseline{{
				Name:         "b",
				Requirements: []hdf.EvaluatedRequirement{{ID: "V-1", Results: []hdf.RequirementResult{{Status: hdf.Passed}}}},
			}},
		}
		b, err := json.Marshal(results)
		require.NoError(t, err)
		out, err := HDFToChecklist(b)
		require.NoError(t, err)
		return out.Asset
	}

	// Legacy HDF: real short name in Name, fqdn also present, no hostname field.
	got := build(hdf.Component{Type: hdf.Host, Name: "web01", FQDN: ptr("web01.prod.example.com")})
	assert.Equal(t, "web01", got.HostName, "legacy short name must survive")
	assert.Equal(t, "web01.prod.example.com", got.HostFQDN)

	// Legacy HDF where Name mirrors the fqdn fallback -> must not fabricate HOST_NAME.
	got = build(hdf.Component{Type: hdf.Host, Name: "web01.prod.example.com", FQDN: ptr("web01.prod.example.com")})
	assert.Empty(t, got.HostName)

	// Legacy HDF where Name mirrors the ip fallback -> must not fabricate HOST_NAME.
	got = build(hdf.Component{Type: hdf.Host, Name: "10.0.1.5", IPAddress: ptr("10.0.1.5")})
	assert.Empty(t, got.HostName)
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
