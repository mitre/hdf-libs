package checklist

import (
	"encoding/xml"
	"fmt"
)

// ---------------------------------------------------------------------------
// CKL XML structs (round-trip: used for both parse and serialize)
// ---------------------------------------------------------------------------

type cklXML struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   cklAsset `xml:"ASSET"`
	Stigs   cklStigs `xml:"STIGS"`
}

type cklAsset struct {
	Role          string `xml:"ROLE"`
	AssetType     string `xml:"ASSET_TYPE"`
	Marking       string `xml:"MARKING,omitempty"`
	HostName      string `xml:"HOST_NAME"`
	HostIP        string `xml:"HOST_IP"`
	HostMAC       string `xml:"HOST_MAC"`
	HostFQDN      string `xml:"HOST_FQDN"`
	TargetComment string `xml:"TARGET_COMMENT"`
	TechArea      string `xml:"TECH_AREA"`
	TargetKey     string `xml:"TARGET_KEY"`
	WebOrDatabase string `xml:"WEB_OR_DATABASE"`
	WebDBSite     string `xml:"WEB_DB_SITE"`
	WebDBInstance string `xml:"WEB_DB_INSTANCE"`
}

type cklStigs struct {
	IStigs []cklIStig `xml:"iSTIG"`
}

type cklIStig struct {
	StigInfo cklStigInfo `xml:"STIG_INFO"`
	Vulns    []cklVuln   `xml:"VULN"`
}

type cklStigInfo struct {
	SiData []cklSiData `xml:"SI_DATA"`
}

type cklSiData struct {
	Name string `xml:"SID_NAME"`
	Data string `xml:"SID_DATA"`
}

type cklVuln struct {
	StigData              []cklStigData `xml:"STIG_DATA"`
	Status                string        `xml:"STATUS"`
	FindingDetails        string        `xml:"FINDING_DETAILS"`
	Comments              string        `xml:"COMMENTS"`
	SeverityOverride      string        `xml:"SEVERITY_OVERRIDE"`
	SeverityJustification string        `xml:"SEVERITY_JUSTIFICATION"`
}

type cklStigData struct {
	Attribute string `xml:"VULN_ATTRIBUTE"`
	Data      string `xml:"ATTRIBUTE_DATA"`
}

// vulnAttrOrder is the canonical VULN_ATTRIBUTE emission order, matching real
// STIG Viewer output. CCI_REF is emitted last (and may repeat).
var vulnAttrOrder = []string{
	"Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title",
	"Vuln_Discuss", "IA_Controls", "Check_Content", "Fix_Text", "False_Positives",
	"False_Negatives", "Documentable", "Mitigations", "Potential_Impact",
	"Third_Party_Tools", "Mitigation_Control", "Responsibility",
	"Security_Override_Guidance", "Check_Content_Ref", "Weight", "Class", "STIG_UUID",
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

// ParseCKL parses CKL XML bytes into the format-neutral Checklist model.
func ParseCKL(input []byte) (*Checklist, error) {
	var doc cklXML
	if err := xml.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("parse ckl: %w", err)
	}
	if len(doc.Stigs.IStigs) == 0 {
		return nil, fmt.Errorf("parse ckl: no <iSTIG> blocks found (not a CKL document?)")
	}

	cl := &Checklist{Format: "ckl"}
	cl.Asset = Asset{
		Role:          doc.Asset.Role,
		AssetType:     doc.Asset.AssetType,
		Marking:       doc.Asset.Marking,
		HostName:      doc.Asset.HostName,
		HostIP:        doc.Asset.HostIP,
		HostMAC:       doc.Asset.HostMAC,
		HostFQDN:      doc.Asset.HostFQDN,
		TargetComment: doc.Asset.TargetComment,
		TechArea:      doc.Asset.TechArea,
		TargetKey:     doc.Asset.TargetKey,
		WebOrDatabase: doc.Asset.WebOrDatabase == "true",
		WebDBSite:     doc.Asset.WebDBSite,
		WebDBInstance: doc.Asset.WebDBInstance,
	}

	for i := range doc.Stigs.IStigs {
		is := &doc.Stigs.IStigs[i]
		// An iSTIG with no rules would yield requirements: [] downstream, which
		// violates the HDF schema's requirements.minItems=1. Reject as malformed,
		// consistent with the no-<iSTIG> guard above.
		if len(is.Vulns) == 0 {
			return nil, fmt.Errorf("parse ckl: <iSTIG> block %d contains no <VULN> rules", i+1)
		}
		stig := Stig{
			StigID:         siValue(is.StigInfo.SiData, "stigid"),
			Title:          siValue(is.StigInfo.SiData, "title"),
			Version:        siValue(is.StigInfo.SiData, "version"),
			ReleaseInfo:    siValue(is.StigInfo.SiData, "releaseinfo"),
			UUID:           siValue(is.StigInfo.SiData, "uuid"),
			Classification: siValue(is.StigInfo.SiData, "classification"),
		}
		for j := range is.Vulns {
			stig.Vulns = append(stig.Vulns, cklVulnToModel(&is.Vulns[j]))
		}
		cl.Stigs = append(cl.Stigs, stig)
	}
	return cl, nil
}

func siValue(data []cklSiData, name string) string {
	for _, d := range data {
		if d.Name == name {
			return d.Data
		}
	}
	return ""
}

func cklVulnToModel(v *cklVuln) Vuln {
	attr := func(name string) string {
		for _, sd := range v.StigData {
			if sd.Attribute == name {
				return sd.Data
			}
		}
		return ""
	}
	var ccis, legacyIDs []string
	extra := map[string]string{}
	for _, sd := range v.StigData {
		switch sd.Attribute {
		case "CCI_REF":
			if sd.Data != "" {
				ccis = append(ccis, sd.Data)
			}
		case "LEGACY_ID":
			if sd.Data != "" {
				legacyIDs = append(legacyIDs, sd.Data)
			}
		case "Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver",
			"Rule_Title", "Vuln_Discuss", "Check_Content", "Fix_Text", "Weight", "Class":
			// promoted to typed fields below
		default:
			if sd.Data != "" {
				extra[sd.Attribute] = sd.Data
			}
		}
	}
	return Vuln{
		VulnNum:               attr("Vuln_Num"),
		RuleID:                attr("Rule_ID"),
		RuleVer:               attr("Rule_Ver"),
		GroupTitle:            attr("Group_Title"),
		Severity:              attr("Severity"),
		RuleTitle:             attr("Rule_Title"),
		VulnDiscuss:           attr("Vuln_Discuss"),
		CheckContent:          attr("Check_Content"),
		FixText:               attr("Fix_Text"),
		Weight:                attr("Weight"),
		Classification:        attr("Class"),
		CCIs:                  ccis,
		LegacyIDs:             legacyIDs,
		Status:                ParseStatus(v.Status),
		FindingDetails:        v.FindingDetails,
		Comments:              v.Comments,
		SeverityOverride:      v.SeverityOverride,
		SeverityJustification: v.SeverityJustification,
		Extra:                 extra,
	}
}

// ---------------------------------------------------------------------------
// Serialize
// ---------------------------------------------------------------------------

// SerializeCKL renders the Checklist model as CKL XML bytes (with header).
func SerializeCKL(cl *Checklist) ([]byte, error) {
	doc := cklXML{
		Asset: cklAsset{
			Role:          orDefault(cl.Asset.Role, "None"),
			AssetType:     orDefault(cl.Asset.AssetType, "Computing"),
			Marking:       cl.Asset.Marking,
			HostName:      cl.Asset.HostName,
			HostIP:        cl.Asset.HostIP,
			HostMAC:       cl.Asset.HostMAC,
			HostFQDN:      cl.Asset.HostFQDN,
			TargetComment: cl.Asset.TargetComment,
			TechArea:      cl.Asset.TechArea,
			TargetKey:     cl.Asset.TargetKey,
			WebOrDatabase: boolStr(cl.Asset.WebOrDatabase),
			WebDBSite:     cl.Asset.WebDBSite,
			WebDBInstance: cl.Asset.WebDBInstance,
		},
	}
	for i := range cl.Stigs {
		stig := &cl.Stigs[i]
		is := cklIStig{StigInfo: cklStigInfo{SiData: stigInfoSiData(stig)}}
		for j := range stig.Vulns {
			is.Vulns = append(is.Vulns, modelVulnToCKL(&stig.Vulns[j]))
		}
		doc.Stigs.IStigs = append(doc.Stigs.IStigs, is)
	}

	out, err := xml.MarshalIndent(doc, "", "\t")
	if err != nil {
		return nil, fmt.Errorf("serialize ckl: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

func stigInfoSiData(s *Stig) []cklSiData {
	pairs := []cklSiData{
		{Name: "version", Data: s.Version},
		{Name: "classification", Data: s.Classification},
		{Name: "stigid", Data: s.StigID},
		{Name: "releaseinfo", Data: s.ReleaseInfo},
		{Name: "title", Data: s.Title},
		{Name: "uuid", Data: s.UUID},
	}
	out := pairs[:0]
	for _, p := range pairs {
		if p.Data != "" {
			out = append(out, p)
		}
	}
	return out
}

func modelVulnToCKL(v *Vuln) cklVuln {
	typed := map[string]string{
		"Vuln_Num": v.VulnNum, "Severity": v.Severity, "Group_Title": v.GroupTitle,
		"Rule_ID": v.RuleID, "Rule_Ver": v.RuleVer, "Rule_Title": v.RuleTitle,
		"Vuln_Discuss": v.VulnDiscuss, "Check_Content": v.CheckContent,
		"Fix_Text": v.FixText, "Weight": orDefault(v.Weight, "10.0"),
		"Class": orDefault(v.Classification, "Unclass"),
	}
	var stigData []cklStigData
	for _, name := range vulnAttrOrder {
		val := typed[name]
		if val == "" {
			val = v.Extra[name]
		}
		// Emit core identity/content fields even when empty (STIG Viewer does);
		// skip purely-optional extras when absent.
		if val == "" && !coreVulnAttr[name] {
			continue
		}
		stigData = append(stigData, cklStigData{Attribute: name, Data: val})
	}
	// LEGACY_ID entries (one per id) precede CCI_REF, matching STIG Viewer.
	for _, lid := range v.LegacyIDs {
		if lid != "" {
			stigData = append(stigData, cklStigData{Attribute: "LEGACY_ID", Data: lid})
		}
	}
	for _, cci := range v.CCIs {
		stigData = append(stigData, cklStigData{Attribute: "CCI_REF", Data: cci})
	}
	return cklVuln{
		StigData:              stigData,
		Status:                v.Status.CKLString(),
		FindingDetails:        v.FindingDetails,
		Comments:              v.Comments,
		SeverityOverride:      v.SeverityOverride,
		SeverityJustification: v.SeverityJustification,
	}
}

// coreVulnAttr marks attributes STIG Viewer always emits, even when empty.
var coreVulnAttr = map[string]bool{
	"Vuln_Num": true, "Severity": true, "Group_Title": true, "Rule_ID": true,
	"Rule_Ver": true, "Rule_Title": true, "Vuln_Discuss": true,
	"Check_Content": true, "Fix_Text": true, "Weight": true, "Class": true,
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
