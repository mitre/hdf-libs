package checklist

import (
	"encoding/json"
	"fmt"
)

// ---------------------------------------------------------------------------
// CKLB JSON structs (STIG Viewer 3.x). Round-trip: parse + serialize.
// ---------------------------------------------------------------------------

type cklbDoc struct {
	Title       string     `json:"title"`
	ID          string     `json:"id,omitempty"`
	CklbVersion string     `json:"cklb_version"`
	Active      bool       `json:"active"`
	Mode        int        `json:"mode,omitempty"`
	HasPath     bool       `json:"has_path"`
	TargetData  cklbTarget `json:"target_data"`
	Stigs       []cklbStig `json:"stigs"`
}

type cklbTarget struct {
	TargetType     string `json:"target_type"`
	HostName       string `json:"host_name"`
	IPAddress      string `json:"ip_address"`
	MACAddress     string `json:"mac_address"`
	FQDN           string `json:"fqdn"`
	Comments       string `json:"comments"`
	Role           string `json:"role"`
	IsWebDatabase  bool   `json:"is_web_database"`
	TechnologyArea string `json:"technology_area"`
	WebDBSite      string `json:"web_db_site"`
	WebDBInstance  string `json:"web_db_instance"`
	Classification string `json:"classification,omitempty"`
}

type cklbStig struct {
	StigName            string     `json:"stig_name"`
	DisplayName         string     `json:"display_name"`
	StigID              string     `json:"stig_id"`
	ReleaseInfo         string     `json:"release_info"`
	Version             string     `json:"version"`
	UUID                string     `json:"uuid"`
	ReferenceIdentifier string     `json:"reference_identifier,omitempty"`
	Size                int        `json:"size,omitempty"`
	Rules               []cklbRule `json:"rules"`
}

type cklbRule struct {
	GroupID         string   `json:"group_id"`
	GroupTitle      string   `json:"group_title"`
	RuleID          string   `json:"rule_id"`
	RuleVersion     string   `json:"rule_version"`
	RuleTitle       string   `json:"rule_title"`
	Severity        string   `json:"severity"`
	Weight          string   `json:"weight"`
	CheckContent    string   `json:"check_content"`
	FixText         string   `json:"fix_text"`
	Discussion      string   `json:"discussion"`
	Classification  string   `json:"classification,omitempty"`
	CCIs            []string `json:"ccis"`
	LegacyIDs       []string `json:"legacy_ids,omitempty"`
	UUID            string   `json:"uuid,omitempty"`
	StigUUID        string   `json:"stig_uuid,omitempty"`
	SrgID           string   `json:"srg_id,omitempty"`
	Status          string   `json:"status"`
	Comments        string   `json:"comments"`
	FindingDetails  string   `json:"finding_details"`
	ThirdPartyTools string   `json:"third_party_tools,omitempty"`
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

// ParseCKLB parses CKLB JSON bytes into the format-neutral Checklist model.
func ParseCKLB(input []byte) (*Checklist, error) {
	var doc cklbDoc
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("parse cklb: %w", err)
	}
	if len(doc.Stigs) == 0 {
		return nil, fmt.Errorf("parse cklb: no stigs[] found (not a CKLB document?)")
	}

	cl := &Checklist{
		Format:      "cklb",
		CKLBVersion: doc.CklbVersion,
		Active:      doc.Active,
		HasPath:     doc.HasPath,
		Mode:        doc.Mode,
	}
	cl.Asset = Asset{
		Role:           doc.TargetData.Role,
		AssetType:      doc.TargetData.TargetType,
		HostName:       doc.TargetData.HostName,
		HostIP:         doc.TargetData.IPAddress,
		HostMAC:        doc.TargetData.MACAddress,
		HostFQDN:       doc.TargetData.FQDN,
		TargetComment:  doc.TargetData.Comments,
		WebOrDatabase:  doc.TargetData.IsWebDatabase,
		WebDBSite:      doc.TargetData.WebDBSite,
		WebDBInstance:  doc.TargetData.WebDBInstance,
		TechArea:       doc.TargetData.TechnologyArea,
		Classification: doc.TargetData.Classification,
	}

	for i := range doc.Stigs {
		s := &doc.Stigs[i]
		// A stig with no rules would yield requirements: [] downstream, which
		// violates the HDF schema's requirements.minItems=1. Reject as malformed,
		// consistent with the empty-stigs[] guard above.
		if len(s.Rules) == 0 {
			return nil, fmt.Errorf("parse cklb: stigs[%d] contains no rules[]", i)
		}
		stig := Stig{
			StigID:              s.StigID,
			Title:               orDefault(s.StigName, s.DisplayName),
			DisplayName:         s.DisplayName,
			Version:             s.Version,
			ReleaseInfo:         s.ReleaseInfo,
			UUID:                s.UUID,
			ReferenceIdentifier: s.ReferenceIdentifier,
		}
		for j := range s.Rules {
			r := &s.Rules[j]
			extra := map[string]string{}
			if r.ThirdPartyTools != "" {
				extra["Third_Party_Tools"] = r.ThirdPartyTools
			}
			if r.SrgID != "" {
				extra["SRG_ID"] = r.SrgID
			}
			stig.Vulns = append(stig.Vulns, Vuln{
				VulnNum:        r.GroupID,
				RuleID:         r.RuleID,
				RuleVer:        r.RuleVersion,
				GroupID:        r.GroupID,
				GroupTitle:     r.GroupTitle,
				Severity:       r.Severity,
				RuleTitle:      r.RuleTitle,
				VulnDiscuss:    r.Discussion,
				CheckContent:   r.CheckContent,
				FixText:        r.FixText,
				Weight:         r.Weight,
				Classification: r.Classification,
				CCIs:           r.CCIs,
				LegacyIDs:      r.LegacyIDs,
				Status:         ParseStatus(r.Status),
				FindingDetails: r.FindingDetails,
				Comments:       r.Comments,
				Extra:          extra,
			})
		}
		cl.Stigs = append(cl.Stigs, stig)
	}
	return cl, nil
}

// ---------------------------------------------------------------------------
// Serialize
// ---------------------------------------------------------------------------

// orEmpty returns a non-nil slice so a required JSON array never marshals to null.
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// SerializeCKLB renders the Checklist model as CKLB JSON bytes.
func SerializeCKLB(cl *Checklist) ([]byte, error) {
	doc := cklbDoc{
		Title:       cklbTitle(cl),
		CklbVersion: orDefault(cl.CKLBVersion, "1.0"),
		Active:      cl.Active,
		HasPath:     cl.HasPath,
		Mode:        cl.Mode,
		TargetData: cklbTarget{
			TargetType:     orDefault(cl.Asset.AssetType, "Computing"),
			HostName:       cl.Asset.HostName,
			IPAddress:      cl.Asset.HostIP,
			MACAddress:     cl.Asset.HostMAC,
			FQDN:           cl.Asset.HostFQDN,
			Comments:       cl.Asset.TargetComment,
			Role:           orDefault(cl.Asset.Role, "None"),
			IsWebDatabase:  cl.Asset.WebOrDatabase,
			TechnologyArea: cl.Asset.TechArea,
			WebDBSite:      cl.Asset.WebDBSite,
			WebDBInstance:  cl.Asset.WebDBInstance,
			Classification: cl.Asset.Classification,
		},
	}

	for i := range cl.Stigs {
		stig := &cl.Stigs[i]
		cs := cklbStig{
			StigName:            stig.Title,
			DisplayName:         orDefault(stig.DisplayName, stig.Title),
			StigID:              stig.StigID,
			ReleaseInfo:         stig.ReleaseInfo,
			Version:             stig.Version,
			UUID:                stig.UUID,
			ReferenceIdentifier: stig.ReferenceIdentifier,
		}
		for j := range stig.Vulns {
			v := &stig.Vulns[j]
			cs.Rules = append(cs.Rules, cklbRule{
				GroupID:        orDefault(v.GroupID, v.VulnNum),
				GroupTitle:     v.GroupTitle,
				RuleID:         v.RuleID,
				RuleVersion:    v.RuleVer,
				RuleTitle:      v.RuleTitle,
				Severity:       v.Severity,
				Weight:         orDefault(v.Weight, "10.0"),
				CheckContent:   v.CheckContent,
				FixText:        v.FixText,
				Discussion:     v.VulnDiscuss,
				Classification: v.Classification,
				// ccis is a required CKLB array: a nil slice would marshal to null,
				// which STIG Viewer (and the TS serializer) do not emit.
				CCIs:            orEmpty(v.CCIs),
				LegacyIDs:       v.LegacyIDs,
				Status:          v.Status.CKLBString(),
				Comments:        v.Comments,
				FindingDetails:  v.FindingDetails,
				ThirdPartyTools: v.Extra["Third_Party_Tools"],
				SrgID:           v.Extra["SRG_ID"],
			})
		}
		doc.Stigs = append(doc.Stigs, cs)
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serialize cklb: %w", err)
	}
	return out, nil
}

func cklbTitle(cl *Checklist) string {
	if len(cl.Stigs) > 0 && cl.Stigs[0].Title != "" {
		return cl.Stigs[0].Title
	}
	return "STIG Checklist"
}
