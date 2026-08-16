// Package hdftooscalpoam converts HDF Amendments to OSCAL Plan of Action and
// Milestones (POA&M) format. This is the reverse direction of the oscal-poam
// to HDF converter.
package hdftooscalpoam

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// ConvertHDFToOSCALPOAM converts HDF Amendments JSON to OSCAL POA&M JSON.
// This is a RawConvertFn — it takes raw bytes and returns raw bytes.
func ConvertHDFToOSCALPOAM(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-oscal-poam", 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-oscal-poam: empty input")
	}

	var amendments hdf.HDFAmendments
	if err := shared.DecodeHDF(input, &amendments); err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-poam: failed to parse JSON: %w", err)
	}

	poam, err := amendmentsToPOAM(&amendments, converterVersion)
	if err != nil {
		return nil, err
	}

	// Wrap in OscalDocument envelope
	doc := oscal.OscalDocument{
		PlanOfActionAndMilestones: poam,
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-poam: failed to serialize OSCAL output: %w", err)
	}

	return output, nil
}

// partyRegistry deduplicates HDF identities into OSCAL metadata parties. A party
// keeps its UUID across reuse so origin actors and responsible parties reference
// the same entry. Insertion order is preserved for deterministic output.
type partyRegistry struct {
	order []string
	byID  map[string]oscal.Party
}

func newPartyRegistry() *partyRegistry {
	return &partyRegistry{byID: make(map[string]oscal.Party)}
}

// getOrAdd returns the party UUID for an identity, minting a new party the first
// time an identifier is seen.
func (r *partyRegistry) getOrAdd(id hdf.Identity) string {
	if p, ok := r.byID[id.Identifier]; ok {
		return p.UUID
	}
	party := oscal.Party{UUID: oscal.GenerateUUID(), Type: "person", Name: id.Identifier}
	r.byID[id.Identifier] = party
	r.order = append(r.order, id.Identifier)
	return party.UUID
}

func (r *partyRegistry) list() []oscal.Party {
	out := make([]oscal.Party, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}

// amendmentsToPOAM converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
func amendmentsToPOAM(amendments *hdf.HDFAmendments, _ string) (*oscal.PlanOfActionAndMilestones, error) {
	parties := newPartyRegistry()

	var roles []oscal.Role
	var responsibleParties []oscal.ResponsibleParty

	// The document preparer and the authorizing official become responsible
	// parties with distinct roles — a direct mirror of one another.
	if amendments.AppliedBy != nil {
		uuid := parties.getOrAdd(*amendments.AppliedBy)
		roles = append(roles, oscal.Role{ID: "prepared-by", Title: "Prepared By"})
		responsibleParties = append(responsibleParties, oscal.ResponsibleParty{RoleID: "prepared-by", PartyIDs: []string{uuid}})
	}
	if amendments.ApprovedBy != nil {
		uuid := parties.getOrAdd(*amendments.ApprovedBy)
		roles = append(roles, oscal.Role{ID: "approved-by", Title: "Approved By"})
		responsibleParties = append(responsibleParties, oscal.ResponsibleParty{RoleID: "approved-by", PartyIDs: []string{uuid}})
	}

	// Register each override's own applier so per-override attribution survives
	// as a distinct metadata party even when it differs from the document default.
	for i := range amendments.Overrides {
		parties.getOrAdd(amendments.Overrides[i].AppliedBy)
	}

	// Build import-ssp
	var importSSP *oscal.ImportSSP
	if amendments.SystemRef != nil && *amendments.SystemRef != "" {
		importSSP = &oscal.ImportSSP{Href: *amendments.SystemRef}
	} else {
		importSSP = &oscal.ImportSSP{Href: "#"}
	}

	// Convert overrides to poam-items, risks and evidence observations.
	var poamItems []oscal.POAMItem
	var risks []oscal.Risk
	var observations []oscal.Observation

	for i := range amendments.Overrides {
		override := &amendments.Overrides[i]
		item, itemRisks, itemObs := overrideToPOAMItem(override, parties)
		poamItems = append(poamItems, item)
		risks = append(risks, itemRisks...)
		observations = append(observations, itemObs...)
	}

	meta := oscal.Metadata{
		Title:              amendments.Name,
		LastModified:       latestAppliedAt(amendments.Overrides),
		Version:            amendmentsVersion(amendments),
		OscalVersion:       oscal.OscalVersion,
		Remarks:            derefString(amendments.Description),
		Roles:              roles,
		Parties:            parties.list(),
		ResponsibleParties: responsibleParties,
		Props:              metadataProps(amendments),
	}

	var backMatter *oscal.BackMatter
	if resources := externalRefResources(amendments.Overrides); len(resources) > 0 {
		backMatter = &oscal.BackMatter{Resources: resources}
	}

	poam := &oscal.PlanOfActionAndMilestones{
		UUID:         oscal.GenerateUUID(),
		Metadata:     meta,
		ImportSSP:    importSSP,
		Observations: observations,
		Risks:        risks,
		POAMItems:    poamItems,
		BackMatter:   backMatter,
	}

	return poam, nil
}

// overrideToPOAMItem converts a single StandaloneOverride to a POAMItem, its
// associated Risk, and any evidence observations.
func overrideToPOAMItem(override *hdf.StandaloneOverride, parties *partyRegistry) (oscal.POAMItem, []oscal.Risk, []oscal.Observation) {
	riskUUID := oscal.GenerateUUID()

	// Map HDF status to OSCAL risk status.
	// Overrides without a status field (impact-only) are treated as open risks.
	riskStatus := "open"
	if override.Status != nil {
		riskStatus = oscal.HDFStatusToOSCALRiskStatus(*override.Status)
	}

	// Convert requirement ID from NIST notation to OSCAL control ID
	controlID := oscal.NistTagToControlID(override.RequirementID)

	// Build risk props: impacted control, override type (disposition), impact
	// override, controlled-vocabulary justification, and disambiguating scope.
	riskProps := []oscal.Property{
		{
			Name:  "impacted-control-id",
			Value: controlID,
		},
	}
	if override.Type != "" {
		riskProps = append(riskProps, oscal.Property{Name: "override-type", Value: string(override.Type)})
	}
	if override.Impact != nil {
		riskProps = append(riskProps, oscal.Property{Name: "impact-override", Value: strconv.FormatFloat(override.Impact.Value, 'f', -1, 64)})
	}
	if override.Justification != nil && *override.Justification != "" {
		riskProps = append(riskProps, oscal.Property{Name: "justification", Value: string(*override.Justification)})
	}
	if override.BaselineRef != nil && *override.BaselineRef != "" {
		riskProps = append(riskProps, oscal.Property{Name: "baseline-ref", Value: *override.BaselineRef})
	}
	if override.ComponentRef != nil && *override.ComponentRef != "" {
		riskProps = append(riskProps, oscal.Property{Name: "component-ref", Value: *override.ComponentRef})
	}

	// Build remediations from milestones. Each milestone becomes a planned
	// remediation task whose within-date-range end carries the estimated
	// completion — the structure the forward converter reads back.
	var remediations []oscal.Remediation
	for _, ms := range override.Milestones {
		var msProps []oscal.Property
		if ms.Status != "" {
			msProps = append(msProps, oscal.Property{Name: "milestone-status", Value: string(ms.Status)})
		}
		var tasks []oscal.Task
		if !ms.EstimatedCompletion.IsZero() {
			eta := ms.EstimatedCompletion.UTC().Format(time.RFC3339)
			task := oscal.Task{
				UUID:  oscal.GenerateUUID(),
				Type:  "milestone",
				Title: ms.Description,
				Timing: &oscal.Timing{
					WithinDateRange: &oscal.DateRange{Start: eta, End: eta},
				},
				Props: milestoneCompletionProps(&ms),
			}
			tasks = []oscal.Task{task}
		}
		rem := oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "planned",
			Title:       ms.Description,
			Description: ms.Description,
			Props:       msProps,
			Tasks:       tasks,
		}
		remediations = append(remediations, rem)
	}

	// Structured CVSS scoring rides on a risk characterization: its facets carry
	// the scores/vectors, and its origin actor attributes the scoring to the
	// override's applier.
	var characterizations []oscal.Characterization
	if override.Cvss != nil {
		actorUUID := parties.getOrAdd(override.AppliedBy)
		characterizations = append(characterizations, oscal.Characterization{
			Origin: &oscal.Origin{Actors: []oscal.Actor{{Type: "party", ActorID: actorUUID}}},
			Facets: cvssFacets(override.Cvss),
		})
	}

	// Build risk log entry for expiration tracking
	var riskLog *oscal.RiskLog
	if !override.ExpiresAt.IsZero() {
		riskLog = &oscal.RiskLog{
			Entries: []oscal.RiskLogEntry{
				{
					UUID:         oscal.GenerateUUID(),
					Title:        "Scheduled review",
					Description:  "Amendment expiration date",
					Start:        override.ExpiresAt.UTC().Format(time.RFC3339),
					StatusChange: riskStatus,
				},
			},
		}
	}

	// The override's enforceable expiry maps to the risk deadline — the field
	// the forward converter reads to reconstruct expiresAt.
	var deadline string
	if !override.ExpiresAt.IsZero() {
		deadline = override.ExpiresAt.UTC().Format(time.RFC3339)
	}

	// Supporting evidence becomes observations, linked back from the poam-item.
	var observations []oscal.Observation
	var relatedObs []oscal.RelatedRef
	collected := observationCollected(override)
	for _, ev := range override.Evidence {
		obsUUID := oscal.GenerateUUID()
		observations = append(observations, evidenceObservation(ev, obsUUID, collected))
		relatedObs = append(relatedObs, oscal.RelatedRef{ObservationUUID: obsUUID})
	}

	risk := oscal.Risk{
		UUID:  riskUUID,
		Title: override.RequirementID,
		// OSCAL requires both description and statement on a risk.
		Description:       override.Reason,
		Statement:         override.Reason,
		Status:            riskStatus,
		Deadline:          deadline,
		Props:             riskProps,
		Characterizations: characterizations,
		Remediations:      remediations,
		RiskLog:           riskLog,
	}

	item := oscal.POAMItem{
		UUID:        oscal.GenerateUUID(),
		Title:       override.RequirementID,
		Description: override.Reason,
		RelatedRisks: []oscal.RelatedRef{
			{RiskUUID: riskUUID},
		},
		RelatedObservations: relatedObs,
	}

	return item, []oscal.Risk{risk}, observations
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// latestAppliedAt returns the most recent override appliedAt formatted for
// metadata.last-modified. Sourcing it from the input keeps output deterministic
// and lets the reverse importer recover appliedAt. Falls back to the wall clock
// only when no override carries a date (appliedAt is schema-required, so real
// documents always supply one).
func latestAppliedAt(overrides []hdf.StandaloneOverride) string {
	var latest time.Time
	for i := range overrides {
		if a := overrides[i].AppliedAt; !a.IsZero() && a.After(latest) {
			latest = a
		}
	}
	if latest.IsZero() {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return latest.UTC().Format(time.RFC3339)
}

// amendmentsVersion sources metadata.version from the amendments document,
// defaulting only when the source omits it.
func amendmentsVersion(a *hdf.HDFAmendments) string {
	if a.Version != nil && *a.Version != "" {
		return *a.Version
	}
	return "1.0.0"
}

// metadataProps carries document identifiers and labels that have no first-class
// OSCAL home. Labels are emitted in sorted key order for deterministic output.
func metadataProps(a *hdf.HDFAmendments) []oscal.Property {
	var props []oscal.Property
	if a.AmendmentID != nil && *a.AmendmentID != "" {
		props = append(props, oscal.Property{Name: "amendment-id", Value: *a.AmendmentID})
	}
	if len(a.Labels) > 0 {
		keys := make([]string, 0, len(a.Labels))
		for k := range a.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			props = append(props, oscal.Property{Name: k, Value: a.Labels[k], Class: "amendment-label"})
		}
	}
	return props
}

// observationCollected picks the collection timestamp for evidence observations,
// preferring the override's appliedAt (schema-required).
func observationCollected(override *hdf.StandaloneOverride) string {
	if !override.AppliedAt.IsZero() {
		return override.AppliedAt.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// evidenceObservation renders a single HDF Evidence item as an OSCAL observation.
func evidenceObservation(ev hdf.Evidence, uuid, defaultCollected string) oscal.Observation {
	collected := defaultCollected
	if ev.CapturedAt != nil && !ev.CapturedAt.IsZero() {
		collected = ev.CapturedAt.UTC().Format(time.RFC3339)
	}

	desc := "supporting evidence"
	if ev.Description != nil && *ev.Description != "" {
		desc = *ev.Description
	}

	re := oscal.RelevantEvidence{Description: desc}
	if ev.Type == hdf.URL {
		re.Href = ev.Data
	} else if ev.Data != "" {
		re.Remarks = ev.Data
	}

	var props []oscal.Property
	if ev.MIMEType != nil && *ev.MIMEType != "" {
		props = append(props, oscal.Property{Name: "mime-type", Value: *ev.MIMEType})
	}
	if ev.CapturedBy != nil && ev.CapturedBy.Identifier != "" {
		props = append(props, oscal.Property{Name: "captured-by", Value: ev.CapturedBy.Identifier})
	}

	return oscal.Observation{
		UUID:             uuid,
		Description:      desc,
		Methods:          []string{"EXAMINE"},
		Types:            []string{string(ev.Type)},
		Collected:        collected,
		Props:            props,
		RelevantEvidence: []oscal.RelevantEvidence{re},
	}
}

// cvssFacets decomposes an HDF Cvss record into OSCAL risk facets. A version
// facet is always present so the characterization carries at least one facet.
func cvssFacets(c *hdf.Cvss) []oscal.Facet {
	system := "http://www.first.org/cvss/v" + string(c.Version)
	facets := []oscal.Facet{{Name: "cvss_version", System: system, Value: string(c.Version)}}
	add := func(name, value string) {
		if value != "" {
			facets = append(facets, oscal.Facet{Name: name, System: system, Value: value})
		}
	}
	if c.BaseScore != nil {
		add("base_score", strconv.FormatFloat(*c.BaseScore, 'f', -1, 64))
	}
	if c.BaseSeverity != nil {
		add("base_severity", string(*c.BaseSeverity))
	}
	if c.BaseVector != nil {
		add("base_vector", *c.BaseVector)
	}
	if c.ThreatScore != nil {
		add("threat_score", strconv.FormatFloat(*c.ThreatScore, 'f', -1, 64))
	}
	if c.ThreatVector != nil {
		add("threat_vector", *c.ThreatVector)
	}
	if c.EnvironmentalScore != nil {
		add("environmental_score", strconv.FormatFloat(*c.EnvironmentalScore, 'f', -1, 64))
	}
	if c.EnvironmentalVector != nil {
		add("environmental_vector", *c.EnvironmentalVector)
	}
	if c.ComputedScore != nil {
		add("computed_score", strconv.FormatFloat(*c.ComputedScore, 'f', -1, 64))
	}
	if c.ComputedSeverity != nil {
		add("computed_severity", string(*c.ComputedSeverity))
	}
	if c.SupplementalVector != nil {
		add("supplemental_vector", *c.SupplementalVector)
	}
	if c.Source != nil {
		add("source", *c.Source)
	}
	return facets
}

// externalRefResources collects every override's external references into
// back-matter resources — the OSCAL home for advisories, STIX, and CTI feeds.
func externalRefResources(overrides []hdf.StandaloneOverride) []oscal.Resource {
	var resources []oscal.Resource
	for i := range overrides {
		for _, ref := range overrides[i].ExternalReferences {
			res := oscal.Resource{
				UUID:  oscal.GenerateUUID(),
				Title: ref.SourceName,
			}
			if ref.Description != nil && *ref.Description != "" {
				res.Description = *ref.Description
			}
			if ref.Href != nil && *ref.Href != "" {
				res.Rlinks = []oscal.Rlink{{Href: *ref.Href}}
			}
			var props []oscal.Property
			if ref.SourceName != "" {
				props = append(props, oscal.Property{Name: "source-name", Value: ref.SourceName})
			}
			if ref.ExternalID != nil && *ref.ExternalID != "" {
				props = append(props, oscal.Property{Name: "external-id", Value: *ref.ExternalID})
			}
			res.Props = props
			resources = append(resources, res)
		}
	}
	return resources
}

// milestoneCompletionProps carries the actual completion attribution that the
// estimated-completion timing cannot express.
func milestoneCompletionProps(ms *hdf.Milestone) []oscal.Property {
	var props []oscal.Property
	if ms.CompletedAt != nil && !ms.CompletedAt.IsZero() {
		props = append(props, oscal.Property{Name: "completed-at", Value: ms.CompletedAt.UTC().Format(time.RFC3339)})
	}
	if ms.CompletedBy != nil && ms.CompletedBy.Identifier != "" {
		props = append(props, oscal.Property{Name: "completed-by", Value: ms.CompletedBy.Identifier})
	}
	return props
}
