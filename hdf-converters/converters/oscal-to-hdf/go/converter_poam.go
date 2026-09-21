package oscal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertPOAMToHDF converts an OSCAL Plan of Action and Milestones (POA&M)
// document to HDF Amendments. Each poam-item becomes a StandaloneOverride.
//
// A POA&M hdf-to-oscal-poam produced returns every amendments field it carries
// (ADR-0014 §4.6), apart from the integrity fields and generator that contract
// excludes. Foreign POA&Ms, and HDF exports from before the ADR (§4.3), keep the
// mapping they had before it: type "poam", with their own extension props not
// carried (§3.6).
func ConvertPOAMToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	doc, err := ParseOscalDocument(input, "plan-of-action-and-milestones", "oscal-poam")
	if err != nil {
		return nil, err
	}

	return poamToHDFAmendments(doc.PlanOfActionAndMilestones, input, converterVersion)
}

// ExpectedPOAMRequirementCount states how many overrides a POA&M must convert
// to: one per poam-item within the item cap. An item with no usable deadline,
// or no usable appliedAt, is rejected exactly as the conversion rejects it.
// Computed from the input alone, through the same schedule validation the
// conversion applies.
func ExpectedPOAMRequirementCount(input []byte) (int, string, error) {
	const unit = "OSCAL POA&M items"
	doc, err := ParseOscalDocument(input, "plan-of-action-and-milestones", "oscal-poam")
	if err != nil {
		return 0, unit, err
	}
	poam := doc.PlanOfActionAndMilestones
	riskMap := buildRiskMap(poam.Risks)
	limitedPOAMItems := shared.LimitSliceWithWarning(poam.POAMItems, 0, "POA&M item")
	count := 0
	for i := range limitedPOAMItems {
		if !identifiedItem(&limitedPOAMItems[i], riskMap) {
			continue
		}
		if _, _, err := poamItemSchedule(&limitedPOAMItems[i], riskMap, poam); err != nil {
			return 0, unit, err
		}
		count++
	}
	return count, unit, nil
}

// poamToHDFAmendments converts a parsed PlanOfActionAndMilestones to HDFAmendments.
// Every emitted date is extracted from the OSCAL source. Conversion FAILS LOUD
// rather than fabricating a missing deadline: a POA&M with no time commitment
// defeats its purpose.
func poamToHDFAmendments(poam *PlanOfActionAndMilestones, rawInput []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	integrity := shared.InputIntegrity(rawInput)
	meta := ExtractMetadata(poam.Metadata)

	riskMap := buildRiskMap(poam.Risks)

	limitedPOAMItems := shared.LimitSliceWithWarning(poam.POAMItems, 0, "POA&M item")
	overrides := make([]hdf.StandaloneOverride, 0, len(limitedPOAMItems))
	hdfProduced := false
	for i := range limitedPOAMItems {
		item := &limitedPOAMItems[i]
		override, identified, err := poamItemToOverride(item, riskMap, poam)
		if err != nil {
			return nil, err
		}
		if !identified {
			continue
		}
		if hdfProducedRisk(item, riskMap) != nil {
			hdfProduced = true
		}
		overrides = append(overrides, override)
	}

	if len(overrides) == 0 {
		return nil, fmt.Errorf("oscal-poam-to-hdf: no poam-item names a requirement; every one of the %d items was skipped", len(limitedPOAMItems))
	}

	// Tamper-evidence must not depend on which route authored the document.
	if err := shared.ChainOverrides(overrides); err != nil {
		return nil, fmt.Errorf("oscal-poam-to-hdf: %w", err)
	}

	amendments := &hdf.HDFAmendments{
		Name:      ToKebabCase(poam.Metadata.Title, "oscal-poam"),
		Overrides: overrides,
		Integrity: integrity,
		Version:   hdfutil.Ptr(meta.Version),
		Generator: &hdf.Generator{
			Name:    "oscal-poam-to-hdf",
			Version: converterVersion,
		},
	}
	if poam.ImportSSP != nil && poam.ImportSSP.Href != "" {
		amendments.SystemRef = hdfutil.Ptr(poam.ImportSSP.Href)
	}
	if partyUUID := firstResponsibleParty(poam.Metadata, "prepared-by"); partyUUID != "" {
		amendments.AppliedBy = &hdf.Identity{Type: hdf.Simple, Identifier: partyUUID}
	}
	if hdfProduced {
		readHDFDocumentFields(poam, amendments)
	}

	return amendments, nil
}

// readHDFDocumentFields reads the amendments document fields from their ADR-0014
// §4.6 homes, which a POA&M carries only when one of its risks is HDF-produced (§4.3).
func readHDFDocumentFields(poam *PlanOfActionAndMilestones, amendments *hdf.HDFAmendments) {
	props := poam.Metadata.Props
	amendments.Name = ""
	if m, ok := FindGroupedVocabularyProp(props, "amendments-name", ""); ok {
		amendments.Name = m.Value
	}
	switch {
	case poam.Metadata.Remarks != "":
		amendments.Description = hdfutil.Ptr(poam.Metadata.Remarks)
	case HasFieldMarker(props, "empty-field", "description", ""):
		amendments.Description = hdfutil.Ptr("")
	}
	amendments.AppliedBy = documentIdentity(poam, "prepared-by")
	if id, ok := partyIdentity(poam, firstResponsibleParty(poam.Metadata, "approved-by")); ok {
		amendments.ApprovedBy = &id
	}
	amendments.AmendmentID = VocabularyString(props, "amendment-id", "amendmentId", "")
	amendments.Labels = amendmentLabels(props)
	amendments.SystemRef = markedField(props, "systemRef", amendments.SystemRef)
	amendments.Version = markedField(props, "version", amendments.Version)
}

// markedField applies the metadata markers for an OSCAL-required field the
// exporter wrote a display fallback for: absent-field leaves it absent and
// empty-field returns it empty.
func markedField(props []Property, field string, value *string) *string {
	switch {
	case HasFieldMarker(props, "absent-field", field, ""):
		return nil
	case HasFieldMarker(props, "empty-field", field, ""):
		return hdfutil.Ptr("")
	default:
		return value
	}
}

// amendmentLabels reads the label-key and label-value pairs, one per label-<n> group.
func amendmentLabels(props []Property) map[string]string {
	groups := map[string]bool{}
	matches := append(FindVocabularyProps(props, "label-key"), FindVocabularyProps(props, "empty-field")...)
	for _, m := range matches {
		if p := props[m.Index]; p.Class == "amendment-label" && p.Group != "" {
			groups[p.Group] = true
		}
	}
	if len(groups) == 0 {
		return nil
	}
	labels := make(map[string]string, len(groups))
	for group := range groups {
		key := VocabularyString(props, "label-key", "key", group)
		value := VocabularyString(props, "label-value", "value", group)
		if key != nil && value != nil {
			labels[*key] = *value
		}
	}
	return labels
}

// buildRiskMap creates a UUID → Risk lookup for correlating poam-items with risks.
func buildRiskMap(risks []Risk) map[string]*Risk {
	m := make(map[string]*Risk, len(risks))
	for i := range risks {
		m[risks[i].UUID] = &risks[i]
	}
	return m
}

// hdfProducedRisk returns the item's first related risk that carries override-type
// in the HDF namespace, which makes it HDF-produced (ADR-0014 §4.3), or nil.
func hdfProducedRisk(item *POAMItem, riskMap map[string]*Risk) *Risk {
	return overrideTypeRisk(item, riskMap, false)
}

// overrideTypeRisk returns the item's first related risk whose override-type prop
// is (legacy) or is not (!legacy) matched through the pre-ADR fallback, or nil.
func overrideTypeRisk(item *POAMItem, riskMap map[string]*Risk, legacy bool) *Risk {
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			if m, found := FindVocabularyProp(risk.Props, "override-type"); found && m.Legacy == legacy {
				return risk
			}
		}
	}
	return nil
}

// poamItemToOverride converts a single POAMItem to a StandaloneOverride. Every
// date is sourced from the OSCAL document; a missing appliedAt or deadline is a
// hard error (fail loud) rather than a fabricated wall-clock value.
// identified is false for a pre-ADR item with no requirement id, which is skipped.
func poamItemToOverride(item *POAMItem, riskMap map[string]*Risk, poam *PlanOfActionAndMilestones) (override hdf.StandaloneOverride, identified bool, err error) {
	risk := hdfProducedRisk(item, riskMap)
	var requirementID string
	if risk != nil {
		if _, ok := hdfRequirementID(risk); !ok {
			log.Printf("WARNING: Skipping poam-item \"%s\" titled \"%s\": its HDF-produced risk has no hdf-requirement-id", item.UUID, item.Title)
			return hdf.StandaloneOverride{}, false, nil
		}
	} else if requirementID, identified = foreignRequirementID(item, riskMap); !identified {
		log.Printf("WARNING: Skipping poam-item \"%s\" titled \"%s\": its pre-ADR risk has no impacted-control-id", item.UUID, item.Title)
		return hdf.StandaloneOverride{}, false, nil
	}

	appliedAt, expiresAt, err := poamItemSchedule(item, riskMap, poam)
	if err != nil {
		return hdf.StandaloneOverride{}, false, err
	}
	if risk != nil {
		return hdfOverride(item, risk, poam, appliedAt, expiresAt), true, nil
	}

	status := poamItemStatus(item, riskMap)
	return hdf.StandaloneOverride{
		Type:          hdf.Poam,
		RequirementID: requirementID,
		Reason:        poamItemReason(item),
		Status:        &status,
		AppliedBy:     poamItemAppliedBy(poam),
		AppliedAt:     appliedAt,
		ExpiresAt:     expiresAt,
		Milestones:    extractMilestones(item, riskMap),
	}, true, nil
}

// hdfOverride reads every override field from its ADR-0014 §4.6 home on an
// HDF-produced risk. An absent prop is an absent field: nothing is derived from
// titles or uuids.
func hdfOverride(item *POAMItem, risk *Risk, poam *PlanOfActionAndMilestones, appliedAt, expiresAt time.Time) hdf.StandaloneOverride {
	props := risk.Props
	override := hdf.StandaloneOverride{
		Reason:    item.Description,
		AppliedAt: appliedAt,
		ExpiresAt: expiresAt,
	}
	if m, ok := FindVocabularyProp(props, "override-type"); ok {
		override.Type = hdf.OverrideType(m.Value)
	}
	if id, ok := hdfRequirementID(risk); ok {
		override.RequirementID = id
	}
	if m, ok := FindVocabularyProp(props, "override-status"); ok {
		status := hdf.ResultStatus(m.Value)
		override.Status = &status
	}
	if m, ok := FindVocabularyProp(props, "impact-override"); ok {
		if value, err := strconv.ParseFloat(m.Value, 64); err == nil {
			override.Impact = &hdf.ImpactOverride{Value: value}
		}
	}
	if m, ok := FindVocabularyProp(props, "justification"); ok {
		justification := hdf.Justification(m.Value)
		override.Justification = &justification
	}
	override.BaselineRef = VocabularyString(props, "baseline-ref", "baselineRef", "")
	override.ComponentRef = VocabularyString(props, "component-ref", "componentRef", "")
	override.InheritedFrom = VocabularyString(props, "inherited-from", "inheritedFrom", "")
	override.AffectedPackages = affectedPackages(props)

	override.AppliedBy = poamItemAppliedBy(poam)
	if entry := overrideAppliedEntry(risk); entry != nil && len(entry.LoggedBy) > 0 {
		if id, ok := partyIdentity(poam, entry.LoggedBy[0].PartyUUID); ok {
			override.AppliedBy = id
		}
	}

	override.Milestones = hdfMilestones(risk, poam)
	override.Cvss = riskCvss(risk)
	override.Evidence = itemEvidence(item, poam)
	override.ExternalReferences = riskReferences(risk, poam)
	return override
}

// overrideAppliedEntry returns the risk-log entry recording when the override was applied.
func overrideAppliedEntry(risk *Risk) *RiskLogEntry {
	if risk.RiskLog == nil {
		return nil
	}
	for i := range risk.RiskLog.Entries {
		if risk.RiskLog.Entries[i].Title == "Override applied" {
			return &risk.RiskLog.Entries[i]
		}
	}
	return nil
}

// affectedPackages reads the package-<n> prop groups in position order.
func affectedPackages(props []Property) []hdf.AffectedPackage {
	positions := map[int]bool{}
	for i := range props {
		if n, ok := strings.CutPrefix(props[i].Group, "package-"); ok && ConsumedVocabularyProp(props[i]) {
			if position, err := strconv.Atoi(n); err == nil && position > 0 {
				positions[position] = true
			}
		}
	}
	if len(positions) == 0 {
		return nil
	}
	ordered := make([]int, 0, len(positions))
	for position := range positions {
		ordered = append(ordered, position)
	}
	sort.Ints(ordered)
	packages := make([]hdf.AffectedPackage, 0, len(ordered))
	for _, position := range ordered {
		group := fmt.Sprintf("package-%d", position)
		pkg := hdf.AffectedPackage{
			Name:           VocabularyString(props, "affected-package-name", "name", group),
			Version:        VocabularyString(props, "affected-package-version", "version", group),
			Cpe:            VocabularyString(props, "affected-package-cpe", "cpe", group),
			Purl:           VocabularyString(props, "affected-package-purl", "purl", group),
			FixedInVersion: VocabularyString(props, "affected-package-fixed-in-version", "fixedInVersion", group),
		}
		if ecosystem := VocabularyString(props, "affected-package-ecosystem", "ecosystem", group); ecosystem != nil {
			e := hdf.Ecosystem(*ecosystem)
			pkg.Ecosystem = &e
		}
		packages = append(packages, pkg)
	}
	return packages
}

// firstResponsibleParty returns the first party uuid metadata assigns to roleID, or "".
func firstResponsibleParty(meta Metadata, roleID string) string {
	for _, rp := range meta.ResponsibleParties {
		if rp.RoleID == roleID && len(rp.PartyIDs) > 0 {
			return rp.PartyIDs[0]
		}
	}
	return ""
}

// partyIdentity reads the HDF identity a metadata party carries. It reports false
// for a party that carries none, which is not HDF's.
func partyIdentity(poam *PlanOfActionAndMilestones, partyUUID string) (hdf.Identity, bool) {
	for i := range poam.Metadata.Parties {
		party := &poam.Metadata.Parties[i]
		if party.UUID != partyUUID {
			continue
		}
		identityType, ok := FindVocabularyProp(party.Props, "identity-type")
		if !ok {
			return hdf.Identity{}, false
		}
		id := hdf.Identity{Type: hdf.IdentityType(identityType.Value)}
		if m, found := FindVocabularyProp(party.Props, "identity-identifier"); found {
			id.Identifier = m.Value
		}
		switch {
		case party.Remarks != "":
			id.Description = hdfutil.Ptr(party.Remarks)
		case HasFieldMarker(party.Props, "empty-field", "description", ""):
			id.Description = hdfutil.Ptr("")
		}
		return id, true
	}
	return hdf.Identity{}, false
}

// documentIdentity reads the identity metadata assigns to roleID: the HDF identity
// its party carries, or else the party uuid as a simple identifier.
func documentIdentity(poam *PlanOfActionAndMilestones, roleID string) *hdf.Identity {
	partyUUID := firstResponsibleParty(poam.Metadata, roleID)
	if partyUUID == "" {
		return nil
	}
	if id, ok := partyIdentity(poam, partyUUID); ok {
		return &id
	}
	return &hdf.Identity{Type: hdf.Simple, Identifier: partyUUID}
}

// milestoneTitlePattern mirrors the schema's Milestone.title pattern: an OSCAL
// task title is markup-line, which a foreign producer may wrap or pad.
var milestoneTitlePattern = regexp.MustCompile("^[^ \t\n\r]([^\n\r]*[^ \t\n\r])?$")

// hdfMilestones reads each planned remediation task of an HDF-produced risk as a
// milestone whose description is the remediation description.
func hdfMilestones(risk *Risk, poam *PlanOfActionAndMilestones) []hdf.Milestone {
	var milestones []hdf.Milestone
	for _, rem := range risk.Remediations {
		if rem.Lifecycle != "planned" {
			continue
		}
		for i := range rem.Tasks {
			task := &rem.Tasks[i]
			if task.Timing == nil || task.Timing.WithinDateRange == nil {
				continue
			}
			eta := hdfutil.ParseTimestamp(task.Timing.WithinDateRange.End)
			if eta.IsZero() {
				continue
			}
			ms := hdf.Milestone{Description: rem.Description, EstimatedCompletion: eta, Status: hdf.Pending}
			if !HasFieldMarker(task.Props, "absent-field", "title", "") {
				if milestoneTitlePattern.MatchString(task.Title) {
					ms.Title = hdfutil.Ptr(task.Title)
				} else {
					log.Printf("WARNING: Dropping the title of task \"%s\": %q is not the single line Milestone.title is", task.UUID, task.Title)
				}
			}
			if m, ok := FindVocabularyProp(task.Props, "milestone-status"); ok {
				ms.Status = hdf.MilestoneStatus(m.Value)
			}
			if m, ok := FindVocabularyProp(task.Props, "completed-at"); ok {
				if t := hdfutil.ParseTimestamp(m.Value); !t.IsZero() {
					ms.CompletedAt = &t
				}
			}
			for _, rr := range task.ResponsibleRoles {
				if rr.RoleID == "completed-by" && len(rr.PartyIDs) > 0 {
					if id, ok := partyIdentity(poam, rr.PartyIDs[0]); ok {
						ms.CompletedBy = &id
					}
				}
			}
			milestones = append(milestones, ms)
		}
	}
	return milestones
}

// cvssSystemPrefix begins the facet system of every CVSS version.
const cvssSystemPrefix = "http://www.first.org/cvss/v"

// riskCvss reads the characterization whose facets all use a CVSS system.
func riskCvss(risk *Risk) *hdf.Cvss {
	for i := range risk.Characterizations {
		ch := &risk.Characterizations[i]
		if len(ch.Facets) == 0 || !cvssFacets(ch.Facets) {
			continue
		}
		values := map[string]*string{}
		for j := range ch.Facets {
			value := ch.Facets[j].Value
			if ch.Facets[j].Remarks != "" {
				value = ch.Facets[j].Remarks
			}
			values[ch.Facets[j].Name] = &value
		}
		str := func(name, field string) *string {
			if v, ok := values[name]; ok {
				return v
			}
			if HasFieldMarker(ch.Props, "empty-field", field, "") {
				return hdfutil.Ptr("")
			}
			return nil
		}
		score := func(name string) *float64 {
			if v, ok := values[name]; ok {
				if f, err := strconv.ParseFloat(*v, 64); err == nil {
					return &f
				}
			}
			return nil
		}
		severity := func(name string) *hdf.CVSSSeverity {
			if v, ok := values[name]; ok {
				s := hdf.CVSSSeverity(*v)
				return &s
			}
			return nil
		}
		c := &hdf.Cvss{
			BaseScore:           score("base_score"),
			BaseSeverity:        severity("base_severity"),
			BaseVector:          str("base_vector", "baseVector"),
			ThreatScore:         score("threat_score"),
			ThreatVector:        str("threat_vector", "threatVector"),
			EnvironmentalScore:  score("environmental_score"),
			EnvironmentalVector: str("environmental_vector", "environmentalVector"),
			ComputedScore:       score("computed_score"),
			ComputedSeverity:    severity("computed_severity"),
			SupplementalVector:  str("supplemental_vector", "supplementalVector"),
			Source:              str("source", "source"),
		}
		if v, ok := values["cvss_version"]; ok {
			c.Version = hdf.Version(*v)
		}
		return c
	}
	return nil
}

func cvssFacets(facets []Facet) bool {
	for _, f := range facets {
		if !strings.HasPrefix(f.System, cvssSystemPrefix) {
			return false
		}
	}
	return true
}

// itemEvidence reads the evidence observations an HDF-produced item lists. An
// observation with no payload is not an HDF evidence item (ADR-0014 §4.6 gives
// Evidence.data no other home) and Evidence.data is required and non-empty, so
// a foreign observation listed alongside the exported ones is skipped.
func itemEvidence(item *POAMItem, poam *PlanOfActionAndMilestones) []hdf.Evidence {
	var evidence []hdf.Evidence
	for _, ro := range item.RelatedObservations {
		for i := range poam.Observations {
			obs := &poam.Observations[i]
			if obs.UUID != ro.ObservationUUID {
				continue
			}
			if ev := observationEvidence(obs, poam); ev.Data != "" {
				evidence = append(evidence, ev)
			} else {
				log.Printf("WARNING: Skipping evidence observation \"%s\": no relevant-evidence href and no evidence resource", obs.UUID)
			}
			break
		}
	}
	return evidence
}

// observationEvidence reads one evidence item from its observation (ADR-0014 §4.6 Evidence table).
func observationEvidence(obs *Observation, poam *PlanOfActionAndMilestones) hdf.Evidence {
	props := obs.Props
	ev := hdf.Evidence{
		MIMEType: VocabularyString(props, "mime-type", "mimeType", ""),
		Encoding: VocabularyString(props, "evidence-encoding", "encoding", ""),
	}
	if len(obs.Types) > 0 {
		ev.Type = hdf.EvidenceType(obs.Types[0])
	}
	if !HasFieldMarker(props, "absent-field", "description", "") {
		ev.Description = hdfutil.Ptr(obs.Description)
	}
	if m, ok := FindVocabularyProp(props, "evidence-size"); ok {
		if size, err := strconv.ParseFloat(m.Value, 64); err == nil {
			ev.Size = &size
		}
	}
	if !HasFieldMarker(props, "absent-field", "capturedAt", "") {
		if t := hdfutil.ParseTimestamp(obs.Collected); !t.IsZero() {
			ev.CapturedAt = &t
		}
	}
	for _, origin := range obs.Origins {
		for _, actor := range origin.Actors {
			if id, ok := partyIdentity(poam, actor.ActorID); ok && actor.Type == "party" && ev.CapturedBy == nil {
				ev.CapturedBy = &id
			}
		}
	}

	if len(obs.RelevantEvidence) > 0 && obs.RelevantEvidence[0].Href != "" {
		ev.Data = obs.RelevantEvidence[0].Href
		return ev
	}
	for _, link := range obs.Links {
		res := backMatterResource(poam, link)
		if link.Rel != "evidence" || res == nil || res.Base64 == nil {
			continue
		}
		ev.Data = res.Base64.Value
		if ev.Encoding == nil || *ev.Encoding != "base64" {
			if decoded, err := base64.StdEncoding.DecodeString(res.Base64.Value); err == nil {
				ev.Data = string(decoded)
			}
		}
		break
	}
	return ev
}

// backMatterResource resolves a link to the back-matter resource its "#<uuid>" href names.
func backMatterResource(poam *PlanOfActionAndMilestones, link Link) *Resource {
	uuid, ok := strings.CutPrefix(link.Href, "#")
	if !ok || poam.BackMatter == nil {
		return nil
	}
	for i := range poam.BackMatter.Resources {
		if poam.BackMatter.Resources[i].UUID == uuid {
			return &poam.BackMatter.Resources[i]
		}
	}
	return nil
}

// riskReferences reads the external references an HDF-produced risk links to
// (ADR-0014 §4.6 External reference table).
func riskReferences(risk *Risk, poam *PlanOfActionAndMilestones) []hdf.ExternalReference {
	var refs []hdf.ExternalReference
	for _, link := range risk.Links {
		res := backMatterResource(poam, link)
		if link.Rel != "reference" || res == nil {
			continue
		}
		props := res.Props
		ref := hdf.ExternalReference{
			ExternalID: VocabularyString(props, "external-id", "externalId", ""),
			Rel:        VocabularyString(props, "reference-rel", "rel", ""),
			MediaType:  VocabularyString(props, "reference-media-type", "mediaType", ""),
			Kind:       VocabularyString(props, "reference-kind", "kind", ""),
		}
		if m, ok := FindVocabularyProp(props, "source-name"); ok {
			ref.SourceName = m.Value
		}
		switch {
		case len(res.Rlinks) > 0:
			ref.Href = hdfutil.Ptr(res.Rlinks[0].Href)
		case HasFieldMarker(props, "empty-field", "href", ""):
			ref.Href = hdfutil.Ptr("")
		}
		switch {
		case res.Description != "":
			ref.Description = hdfutil.Ptr(res.Description)
		case HasFieldMarker(props, "empty-field", "description", ""):
			ref.Description = hdfutil.Ptr("")
		}
		if algorithm := VocabularyString(props, "checksum-algorithm", "checksum.algorithm", ""); algorithm != nil {
			ref.Checksum = &hdf.Checksum{Algorithm: hdf.HashAlgorithm(*algorithm)}
			if value := VocabularyString(props, "checksum-value", "checksum.value", ""); value != nil {
				ref.Checksum.Value = *value
			}
		}
		if m, ok := FindVocabularyProp(props, "added-by"); ok {
			if id, found := partyIdentity(poam, m.Value); found {
				ref.AddedBy = &id
			}
		}
		if m, ok := FindVocabularyProp(props, "added-at"); ok {
			if t := hdfutil.ParseTimestamp(m.Value); !t.IsZero() {
				ref.AddedAt = &t
			}
		}
		if res.Base64 != nil {
			if raw, err := base64.StdEncoding.DecodeString(res.Base64.Value); err == nil {
				var document map[string]interface{}
				if json.Unmarshal(raw, &document) == nil {
					ref.Document = document
				}
			}
		}
		refs = append(refs, ref)
	}
	return refs
}

// poamItemSchedule resolves the item's appliedAt and deadline, failing loud on
// either. It is the item-level acceptance rule: the conversion emits an
// override only for an item that passes it, and ExpectedPOAMRequirementCount
// applies the same rule. An HDF-produced risk records appliedAt in its risk
// log; any other item takes the document's last-modified.
func poamItemSchedule(item *POAMItem, riskMap map[string]*Risk, poam *PlanOfActionAndMilestones) (appliedAt, expiresAt time.Time, err error) {
	label := extractRequirementIDFromPOAMItem(item, riskMap)
	if risk := hdfProducedRisk(item, riskMap); risk != nil {
		label, _ = hdfRequirementID(risk)
		if entry := overrideAppliedEntry(risk); entry != nil {
			appliedAt = hdfutil.ParseTimestamp(entry.Start)
		}
	}
	if appliedAt.IsZero() {
		appliedAt, err = poamItemAppliedAt(poam)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("poam-item %q: %w", label, err)
		}
	}
	expiresAt, err = poamItemExpiresAt(item, riskMap)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("poam-item %q: %w", label, err)
	}
	return appliedAt, expiresAt, nil
}

// foreignRequirementID returns the requirement id of an item that is not
// HDF-produced. A pre-ADR HDF export's id comes only from its legacy
// impacted-control-id, never from a title (ADR-0014 §4.3), so identified is false
// for one that has none, which the conversion skips.
func foreignRequirementID(item *POAMItem, riskMap map[string]*Risk) (id string, identified bool) {
	if risk := overrideTypeRisk(item, riskMap, true); risk != nil {
		m, ok := FindVocabularyProp(risk.Props, "impacted-control-id")
		if !ok {
			return "", false
		}
		return ControlIDToNistTag(m.Value), true
	}
	return extractRequirementIDFromPOAMItem(item, riskMap), true
}

// identifiedItem reports whether the conversion imports an item rather than
// skipping it for want of a requirement id.
func identifiedItem(item *POAMItem, riskMap map[string]*Risk) bool {
	if risk := hdfProducedRisk(item, riskMap); risk != nil {
		_, ok := hdfRequirementID(risk)
		return ok
	}
	_, identified := foreignRequirementID(item, riskMap)
	return identified
}

// hdfRequirementID reads the requirement id an HDF-produced risk carries. An
// absent or empty prop names no requirement, and StandaloneOverride.requirementId
// is required and non-empty, so the item is skipped rather than imported unusable.
func hdfRequirementID(risk *Risk) (string, bool) {
	m, ok := FindVocabularyProp(risk.Props, "hdf-requirement-id")
	if !ok || m.Value == "" {
		return "", false
	}
	return m.Value, true
}

// extractRequirementIDFromPOAMItem extracts a requirement ID from a foreign
// poam-item. It checks the related risks for impacted-control-id props, then
// falls back to the poam-item title.
func extractRequirementIDFromPOAMItem(item *POAMItem, riskMap map[string]*Risk) string {
	// Check related risks for impacted-control-id
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			if controlID, found := ExtractPropValue(risk.Props, "impacted-control-id", ""); found {
				return ControlIDToNistTag(controlID)
			}
		}
	}

	// Check poam-item props for POAM-ID or control reference
	if poamID, ok := ExtractPropValue(item.Props, "POAM-ID", ""); ok {
		return poamID
	}

	// Fall back to the title
	if item.Title != "" {
		return item.Title
	}

	return "unknown"
}

// poamItemReason builds a reason string from the poam-item description and
// related risk information.
func poamItemReason(item *POAMItem) string {
	if item.Description != "" {
		return item.Description
	}
	if item.Title != "" {
		return item.Title
	}
	return "POA&M item"
}

// poamItemStatus determines the HDF status for a poam-item based on related
// risk status. POA&Ms track remediation, so the status reflects the current
// risk state.
func poamItemStatus(item *POAMItem, riskMap map[string]*Risk) hdf.ResultStatus {
	// Check related risks for status
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			if status, found := OscalStatusToHDF(risk.Status); found {
				switch status {
				case "passed":
					return hdf.Passed
				case "failed":
					return hdf.Failed
				}
			}
		}
	}

	// Default: POA&M items typically represent open/failed findings
	return hdf.Failed
}

// poamItemAppliedBy extracts the identity of who is responsible for the POA&M.
func poamItemAppliedBy(poam *PlanOfActionAndMilestones) hdf.Identity {
	// Look for prepared-by in responsible-parties
	if partyUUID := firstResponsibleParty(poam.Metadata, "prepared-by"); partyUUID != "" {
		return hdf.Identity{Type: hdf.Simple, Identifier: partyUUID}
	}

	// Fall back to any responsible party
	if len(poam.Metadata.ResponsibleParties) > 0 && len(poam.Metadata.ResponsibleParties[0].PartyIDs) > 0 {
		return hdf.Identity{
			Type:       hdf.Simple,
			Identifier: poam.Metadata.ResponsibleParties[0].PartyIDs[0],
		}
	}

	return hdf.Identity{
		Type:       hdf.IdentityTypeSystem,
		Identifier: "oscal-poam-converter",
	}
}

// poamItemAppliedAt returns the appliedAt timestamp from the document's
// metadata.last-modified. OSCAL requires last-modified, so its absence is a
// malformed document — fail loud rather than stamp a wall-clock time.
func poamItemAppliedAt(poam *PlanOfActionAndMilestones) (time.Time, error) {
	if t := hdfutil.ParseTimestamp(poam.Metadata.LastModified); !t.IsZero() {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("no usable metadata.last-modified for appliedAt")
}

// poamItemExpiresAt returns the override deadline from the related risk's
// `deadline`. This is the enforceable time commitment of the POA&M; if no
// related risk carries a usable deadline the conversion fails loud rather than
// invent one (a POA&M without a deadline is meaningless).
func poamItemExpiresAt(item *POAMItem, riskMap map[string]*Risk) (time.Time, error) {
	for _, rr := range item.RelatedRisks {
		risk, ok := riskMap[rr.RiskUUID]
		if !ok {
			continue
		}
		if t := hdfutil.ParseTimestamp(risk.Deadline); !t.IsZero() {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no related risk carries a usable deadline; a POA&M requires a time commitment")
}

// extractMilestones builds milestones from the planned remediation tasks of a
// foreign item's related risks. Each task's within-date-range end is its
// estimated completion. Tasks without a usable end date are skipped (the
// milestones array is optional) — never fabricated — since
// Milestone.estimatedCompletion is required and must reflect real source data.
func extractMilestones(item *POAMItem, riskMap map[string]*Risk) []hdf.Milestone {
	var milestones []hdf.Milestone

	for _, rr := range item.RelatedRisks {
		risk, ok := riskMap[rr.RiskUUID]
		if !ok {
			continue
		}

		for _, rem := range risk.Remediations {
			if rem.Lifecycle != "planned" {
				continue
			}
			for i := range rem.Tasks {
				task := &rem.Tasks[i]
				if task.Timing == nil || task.Timing.WithinDateRange == nil {
					continue
				}
				eta := hdfutil.ParseTimestamp(task.Timing.WithinDateRange.End)
				if eta.IsZero() {
					continue
				}
				milestones = append(milestones, hdf.Milestone{
					Description:         milestoneDescription(task),
					EstimatedCompletion: eta,
					Status:              hdf.Pending,
				})
			}
		}
	}

	return milestones
}

// milestoneDescription renders a milestone label from an OSCAL task: its title,
// with the description appended when present.
func milestoneDescription(task *Task) string {
	if task.Description != "" {
		return task.Title + ": " + task.Description
	}
	return task.Title
}
