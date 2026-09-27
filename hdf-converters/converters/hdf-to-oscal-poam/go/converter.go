// Package hdftooscalpoam converts HDF Amendments to OSCAL Plan of Action and
// Milestones (POA&M) format. This is the reverse direction of the oscal-poam
// to HDF converter.
//
// Every amendments field has an OSCAL home the importer reads back exactly
// (ADR-0014 §4.6), with four exclusions: the document integrity and signature,
// the generator (the importer stamps its own), and each override's signature
// and previousChecksum. A signature covers the original HDF bytes and the
// checksum chain covers document order; neither survives a format change, and
// the importer re-chains the overrides it reads.
package hdftooscalpoam

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	nist "github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertHDFToOSCALPOAM converts HDF Amendments JSON to OSCAL POA&M JSON.
// This is a RawConvertFn — it takes raw bytes and returns raw bytes.
func ConvertHDFToOSCALPOAM(input []byte, converterVersion string) ([]byte, error) {
	// The guard rejects a document that cannot be faithfully converted rather
	// than zero-filling it: the amendments schema puts minItems 1 on overrides,
	// so a document that amends nothing is invalid input, not a request for an
	// empty POA&M. It also keeps poam-items and risks non-empty, which the OSCAL
	// schema requires (both carry minItems 1, so an empty array would be as
	// invalid as the null a nil slice used to produce).
	var amendments hdf.HDFAmendments
	if err := shared.RequireHDFAmendmentsTyped(input, "hdf-to-oscal-poam", &amendments); err != nil {
		return nil, err
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

// Role ids of the metadata roles the exporter defines.
const (
	rolePreparedBy  = "prepared-by"
	roleApprovedBy  = "approved-by"
	roleCompletedBy = "completed-by"
)

// overrideAppliedTitle marks the risk-log entry whose start is the override's
// appliedAt and whose logged-by names its appliedBy.
const overrideAppliedTitle = "Override applied"

// identityKey is the (identifier, type, description) triple that makes an HDF
// identity one OSCAL party. An absent and an empty description are distinct.
type identityKey struct {
	identifier     string
	identityType   string
	hasDescription bool
	description    string
}

// partyRegistry deduplicates HDF identities into OSCAL metadata parties, one per
// distinct identity triple. Insertion order is preserved for deterministic output.
type partyRegistry struct {
	parties []oscal.Party
	byKey   map[identityKey]string
}

func newPartyRegistry() *partyRegistry {
	return &partyRegistry{byKey: make(map[identityKey]string)}
}

// getOrAdd returns the party UUID for an identity, minting the party the first
// time its triple is seen. The party carries the identity in HDF props and its
// description in remarks; the party name and type are display text.
func (r *partyRegistry) getOrAdd(id hdf.Identity) string {
	key := identityKey{identifier: id.Identifier, identityType: string(id.Type), hasDescription: id.Description != nil}
	if id.Description != nil {
		key.description = *id.Description
	}
	if uuid, ok := r.byKey[key]; ok {
		return uuid
	}
	party := oscal.Party{UUID: oscal.GenerateUUID(), Type: "person", Name: oscal.OSCALString(id.Identifier)}
	party.Props = oscal.AppendVocabularyProp(nil, "identity-identifier", id.Identifier)
	party.Props = oscal.AppendVocabularyProp(party.Props, "identity-type", string(id.Type))
	switch {
	case id.Description == nil:
	case *id.Description == "":
		party.Props = append(party.Props, oscal.EmptyFieldProp("description"))
	default:
		party.Remarks = *id.Description
	}
	r.byKey[key] = party.UUID
	r.parties = append(r.parties, party)
	return party.UUID
}

func (r *partyRegistry) list() []oscal.Party {
	return r.parties
}

// poamBuilder accumulates the document-wide objects overrides contribute to.
type poamBuilder struct {
	parties      *partyRegistry
	observations []oscal.Observation
	resources    []oscal.Resource
	completedBy  bool
}

// amendmentsToPOAM converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
func amendmentsToPOAM(amendments *hdf.HDFAmendments, _ string) (*oscal.PlanOfActionAndMilestones, error) {
	b := &poamBuilder{parties: newPartyRegistry()}

	var roles []oscal.Role
	var responsibleParties []oscal.ResponsibleParty

	// The document preparer and the authorizing official become responsible
	// parties with distinct roles — a direct mirror of one another.
	if amendments.AppliedBy != nil {
		uuid := b.parties.getOrAdd(*amendments.AppliedBy)
		roles = append(roles, oscal.Role{ID: rolePreparedBy, Title: "Prepared By"})
		responsibleParties = append(responsibleParties, oscal.ResponsibleParty{RoleID: rolePreparedBy, PartyIDs: []string{uuid}})
	}
	if amendments.ApprovedBy != nil {
		uuid := b.parties.getOrAdd(*amendments.ApprovedBy)
		roles = append(roles, oscal.Role{ID: roleApprovedBy, Title: "Approved By"})
		responsibleParties = append(responsibleParties, oscal.ResponsibleParty{RoleID: roleApprovedBy, PartyIDs: []string{uuid}})
	}

	// Register each override's own applier so per-override attribution survives
	// as a distinct metadata party even when it differs from the document default.
	for i := range amendments.Overrides {
		b.parties.getOrAdd(amendments.Overrides[i].AppliedBy)
	}

	// poamItems is pre-allocated rather than declared nil because POAMItems has
	// no omitempty: a nil slice would marshal as null, which the schema rejects
	// for a required array. Risks does carry omitempty, so a nil there would be
	// omitted rather than nulled — legal, since the schema requires only that
	// risks be non-empty WHEN present. Both are pre-allocated for symmetry.
	//
	// The guard already rules out zero overrides, so neither is a live path; this
	// is defence against a future refactor moving that guard.
	poamItems := make([]oscal.POAMItem, 0, len(amendments.Overrides))
	risks := make([]oscal.Risk, 0, len(amendments.Overrides))

	for i := range amendments.Overrides {
		item, risk, err := b.overrideToPOAMItem(&amendments.Overrides[i])
		if err != nil {
			return nil, err
		}
		poamItems = append(poamItems, item)
		risks = append(risks, risk)
	}

	if b.completedBy {
		roles = append(roles, oscal.Role{ID: roleCompletedBy, Title: "Completed By"})
	}

	meta := oscal.Metadata{
		Title:              poamTitle(amendments),
		LastModified:       latestAppliedAt(amendments.Overrides),
		Version:            amendmentsVersion(amendments),
		OscalVersion:       oscal.OscalVersion,
		Roles:              roles,
		Parties:            b.parties.list(),
		ResponsibleParties: responsibleParties,
		Props:              metadataProps(amendments),
	}
	if amendments.Description != nil {
		meta.Remarks = *amendments.Description
	}

	var backMatter *oscal.BackMatter
	if len(b.resources) > 0 {
		backMatter = &oscal.BackMatter{Resources: b.resources}
	}

	poam := &oscal.PlanOfActionAndMilestones{
		UUID:         oscal.GenerateUUID(),
		Metadata:     meta,
		ImportSSP:    &oscal.ImportSSP{Href: systemRefHref(amendments.SystemRef)},
		Observations: b.observations,
		Risks:        risks,
		POAMItems:    poamItems,
		BackMatter:   backMatter,
	}

	return poam, nil
}

// systemRefHref is the import-ssp href, which OSCAL requires: "#" stands in for
// an absent or empty systemRef, which metadata props mark.
func systemRefHref(systemRef *string) string {
	if systemRef == nil || *systemRef == "" {
		return "#"
	}
	return *systemRef
}

// formatTimestamp renders an HDF timestamp in HDF's canonical trimmed-UTC form,
// keeping the millisecond fraction the round trip must return.
func formatTimestamp(t time.Time) string {
	return hdfutil.NormalizeTimestamp(t).Format(time.RFC3339Nano)
}

// appendOptionalString carries an optional HDF string field: its prop when the
// value is non-empty, empty-field when it is present and empty (§1.7.3), and
// nothing when it is absent.
func appendOptionalString(props []oscal.Property, name, field string, value *string) []oscal.Property {
	switch {
	case value == nil:
		return props
	case *value == "":
		return append(props, oscal.EmptyFieldProp(field))
	default:
		return oscal.AppendVocabularyProp(props, name, *value)
	}
}

// displayLine renders HDF text as single-line OSCAL display text, falling back
// when there is none.
func displayLine(text, fallback string) string {
	if line := oscal.NormalizePropValue(text); line != "" {
		return line
	}
	return fallback
}

// overrideToPOAMItem converts a single StandaloneOverride to a POAMItem and its
// Risk, adding its evidence observations, back-matter resources and parties to
// the builder.
func (b *poamBuilder) overrideToPOAMItem(override *hdf.StandaloneOverride) (oscal.POAMItem, oscal.Risk, error) {
	riskUUID := oscal.GenerateUUID()

	// Overrides without a status field (impact-only) are treated as open risks.
	riskStatus := "open"
	if override.Status != nil {
		riskStatus = oscal.HDFStatusToOSCALRiskStatus(*override.Status)
	}

	applier := b.parties.getOrAdd(override.AppliedBy)

	risk := oscal.Risk{
		UUID:              riskUUID,
		Title:             requirementTitle(override),
		Status:            riskStatus,
		Props:             riskProps(override),
		Remediations:      b.milestoneRemediations(override.Milestones),
		Characterizations: cvssCharacterizations(override.Cvss, applier),
		RiskLog:           riskLog(override, applier, riskStatus),
	}
	// OSCAL lists title, description, statement and status as required on a risk,
	// and Statement carries omitempty, so an empty HDF reason used to drop the
	// field entirely. HDF does not constrain reason, so this is reachable from a
	// schema-valid document.
	risk.Description = riskRationale(override)
	risk.Statement = risk.Description
	if !override.ExpiresAt.IsZero() {
		risk.Deadline = formatTimestamp(override.ExpiresAt)
	}

	var relatedObs []oscal.RelatedRef
	for i := range override.Evidence {
		obs := b.evidenceObservation(&override.Evidence[i], override.AppliedAt)
		b.observations = append(b.observations, obs)
		relatedObs = append(relatedObs, oscal.RelatedRef{ObservationUUID: obs.UUID})
	}
	for i := range override.ExternalReferences {
		res, err := b.referenceResource(&override.ExternalReferences[i])
		if err != nil {
			return oscal.POAMItem{}, oscal.Risk{}, err
		}
		b.resources = append(b.resources, res)
		risk.Links = append(risk.Links, oscal.Link{Href: "#" + res.UUID, Rel: "reference"})
	}

	item := oscal.POAMItem{
		UUID:                oscal.GenerateUUID(),
		Title:               requirementTitle(override),
		Description:         override.Reason,
		RelatedRisks:        []oscal.RelatedRef{{RiskUUID: riskUUID}},
		RelatedObservations: relatedObs,
	}

	return item, risk, nil
}

// riskProps carries the override's identity, disposition and scope. The FedRAMP
// impacted-control-id is added only for a requirement id NIST defines.
func riskProps(override *hdf.StandaloneOverride) []oscal.Property {
	props := oscal.AppendVocabularyProp(nil, "hdf-requirement-id", override.RequirementID)
	if nist.NistExists(override.RequirementID) {
		props = oscal.AppendVocabularyProp(props, "impacted-control-id", oscal.NistTagToControlID(override.RequirementID))
	}
	props = oscal.AppendVocabularyProp(props, "override-type", string(override.Type))
	if override.Status != nil {
		props = oscal.AppendVocabularyProp(props, "override-status", string(*override.Status))
	}
	if override.Impact != nil {
		props = oscal.AppendVocabularyProp(props, "impact-override", string(exportmap.FloatToken(override.Impact.Value)))
	}
	if override.Justification != nil {
		props = oscal.AppendVocabularyProp(props, "justification", string(*override.Justification))
	}
	props = appendOptionalString(props, "baseline-ref", "baselineRef", override.BaselineRef)
	props = appendOptionalString(props, "component-ref", "componentRef", override.ComponentRef)
	props = appendOptionalString(props, "inherited-from", "inheritedFrom", override.InheritedFrom)
	for i := range override.AffectedPackages {
		props = append(props, affectedPackageProps(&override.AffectedPackages[i], fmt.Sprintf("package-%d", i+1))...)
	}
	return props
}

// affectedPackageProps carries one affected package, every prop in its group.
func affectedPackageProps(pkg *hdf.AffectedPackage, group string) []oscal.Property {
	var ecosystem *string
	if pkg.Ecosystem != nil {
		e := string(*pkg.Ecosystem)
		ecosystem = &e
	}
	props := appendOptionalString(nil, "affected-package-name", "name", pkg.Name)
	props = appendOptionalString(props, "affected-package-version", "version", pkg.Version)
	props = appendOptionalString(props, "affected-package-ecosystem", "ecosystem", ecosystem)
	props = appendOptionalString(props, "affected-package-cpe", "cpe", pkg.Cpe)
	props = appendOptionalString(props, "affected-package-purl", "purl", pkg.Purl)
	props = appendOptionalString(props, "affected-package-fixed-in-version", "fixedInVersion", pkg.FixedInVersion)
	for i := range props {
		props[i].Group = group
	}
	return props
}

// riskLog records when and by whom the override was applied, and its scheduled
// review at expiry.
func riskLog(override *hdf.StandaloneOverride, applier, riskStatus string) *oscal.RiskLog {
	var entries []oscal.RiskLogEntry
	if !override.AppliedAt.IsZero() {
		entries = append(entries, oscal.RiskLogEntry{
			UUID:     oscal.GenerateUUID(),
			Title:    overrideAppliedTitle,
			Start:    formatTimestamp(override.AppliedAt),
			LoggedBy: []oscal.LoggedBy{{PartyUUID: applier}},
		})
	}
	if !override.ExpiresAt.IsZero() {
		entries = append(entries, oscal.RiskLogEntry{
			UUID:         oscal.GenerateUUID(),
			Title:        "Scheduled review",
			Description:  "Amendment expiration date",
			Start:        formatTimestamp(override.ExpiresAt),
			StatusChange: riskStatus,
		})
	}
	if len(entries) == 0 {
		return nil
	}
	return &oscal.RiskLog{Entries: entries}
}

// milestoneRemediations renders each milestone as a planned remediation whose
// title and description are the milestone's and whose task carries its title,
// schedule, status and completion. An untitled milestone is titled "Milestone <n>"
// and marked absent-field on both objects (§1.7.4).
func (b *poamBuilder) milestoneRemediations(milestones []hdf.Milestone) []oscal.Remediation {
	var remediations []oscal.Remediation
	for i := range milestones {
		ms := &milestones[i]
		var marker []oscal.Property
		title := fmt.Sprintf("Milestone %d", i+1)
		if ms.Title != nil {
			title = *ms.Title
		} else {
			marker = []oscal.Property{oscal.AbsentFieldProp("title")}
		}
		rem := oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "planned",
			Title:       title,
			Description: ms.Description,
			Props:       marker,
		}
		if !ms.EstimatedCompletion.IsZero() {
			eta := formatTimestamp(ms.EstimatedCompletion)
			task := oscal.Task{
				UUID:   oscal.GenerateUUID(),
				Type:   "milestone",
				Title:  title,
				Timing: &oscal.Timing{WithinDateRange: &oscal.DateRange{Start: eta, End: eta}},
				Props:  oscal.AppendVocabularyProp(append([]oscal.Property(nil), marker...), "milestone-status", string(ms.Status)),
			}
			if ms.CompletedAt != nil && !ms.CompletedAt.IsZero() {
				task.Props = oscal.AppendVocabularyProp(task.Props, "completed-at", formatTimestamp(*ms.CompletedAt))
			}
			if ms.CompletedBy != nil {
				b.completedBy = true
				task.ResponsibleRoles = []oscal.ResponsibleRole{{RoleID: roleCompletedBy, PartyIDs: []string{b.parties.getOrAdd(*ms.CompletedBy)}}}
			}
			rem.Tasks = []oscal.Task{task}
		}
		remediations = append(remediations, rem)
	}
	return remediations
}

// poamTitle picks the document title, which OSCAL requires on metadata. The HDF
// name is schema-required, so the fallbacks only matter for a document that
// slipped through some other producer's validation.
func poamTitle(a *hdf.HDFAmendments) string {
	return shared.FirstNonEmpty(a.Name, derefString(a.AmendmentID), "HDF Amendments")
}

// unidentifiedRequirementTitle stands in for an empty requirementId: HDF puts no
// minLength on it, and OSCAL 1.2.x requires risk and POA&M item titles to be
// non-empty. It is display text only; the requirement id rides in hdf-requirement-id.
const unidentifiedRequirementTitle = "Unidentified requirement"

// requirementTitle is the title of the risk and POA&M item an override produces.
func requirementTitle(override *hdf.StandaloneOverride) string {
	return shared.FirstNonEmpty(override.RequirementID, unidentifiedRequirementTitle)
}

// riskRationale supplies the text OSCAL requires for a risk's description and
// statement. HDF puts no minLength on reason, so an override can legitimately
// carry none; the fallback states that absence rather than inventing an impact
// assessment the source never made, and names the requirement only when there is one.
func riskRationale(override *hdf.StandaloneOverride) string {
	absence := fmt.Sprintf("No rationale was recorded for the %s override applied to %s.",
		override.Type, override.RequirementID)
	if shared.FirstNonEmpty(override.RequirementID) == "" {
		absence = fmt.Sprintf("No rationale was recorded for the %s override.", override.Type)
	}
	return shared.FirstNonEmpty(override.Reason, absence)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// latestAppliedAt returns the most recent override appliedAt formatted for
// metadata.last-modified. Sourcing it from the input keeps output deterministic.
// Falls back to the wall clock only when no override carries a date (appliedAt
// is schema-required, so real documents always supply one).
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

// amendmentsVersion sources metadata.version from the amendments document. OSCAL
// requires a version, so an absent or empty one is written as 1.0.0 and marked
// by a metadata prop.
func amendmentsVersion(a *hdf.HDFAmendments) string {
	if a.Version != nil {
		if v := oscal.OSCALString(*a.Version); v != "" {
			return v
		}
	}
	return "1.0.0"
}

// metadataProps carries the document fields that have no first-class OSCAL home
// and marks the display fallbacks OSCAL forced. Labels are key/value prop pairs
// grouped in sorted key order.
func metadataProps(a *hdf.HDFAmendments) []oscal.Property {
	props := oscal.AppendVocabularyProp(nil, "amendments-name", a.Name)
	props = appendOptionalString(props, "amendment-id", "amendmentId", a.AmendmentID)
	if a.Description != nil && *a.Description == "" {
		props = append(props, oscal.EmptyFieldProp("description"))
	}
	props = appendFallbackMarker(props, "systemRef", a.SystemRef)
	props = appendFallbackMarker(props, "version", a.Version)

	keys := make([]string, 0, len(a.Labels))
	for k := range a.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		group := fmt.Sprintf("label-%d", i+1)
		props = append(props, labelProp("label-key", "key", k, group), labelProp("label-value", "value", a.Labels[k], group))
	}
	return props
}

// appendFallbackMarker marks an OSCAL-required field written as a display
// fallback: absent-field when the HDF field is absent, empty-field when it is empty.
func appendFallbackMarker(props []oscal.Property, field string, value *string) []oscal.Property {
	switch {
	case value == nil:
		return append(props, oscal.AbsentFieldProp(field))
	case *value == "":
		return append(props, oscal.EmptyFieldProp(field))
	default:
		return props
	}
}

// labelProp renders one half of an amendments label; an empty key or value is
// carried by empty-field (§1.7.3).
func labelProp(name, field, value, group string) oscal.Property {
	prop := oscal.EmptyFieldProp(field)
	if value != "" {
		prop, _ = oscal.VocabularyProp(name, value)
	}
	prop.Class = "amendment-label"
	prop.Group = group
	return prop
}

// absoluteURIPattern matches an RFC 3986 URI with a scheme, whose characters are
// all ones a URI may contain.
var absoluteURIPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$`)

// evidenceDataIsHref reports whether evidence data is carried as the observation's
// relevant-evidence href rather than in a back-matter resource.
func evidenceDataIsHref(ev *hdf.Evidence) bool {
	switch ev.Type {
	case hdf.URL:
		return true
	case hdf.Screenshot, hdf.File:
		return absoluteURIPattern.MatchString(ev.Data)
	default:
		return false
	}
}

// evidenceObservation renders a single HDF Evidence item as an OSCAL observation.
func (b *poamBuilder) evidenceObservation(ev *hdf.Evidence, appliedAt time.Time) oscal.Observation {
	obs := oscal.Observation{
		UUID:    oscal.GenerateUUID(),
		Methods: []string{"EXAMINE"},
		Types:   []string{string(ev.Type)},
	}

	display := "Supporting evidence"
	if ev.Description == nil {
		obs.Description = display
		obs.Props = append(obs.Props, oscal.AbsentFieldProp("description"))
	} else {
		obs.Description = *ev.Description
		display = displayLine(*ev.Description, display)
	}
	obs.Props = appendOptionalString(obs.Props, "mime-type", "mimeType", ev.MIMEType)
	obs.Props = appendOptionalString(obs.Props, "evidence-encoding", "encoding", ev.Encoding)
	if ev.Size != nil {
		obs.Props = oscal.AppendVocabularyProp(obs.Props, "evidence-size", string(exportmap.FloatToken(*ev.Size)))
	}
	if ev.CapturedAt != nil && !ev.CapturedAt.IsZero() {
		obs.Collected = formatTimestamp(*ev.CapturedAt)
	} else {
		obs.Collected = formatTimestamp(appliedAt)
		obs.Props = append(obs.Props, oscal.AbsentFieldProp("capturedAt"))
	}
	if ev.CapturedBy != nil {
		obs.Origins = []oscal.Origin{{Actors: []oscal.Actor{{Type: "party", ActorID: b.parties.getOrAdd(*ev.CapturedBy)}}}}
	}

	re := oscal.RelevantEvidence{Description: display}
	if evidenceDataIsHref(ev) {
		re.Href = ev.Data
	} else {
		value := base64.StdEncoding.EncodeToString([]byte(ev.Data))
		if ev.Encoding != nil && *ev.Encoding == "base64" {
			value = ev.Data
		}
		res := oscal.Resource{UUID: oscal.GenerateUUID(), Base64: &oscal.Base64{Value: value}}
		if ev.MIMEType != nil {
			res.Base64.MediaType = oscal.NormalizePropValue(*ev.MIMEType)
		}
		b.resources = append(b.resources, res)
		obs.Links = []oscal.Link{{Href: "#" + res.UUID, Rel: "evidence"}}
	}
	obs.RelevantEvidence = []oscal.RelevantEvidence{re}
	return obs
}

// cvssCharacterizations carries an HDF Cvss record as one risk characterization:
// a facet per present field in the CVSS system for its version, attributed to
// the override's applier.
func cvssCharacterizations(c *hdf.Cvss, applier string) []oscal.Characterization {
	if c == nil {
		return nil
	}
	ch := oscal.Characterization{Origin: &oscal.Origin{Actors: []oscal.Actor{{Type: "party", ActorID: applier}}}}
	system := "http://www.first.org/cvss/v" + string(c.Version)
	add := func(name, field string, value *string) {
		switch {
		case value == nil:
		case *value == "":
			ch.Props = append(ch.Props, oscal.EmptyFieldProp(field))
		default:
			facet := oscal.Facet{Name: name, System: system, Value: oscal.NormalizePropValue(*value)}
			if facet.Value != *value {
				facet.Remarks = *value
			}
			ch.Facets = append(ch.Facets, facet)
		}
	}
	score := func(name, field string, value *float64) {
		if value != nil {
			s := string(exportmap.FloatToken(*value))
			add(name, field, &s)
		}
	}
	version := string(c.Version)
	add("cvss_version", "version", &version)
	score("base_score", "baseScore", c.BaseScore)
	add("base_severity", "baseSeverity", (*string)(c.BaseSeverity))
	add("base_vector", "baseVector", c.BaseVector)
	score("threat_score", "threatScore", c.ThreatScore)
	add("threat_vector", "threatVector", c.ThreatVector)
	score("environmental_score", "environmentalScore", c.EnvironmentalScore)
	add("environmental_vector", "environmentalVector", c.EnvironmentalVector)
	score("computed_score", "computedScore", c.ComputedScore)
	add("computed_severity", "computedSeverity", (*string)(c.ComputedSeverity))
	add("supplemental_vector", "supplementalVector", c.SupplementalVector)
	add("source", "source", c.Source)
	return []oscal.Characterization{ch}
}

// referenceResource carries one external reference as a back-matter resource.
func (b *poamBuilder) referenceResource(ref *hdf.ExternalReference) (oscal.Resource, error) {
	res := oscal.Resource{UUID: oscal.GenerateUUID(), Title: ref.SourceName}
	props := oscal.AppendVocabularyProp(nil, "source-name", ref.SourceName)
	props = appendOptionalString(props, "external-id", "externalId", ref.ExternalID)
	switch {
	case ref.Href == nil:
	case *ref.Href == "":
		props = append(props, oscal.EmptyFieldProp("href"))
	default:
		res.Rlinks = []oscal.Rlink{{Href: *ref.Href}}
	}
	switch {
	case ref.Description == nil:
	case *ref.Description == "":
		props = append(props, oscal.EmptyFieldProp("description"))
	default:
		res.Description = *ref.Description
	}
	props = appendOptionalString(props, "reference-rel", "rel", ref.Rel)
	props = appendOptionalString(props, "reference-media-type", "mediaType", ref.MediaType)
	if ref.Checksum != nil {
		algorithm := string(ref.Checksum.Algorithm)
		props = appendOptionalString(props, "checksum-algorithm", "checksum.algorithm", &algorithm)
		props = appendOptionalString(props, "checksum-value", "checksum.value", &ref.Checksum.Value)
	}
	if ref.AddedBy != nil {
		props = oscal.AppendVocabularyProp(props, "added-by", b.parties.getOrAdd(*ref.AddedBy))
	}
	if ref.AddedAt != nil && !ref.AddedAt.IsZero() {
		props = oscal.AppendVocabularyProp(props, "added-at", formatTimestamp(*ref.AddedAt))
	}
	props = appendOptionalString(props, "reference-kind", "kind", ref.Kind)
	res.Props = props
	if ref.Document != nil {
		// Compact JSON with sorted object keys, byte-identical to the TypeScript peer.
		line, err := exportmap.EncodeLine(ref.Document)
		if err != nil {
			return oscal.Resource{}, fmt.Errorf("hdf-to-oscal-poam: failed to serialize an external reference document: %w", err)
		}
		res.Base64 = &oscal.Base64{MediaType: "application/json", Value: base64.StdEncoding.EncodeToString(bytes.TrimSuffix(line, []byte("\n")))}
	}
	return res, nil
}
