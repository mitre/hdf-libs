// Package oscal converts NIST OSCAL documents to HDF format.
//
// OSCAL (Open Security Controls Assessment Language) defines 7 document types:
//   - catalog: Control definitions (e.g., NIST SP 800-53)
//   - profile: Control baselines/tailorings (e.g., FedRAMP Moderate)
//   - component-definition: Product/service security capabilities
//   - system-security-plan: System description + control implementations
//   - assessment-plan: Plan for assessing a system
//   - assessment-results: Assessment findings with pass/fail
//   - plan-of-action-and-milestones: Risk tracking + remediation plans
//
// Each type maps to either HDFResults or HDFBaseline depending on whether
// it contains assessment findings (results) or just requirements (baseline).
package oscal

// ---------------------------------------------------------------------------
// Shared OSCAL JSON types (common across all 7 document models)
// ---------------------------------------------------------------------------

// OscalDocument is a thin wrapper used for root-key detection.
// Only one field will be non-nil after unmarshaling.
type OscalDocument struct {
	Catalog                   *Catalog                   `json:"catalog,omitempty"`
	Profile                   *Profile                   `json:"profile,omitempty"`
	ComponentDefinition       *ComponentDefinition       `json:"component-definition,omitempty"`
	SystemSecurityPlan        *SystemSecurityPlan        `json:"system-security-plan,omitempty"`
	AssessmentPlan            *AssessmentPlan            `json:"assessment-plan,omitempty"`
	AssessmentResults         *AssessmentResults         `json:"assessment-results,omitempty"`
	PlanOfActionAndMilestones *PlanOfActionAndMilestones `json:"plan-of-action-and-milestones,omitempty"`
}

// DocumentType returns the OSCAL document type string, or "" if unknown.
func (d *OscalDocument) DocumentType() string {
	switch {
	case d.Catalog != nil:
		return "catalog"
	case d.Profile != nil:
		return "profile"
	case d.ComponentDefinition != nil:
		return "component-definition"
	case d.SystemSecurityPlan != nil:
		return "system-security-plan"
	case d.AssessmentPlan != nil:
		return "assessment-plan"
	case d.AssessmentResults != nil:
		return "assessment-results"
	case d.PlanOfActionAndMilestones != nil:
		return "plan-of-action-and-milestones"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Metadata — shared by all 7 OSCAL document types
// ---------------------------------------------------------------------------

// Metadata contains document-level metadata shared across all OSCAL models.
type Metadata struct {
	Title              string             `json:"title"`
	LastModified       string             `json:"last-modified"`
	Version            string             `json:"version"`
	OscalVersion       string             `json:"oscal-version"`
	Roles              []Role             `json:"roles,omitempty"`
	Parties            []Party            `json:"parties,omitempty"`
	ResponsibleParties []ResponsibleParty `json:"responsible-parties,omitempty"`
	Props              []Property         `json:"props,omitempty"`
	Links              []Link             `json:"links,omitempty"`
	Revisions          []Revision         `json:"revisions,omitempty"`
	Remarks            string             `json:"remarks,omitempty"`
}

// Role defines a responsibility or function.
type Role struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Party represents an organization or person.
type Party struct {
	UUID string `json:"uuid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// ResponsibleParty maps a role to party UUIDs.
type ResponsibleParty struct {
	RoleID   string   `json:"role-id"`
	PartyIDs []string `json:"party-uuids"`
}

// Property is a name-value pair with optional namespace and class.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Ns    string `json:"ns,omitempty"`
	Class string `json:"class,omitempty"`
	UUID  string `json:"uuid,omitempty"`
}

// Link is a reference to an external resource.
type Link struct {
	Href      string `json:"href"`
	Rel       string `json:"rel,omitempty"`
	MediaType string `json:"media-type,omitempty"`
	Text      string `json:"text,omitempty"`
}

// Revision records a version change.
type Revision struct {
	Title        string     `json:"title,omitempty"`
	Published    string     `json:"published,omitempty"`
	LastModified string     `json:"last-modified,omitempty"`
	Version      string     `json:"version,omitempty"`
	Props        []Property `json:"props,omitempty"`
	Links        []Link     `json:"links,omitempty"`
	Remarks      string     `json:"remarks,omitempty"`
}

// BackMatter contains resources referenced by the document.
type BackMatter struct {
	Resources []Resource `json:"resources,omitempty"`
}

// Resource is a citable resource with optional content.
type Resource struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Rlinks      []Rlink    `json:"rlinks,omitempty"`
}

// Rlink is a resource link (URL reference).
type Rlink struct {
	Href      string `json:"href"`
	MediaType string `json:"media-type,omitempty"`
}

// ---------------------------------------------------------------------------
// Control-related types (used by Catalog, Profile, SSP, SAP, SAR)
// ---------------------------------------------------------------------------

// Control represents a security control definition.
type Control struct {
	ID       string     `json:"id"`
	Class    string     `json:"class,omitempty"`
	Title    string     `json:"title"`
	Params   []Param    `json:"params,omitempty"`
	Props    []Property `json:"props,omitempty"`
	Links    []Link     `json:"links,omitempty"`
	Parts    []Part     `json:"parts,omitempty"`
	Controls []Control  `json:"controls,omitempty"` // nested enhancements
}

// Group organizes controls into families.
type Group struct {
	ID       string     `json:"id"`
	Class    string     `json:"class,omitempty"`
	Title    string     `json:"title"`
	Props    []Property `json:"props,omitempty"`
	Parts    []Part     `json:"parts,omitempty"`
	Controls []Control  `json:"controls,omitempty"`
	Groups   []Group    `json:"groups,omitempty"` // nested sub-groups
}

// Param is a control parameter.
type Param struct {
	ID          string      `json:"id"`
	Label       string      `json:"label,omitempty"`
	Guidelines  []Guideline `json:"guidelines,omitempty"`
	Constraints []string    `json:"constraints,omitempty"`
	Select      *Selection  `json:"select,omitempty"`
}

// Guideline provides guidance for setting a parameter.
type Guideline struct {
	Prose string `json:"prose,omitempty"`
}

// Selection defines choices for a parameter.
type Selection struct {
	HowMany string   `json:"how-many,omitempty"`
	Choice  []string `json:"choice,omitempty"`
}

// Part is a named prose section within a control.
type Part struct {
	ID    string     `json:"id,omitempty"`
	Name  string     `json:"name"`
	Prose string     `json:"prose,omitempty"`
	Props []Property `json:"props,omitempty"`
	Parts []Part     `json:"parts,omitempty"` // nested parts
	Links []Link     `json:"links,omitempty"`
}

// ---------------------------------------------------------------------------
// Catalog-specific types
// ---------------------------------------------------------------------------

// Catalog contains security control definitions.
type Catalog struct {
	UUID       string     `json:"uuid"`
	Metadata   Metadata   `json:"metadata"`
	Groups     []Group    `json:"groups,omitempty"`
	Controls   []Control  `json:"controls,omitempty"` // top-level controls
	BackMatter BackMatter `json:"back-matter"`
}

// ---------------------------------------------------------------------------
// Profile-specific types
// ---------------------------------------------------------------------------

// Profile represents a control baseline that selects/modifies catalog controls.
type Profile struct {
	UUID       string     `json:"uuid"`
	Metadata   Metadata   `json:"metadata"`
	Imports    []Import   `json:"imports"`
	Merge      *Merge     `json:"merge,omitempty"`
	Modify     *Modify    `json:"modify,omitempty"`
	BackMatter BackMatter `json:"back-matter"`
}

// Import specifies a catalog or profile to include controls from.
type Import struct {
	Href            string           `json:"href"`
	IncludeControls []IncludeControl `json:"include-controls,omitempty"`
	ExcludeControls []ExcludeControl `json:"exclude-controls,omitempty"`
}

// IncludeControl identifies controls to include by ID.
type IncludeControl struct {
	WithIDs []string `json:"with-ids,omitempty"`
}

// ExcludeControl identifies controls to exclude by ID.
type ExcludeControl struct {
	WithIDs []string `json:"with-ids,omitempty"`
}

// Merge defines how imported controls are combined.
type Merge struct {
	AsIs   bool   `json:"as-is,omitempty"`
	Custom string `json:"custom,omitempty"`
}

// Modify contains parameter settings and control alterations.
type Modify struct {
	SetParameters []SetParameter `json:"set-parameters,omitempty"`
	Alters        []Alter        `json:"alters,omitempty"`
}

// SetParameter overrides a control parameter value.
type SetParameter struct {
	ParamID string   `json:"param-id"`
	Values  []string `json:"values,omitempty"`
}

// Alter modifies a control (add/remove parts, props).
type Alter struct {
	ControlID string     `json:"control-id"`
	Removes   []Remove   `json:"removes,omitempty"`
	Adds      []Addition `json:"adds,omitempty"`
}

// Remove specifies items to remove from a control.
type Remove struct {
	ByName string `json:"by-name,omitempty"`
	ByID   string `json:"by-id,omitempty"`
}

// Addition specifies items to add to a control.
type Addition struct {
	Position string     `json:"position,omitempty"` // before, after, starting, ending
	ByID     string     `json:"by-id,omitempty"`    // target part ID for positional adds
	Parts    []Part     `json:"parts,omitempty"`
	Props    []Property `json:"props,omitempty"`
}

// ---------------------------------------------------------------------------
// Component Definition types
// ---------------------------------------------------------------------------

// ComponentDefinition describes products/services and their control satisfaction.
type ComponentDefinition struct {
	UUID       string      `json:"uuid"`
	Metadata   Metadata    `json:"metadata"`
	Components []Component `json:"components,omitempty"`
	BackMatter BackMatter  `json:"back-matter"`
}

// Component represents a product, service, or security capability.
type Component struct {
	UUID                   string                  `json:"uuid"`
	Type                   string                  `json:"type"`
	Title                  string                  `json:"title"`
	Description            string                  `json:"description"`
	Props                  []Property              `json:"props,omitempty"`
	ResponsibleRoles       []ResponsibleRole       `json:"responsible-roles,omitempty"`
	ControlImplementations []ControlImplementation `json:"control-implementations,omitempty"`
}

// ResponsibleRole maps a role to party references.
type ResponsibleRole struct {
	RoleID   string   `json:"role-id"`
	PartyIDs []string `json:"party-uuids,omitempty"`
}

// ControlImplementation describes how controls are satisfied.
type ControlImplementation struct {
	UUID                    string                   `json:"uuid"`
	Source                  string                   `json:"source"`
	Description             string                   `json:"description"`
	ImplementedRequirements []ImplementedRequirement `json:"implemented-requirements,omitempty"`
}

// ImplementedRequirement maps a control to its implementation.
type ImplementedRequirement struct {
	UUID         string        `json:"uuid"`
	ControlID    string        `json:"control-id"`
	Description  string        `json:"description,omitempty"`
	Props        []Property    `json:"props,omitempty"`
	Statements   []Statement   `json:"statements,omitempty"`
	ByComponents []ByComponent `json:"by-components,omitempty"`
}

// Statement describes how a specific control statement is implemented.
type Statement struct {
	StatementID  string        `json:"statement-id"`
	UUID         string        `json:"uuid"`
	Description  string        `json:"description,omitempty"`
	Props        []Property    `json:"props,omitempty"`
	Remarks      string        `json:"remarks,omitempty"`
	ByComponents []ByComponent `json:"by-components,omitempty"`
}

// ByComponent links a control implementation to a specific system component.
type ByComponent struct {
	ComponentUUID string     `json:"component-uuid"`
	UUID          string     `json:"uuid"`
	Description   string     `json:"description,omitempty"`
	Props         []Property `json:"props,omitempty"`
}

// ---------------------------------------------------------------------------
// System Security Plan types
// ---------------------------------------------------------------------------

// SystemSecurityPlan describes a system and its security implementation.
type SystemSecurityPlan struct {
	UUID                  string                 `json:"uuid"`
	Metadata              Metadata               `json:"metadata"`
	ImportProfile         *ImportProfile         `json:"import-profile,omitempty"`
	SystemCharacteristics *SystemCharacteristics `json:"system-characteristics,omitempty"`
	SystemImplementation  *SystemImplementation  `json:"system-implementation,omitempty"`
	ControlImplementation *SSPControlImpl        `json:"control-implementation,omitempty"`
	BackMatter            BackMatter             `json:"back-matter"`
}

// ImportProfile references the baseline profile.
type ImportProfile struct {
	Href string `json:"href"`
}

// SystemCharacteristics describes the system.
type SystemCharacteristics struct {
	SystemIDs           []SystemID           `json:"system-ids,omitempty"`
	SystemName          string               `json:"system-name"`
	Description         string               `json:"description"`
	SecuritySensLevel   *SecLevel            `json:"security-sensitivity-level,omitempty"`
	Props               []Property           `json:"props,omitempty"`
	SecurityImpactLevel *SecurityImpactLevel `json:"security-impact-level,omitempty"`
	AuthorizationBound  *AuthBoundary        `json:"authorization-boundary,omitempty"`
	Status              *SystemStatus        `json:"status,omitempty"`
}

// SystemID is a system identifier.
type SystemID struct {
	IdentifierType string `json:"identifier-type,omitempty"`
	ID             string `json:"id"`
}

// SecLevel is the security sensitivity level.
type SecLevel = string

// SecurityImpactLevel defines CIA impact levels.
type SecurityImpactLevel struct {
	Confidentiality string `json:"security-objective-confidentiality,omitempty"`
	Integrity       string `json:"security-objective-integrity,omitempty"`
	Availability    string `json:"security-objective-availability,omitempty"`
}

// AuthBoundary describes the authorization boundary.
type AuthBoundary struct {
	Description string `json:"description,omitempty"`
}

// SystemStatus represents the system operational status.
type SystemStatus struct {
	State   string `json:"state"`
	Remarks string `json:"remarks,omitempty"`
}

// SystemImplementation describes users and components.
type SystemImplementation struct {
	Users      []SystemUser      `json:"users,omitempty"`
	Components []SystemComponent `json:"components,omitempty"`
}

// SystemUser represents an authorized system user.
type SystemUser struct {
	UUID  string     `json:"uuid"`
	Title string     `json:"title,omitempty"`
	Props []Property `json:"props,omitempty"`
}

// SystemComponent represents a system component.
type SystemComponent struct {
	UUID        string           `json:"uuid"`
	Type        string           `json:"type"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Props       []Property       `json:"props,omitempty"`
	Status      *ComponentStatus `json:"status,omitempty"`
}

// ComponentStatus is the operational status of a component.
type ComponentStatus struct {
	State string `json:"state"`
}

// SSPControlImpl is the SSP-specific control implementation container.
type SSPControlImpl struct {
	Description             string                   `json:"description,omitempty"`
	ImplementedRequirements []ImplementedRequirement `json:"implemented-requirements,omitempty"`
}

// ---------------------------------------------------------------------------
// Assessment Plan types
// ---------------------------------------------------------------------------

// AssessmentPlan describes the plan for assessing a system.
type AssessmentPlan struct {
	UUID               string              `json:"uuid"`
	Metadata           Metadata            `json:"metadata"`
	ImportSSP          *ImportSSP          `json:"import-ssp,omitempty"`
	LocalDefinitions   *APLocalDefinitions `json:"local-definitions,omitempty"`
	TermsAndConditions *TermsAndConditions `json:"terms-and-conditions,omitempty"`
	ReviewedControls   *ReviewedControls   `json:"reviewed-controls,omitempty"`
	AssessmentSubjects []AssessmentSubject `json:"assessment-subjects,omitempty"`
	AssessmentAssets   *AssessmentAssets   `json:"assessment-assets,omitempty"`
	Tasks              []Task              `json:"tasks,omitempty"`
	BackMatter         BackMatter          `json:"back-matter"`
}

// ImportSSP references the system security plan.
type ImportSSP struct {
	Href string `json:"href"`
}

// APLocalDefinitions contains assessment-plan-specific local definitions.
type APLocalDefinitions struct {
	Components []SystemComponent `json:"components,omitempty"`
	Users      []SystemUser      `json:"users,omitempty"`
	Objectives []Objective       `json:"objectives-and-methods,omitempty"`
	Activities []Activity        `json:"activities,omitempty"`
}

// Objective defines a control assessment objective.
type Objective struct {
	ID          string     `json:"id,omitempty"`
	ControlID   string     `json:"control-id,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Parts       []Part     `json:"parts,omitempty"`
	Links       []Link     `json:"links,omitempty"`
}

// Activity defines an assessment activity.
type Activity struct {
	UUID        string     `json:"uuid"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
}

// TermsAndConditions describes assessment constraints.
type TermsAndConditions struct {
	Parts []Part `json:"parts,omitempty"`
}

// ReviewedControls defines the set of controls to assess.
type ReviewedControls struct {
	ControlSelections []ControlSelection `json:"control-selections,omitempty"`
	ControlObjectives []ControlObjective `json:"control-objective-selections,omitempty"`
}

// ControlSelection identifies controls included in the assessment.
type ControlSelection struct {
	Description     string          `json:"description,omitempty"`
	IncludeAll      *IncludeAll     `json:"include-all,omitempty"`
	IncludeControls []SelectControl `json:"include-controls,omitempty"`
}

// IncludeAll indicates all controls are included.
type IncludeAll struct{}

// SelectControl identifies a control by ID for selection.
type SelectControl struct {
	ControlID string `json:"control-id"`
}

// ControlObjective identifies control objectives.
type ControlObjective struct {
	Description     string          `json:"description,omitempty"`
	IncludeAll      *IncludeAll     `json:"include-all,omitempty"`
	IncludeControls []SelectControl `json:"include-objectives,omitempty"`
}

// AssessmentSubject defines what is being assessed.
type AssessmentSubject struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	IncludeAll  *IncludeAll `json:"include-all,omitempty"`
	Props       []Property  `json:"props,omitempty"`
}

// AssessmentAssets describes testing tools and platforms.
type AssessmentAssets struct {
	Components          []SystemComponent    `json:"components,omitempty"`
	AssessmentPlatforms []AssessmentPlatform `json:"assessment-platforms,omitempty"`
}

// AssessmentPlatform describes an assessment tool/platform.
type AssessmentPlatform struct {
	UUID  string     `json:"uuid"`
	Title string     `json:"title,omitempty"`
	Props []Property `json:"props,omitempty"`
}

// Task defines an assessment task.
type Task struct {
	UUID        string     `json:"uuid"`
	Type        string     `json:"type"`
	Title       string     `json:"title,omitempty"`
	Description string     `json:"description,omitempty"`
	Props       []Property `json:"props,omitempty"`
	Timing      *Timing    `json:"timing,omitempty"`
	Tasks       []Task     `json:"tasks,omitempty"` // nested sub-tasks
}

// Timing defines task scheduling.
type Timing struct {
	WithinDateRange *DateRange `json:"within-date-range,omitempty"`
}

// DateRange is a start/end date range.
type DateRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// ---------------------------------------------------------------------------
// Assessment Results types
// ---------------------------------------------------------------------------

// AssessmentResults contains findings from a security assessment.
type AssessmentResults struct {
	UUID             string              `json:"uuid"`
	Metadata         Metadata            `json:"metadata"`
	ImportAP         *ImportAP           `json:"import-ap,omitempty"`
	LocalDefinitions *ARLocalDefinitions `json:"local-definitions,omitempty"`
	Results          []Result            `json:"results"`
	BackMatter       *BackMatter         `json:"back-matter,omitempty"`
}

// ImportAP references the assessment plan.
type ImportAP struct {
	Href string `json:"href"`
}

// ARLocalDefinitions contains assessment-results-specific local definitions.
type ARLocalDefinitions struct {
	Objectives []Objective `json:"objectives-and-methods,omitempty"`
	Activities []Activity  `json:"activities,omitempty"`
}

// Result contains assessment findings for a specific assessment cycle.
type Result struct {
	UUID         string        `json:"uuid"`
	Title        string        `json:"title"`
	Description  string        `json:"description,omitempty"`
	Start        string        `json:"start"`
	End          string        `json:"end,omitempty"`
	Props        []Property    `json:"props,omitempty"`
	Findings     []Finding     `json:"findings,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	Risks        []Risk        `json:"risks,omitempty"`
}

// Finding is an assessment determination about a control.
type Finding struct {
	UUID                string        `json:"uuid"`
	Title               string        `json:"title"`
	Description         string        `json:"description,omitempty"`
	Props               []Property    `json:"props,omitempty"`
	Links               []Link        `json:"links,omitempty"`
	Target              FindingTarget `json:"target"`
	RelatedObservations []RelatedRef  `json:"related-observations,omitempty"`
	RelatedRisks        []RelatedRef  `json:"related-risks,omitempty"`
}

// FindingTarget identifies what was assessed and the result.
type FindingTarget struct {
	Type        string       `json:"type"`
	TargetID    string       `json:"target-id"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Props       []Property   `json:"props,omitempty"`
	Status      TargetStatus `json:"status"`
}

// TargetStatus is the finding status (satisfied, not-satisfied, etc.).
type TargetStatus struct {
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
	Remarks string `json:"remarks,omitempty"`
}

// RelatedRef links to an observation or risk by UUID.
type RelatedRef struct {
	ObservationUUID string `json:"observation-uuid,omitempty"`
	RiskUUID        string `json:"risk-uuid,omitempty"`
}

// Observation records evidence from the assessment.
type Observation struct {
	UUID        string       `json:"uuid"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description"`
	Props       []Property   `json:"props,omitempty"`
	Methods     []string     `json:"methods,omitempty"`
	Types       []string     `json:"types,omitempty"`
	Collected   string       `json:"collected"`
	Expires     string       `json:"expires,omitempty"`
	Remarks     string       `json:"remarks,omitempty"`
	Subjects    []SubjectRef `json:"subjects,omitempty"`
}

// SubjectRef references an assessment subject.
type SubjectRef struct {
	SubjectUUID string     `json:"subject-uuid"`
	Type        string     `json:"type"`
	Title       string     `json:"title,omitempty"`
	Props       []Property `json:"props,omitempty"`
}

// ---------------------------------------------------------------------------
// Plan of Action and Milestones types
// ---------------------------------------------------------------------------

// PlanOfActionAndMilestones tracks risks and remediation.
type PlanOfActionAndMilestones struct {
	UUID             string         `json:"uuid"`
	Metadata         Metadata       `json:"metadata"`
	ImportSSP        *ImportSSP     `json:"import-ssp,omitempty"`
	SystemID         *SystemID      `json:"system-id,omitempty"`
	LocalDefinitions *POAMLocalDefs `json:"local-definitions,omitempty"`
	Observations     []Observation  `json:"observations,omitempty"`
	Risks            []Risk         `json:"risks,omitempty"`
	POAMItems        []POAMItem     `json:"poam-items"`
	BackMatter       *BackMatter    `json:"back-matter,omitempty"`
}

// POAMLocalDefs contains POA&M-specific local definitions.
type POAMLocalDefs struct {
	Components []SystemComponent `json:"components,omitempty"`
}

// Risk describes an identified security risk.
type Risk struct {
	UUID              string             `json:"uuid"`
	Title             string             `json:"title"`
	Description       string             `json:"description"`
	Statement         string             `json:"statement,omitempty"`
	Props             []Property         `json:"props,omitempty"`
	Status            string             `json:"status"`
	Deadline          string             `json:"deadline,omitempty"`
	Characterizations []Characterization `json:"characterizations,omitempty"`
	Remediations      []Remediation      `json:"remediations,omitempty"`
	RiskLog           *RiskLog           `json:"risk-log,omitempty"`
}

// Characterization provides risk characterization details.
type Characterization struct {
	Origin *Origin `json:"origin,omitempty"`
	Facets []Facet `json:"facets,omitempty"`
}

// Origin identifies who made the characterization.
type Origin struct {
	Actors []Actor `json:"actors,omitempty"`
}

// Actor identifies an assessment actor.
type Actor struct {
	Type    string `json:"type"`
	ActorID string `json:"actor-uuid"`
}

// Facet is a risk facet (e.g., likelihood, impact).
type Facet struct {
	Name   string     `json:"name"`
	System string     `json:"system"`
	Value  string     `json:"value"`
	Props  []Property `json:"props,omitempty"`
}

// Remediation describes a risk mitigation plan.
type Remediation struct {
	UUID        string     `json:"uuid"`
	Lifecycle   string     `json:"lifecycle"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Props       []Property `json:"props,omitempty"`
	Tasks       []Task     `json:"tasks,omitempty"`
}

// RiskLog tracks risk status changes over time.
type RiskLog struct {
	Entries []RiskLogEntry `json:"entries,omitempty"`
}

// RiskLogEntry is a single risk log entry.
type RiskLogEntry struct {
	UUID         string     `json:"uuid"`
	Title        string     `json:"title,omitempty"`
	Description  string     `json:"description,omitempty"`
	Start        string     `json:"start"`
	StatusChange string     `json:"status-change,omitempty"`
	Props        []Property `json:"props,omitempty"`
}

// POAMItem tracks a specific remediation item.
type POAMItem struct {
	UUID                string       `json:"uuid,omitempty"`
	Title               string       `json:"title"`
	Description         string       `json:"description"`
	Props               []Property   `json:"props,omitempty"`
	RelatedObservations []RelatedRef `json:"related-observations,omitempty"`
	RelatedRisks        []RelatedRef `json:"related-risks,omitempty"`
}
