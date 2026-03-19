/**
 * TypeScript interfaces for OSCAL (Open Security Controls Assessment Language) documents.
 *
 * Mirrors the Go types defined in converters/oscal-to-hdf/go/types.go.
 * OSCAL defines 7 document types: catalog, profile, component-definition,
 * system-security-plan, assessment-plan, assessment-results,
 * plan-of-action-and-milestones.
 */

// ---------------------------------------------------------------------------
// Shared OSCAL JSON types (common across all 7 document models)
// ---------------------------------------------------------------------------

/** Thin wrapper used for root-key detection. Only one field will be defined. */
export interface OscalDocument {
  catalog?: Catalog;
  profile?: Profile;
  'component-definition'?: ComponentDefinition;
  'system-security-plan'?: SystemSecurityPlan;
  'assessment-plan'?: AssessmentPlan;
  'assessment-results'?: AssessmentResults;
  'plan-of-action-and-milestones'?: PlanOfActionAndMilestones;
}

// ---------------------------------------------------------------------------
// Metadata -- shared by all 7 OSCAL document types
// ---------------------------------------------------------------------------

export interface Metadata {
  title: string;
  'last-modified': string;
  version: string;
  'oscal-version': string;
  roles?: Role[];
  parties?: Party[];
  'responsible-parties'?: ResponsibleParty[];
  props?: Property[];
  links?: Link[];
  revisions?: Revision[];
  remarks?: string;
}

export interface Role {
  id: string;
  title: string;
}

export interface Party {
  uuid: string;
  type: string;
  name: string;
}

export interface ResponsibleParty {
  'role-id': string;
  'party-uuids': string[];
}

export interface Property {
  name: string;
  value: string;
  ns?: string;
  class?: string;
  uuid?: string;
}

export interface Link {
  href: string;
  rel?: string;
  'media-type'?: string;
  text?: string;
}

export interface Revision {
  title?: string;
  published?: string;
  'last-modified'?: string;
  version?: string;
  props?: Property[];
  links?: Link[];
  remarks?: string;
}

export interface BackMatter {
  resources?: Resource[];
}

export interface Resource {
  uuid: string;
  title?: string;
  description?: string;
  props?: Property[];
  rlinks?: Rlink[];
}

export interface Rlink {
  href: string;
  'media-type'?: string;
}

// ---------------------------------------------------------------------------
// Control-related types (used by Catalog, Profile, SSP, SAP, SAR)
// ---------------------------------------------------------------------------

export interface Control {
  id: string;
  class?: string;
  title: string;
  params?: Param[];
  props?: Property[];
  links?: Link[];
  parts?: Part[];
  controls?: Control[]; // nested enhancements
}

export interface Group {
  id: string;
  class?: string;
  title: string;
  props?: Property[];
  parts?: Part[];
  controls?: Control[];
  groups?: Group[]; // nested sub-groups
}

export interface Param {
  id: string;
  label?: string;
  guidelines?: Guideline[];
  constraints?: string[];
  select?: Selection;
}

export interface Guideline {
  prose?: string;
}

export interface Selection {
  'how-many'?: string;
  choice?: string[];
}

export interface Part {
  id?: string;
  name: string;
  prose?: string;
  props?: Property[];
  parts?: Part[]; // nested parts
  links?: Link[];
}

// ---------------------------------------------------------------------------
// Catalog-specific types
// ---------------------------------------------------------------------------

export interface Catalog {
  uuid: string;
  metadata: Metadata;
  groups?: Group[];
  controls?: Control[]; // top-level controls
  'back-matter'?: BackMatter;
}

// ---------------------------------------------------------------------------
// Profile-specific types
// ---------------------------------------------------------------------------

export interface Profile {
  uuid: string;
  metadata: Metadata;
  imports: Import[];
  merge?: Merge;
  modify?: Modify;
  'back-matter'?: BackMatter;
}

export interface Import {
  href: string;
  'include-controls'?: IncludeControl[];
  'exclude-controls'?: ExcludeControl[];
}

export interface IncludeControl {
  'with-ids'?: string[];
}

export interface ExcludeControl {
  'with-ids'?: string[];
}

export interface Merge {
  'as-is'?: boolean;
  custom?: string;
}

export interface Modify {
  'set-parameters'?: SetParameter[];
  alters?: Alter[];
}

export interface SetParameter {
  'param-id': string;
  values?: string[];
}

export interface Alter {
  'control-id': string;
  removes?: Remove[];
  adds?: Addition[];
}

export interface Remove {
  'by-name'?: string;
  'by-id'?: string;
}

export interface Addition {
  position?: string;
  parts?: Part[];
  props?: Property[];
}

// ---------------------------------------------------------------------------
// Component Definition types
// ---------------------------------------------------------------------------

export interface ComponentDefinition {
  uuid: string;
  metadata: Metadata;
  components?: OscalComponent[];
  'back-matter'?: BackMatter;
}

export interface OscalComponent {
  uuid: string;
  type: string;
  title: string;
  description: string;
  props?: Property[];
  'responsible-roles'?: ResponsibleRole[];
  'control-implementations'?: ControlImplementation[];
}

export interface ResponsibleRole {
  'role-id': string;
  'party-uuids'?: string[];
}

export interface ControlImplementation {
  uuid: string;
  source: string;
  description: string;
  'implemented-requirements'?: ImplementedRequirement[];
}

export interface ImplementedRequirement {
  uuid: string;
  'control-id': string;
  description?: string;
  props?: Property[];
  statements?: Statement[];
  'by-components'?: ByComponent[];
}

export interface Statement {
  'statement-id': string;
  uuid: string;
  description?: string;
  props?: Property[];
  remarks?: string;
  'by-components'?: ByComponent[];
}

export interface ByComponent {
  'component-uuid': string;
  uuid: string;
  description?: string;
  props?: Property[];
}

// ---------------------------------------------------------------------------
// System Security Plan types
// ---------------------------------------------------------------------------

export interface SystemSecurityPlan {
  uuid: string;
  metadata: Metadata;
  'import-profile'?: ImportProfile;
  'system-characteristics'?: SystemCharacteristics;
  'system-implementation'?: SystemImplementation;
  'control-implementation'?: SSPControlImpl;
  'back-matter'?: BackMatter;
}

export interface ImportProfile {
  href: string;
}

export interface SystemCharacteristics {
  'system-ids'?: SystemID[];
  'system-name': string;
  description: string;
  'security-sensitivity-level'?: string;
  props?: Property[];
  'security-impact-level'?: SecurityImpactLevel;
  'authorization-boundary'?: AuthBoundary;
  status?: SystemStatus;
}

export interface SystemID {
  'identifier-type'?: string;
  id: string;
}

export interface SecurityImpactLevel {
  'security-objective-confidentiality'?: string;
  'security-objective-integrity'?: string;
  'security-objective-availability'?: string;
}

export interface AuthBoundary {
  description?: string;
}

export interface SystemStatus {
  state: string;
  remarks?: string;
}

export interface SystemImplementation {
  users?: SystemUser[];
  components?: SystemComponent[];
}

export interface SystemUser {
  uuid: string;
  title?: string;
  props?: Property[];
}

export interface SystemComponent {
  uuid: string;
  type: string;
  title: string;
  description: string;
  props?: Property[];
  status?: ComponentStatus;
}

export interface ComponentStatus {
  state: string;
}

export interface SSPControlImpl {
  description?: string;
  'implemented-requirements'?: ImplementedRequirement[];
}

// ---------------------------------------------------------------------------
// Assessment Plan types
// ---------------------------------------------------------------------------

export interface AssessmentPlan {
  uuid: string;
  metadata: Metadata;
  'import-ssp'?: ImportSSP;
  'local-definitions'?: APLocalDefinitions;
  'terms-and-conditions'?: TermsAndConditions;
  'reviewed-controls'?: ReviewedControls;
  'assessment-subjects'?: AssessmentSubject[];
  'assessment-assets'?: AssessmentAssets;
  tasks?: Task[];
  'back-matter'?: BackMatter;
}

export interface ImportSSP {
  href: string;
}

export interface APLocalDefinitions {
  components?: SystemComponent[];
  users?: SystemUser[];
  'objectives-and-methods'?: Objective[];
  activities?: Activity[];
}

export interface Objective {
  id?: string;
  'control-id'?: string;
  description?: string;
  props?: Property[];
  parts?: Part[];
  links?: Link[];
}

export interface Activity {
  uuid: string;
  title?: string;
  description?: string;
  props?: Property[];
}

export interface TermsAndConditions {
  parts?: Part[];
}

export interface ReviewedControls {
  'control-selections'?: ControlSelection[];
  'control-objective-selections'?: ControlObjective[];
}

export interface ControlSelection {
  description?: string;
  'include-all'?: Record<string, never>;
  'include-controls'?: SelectControl[];
}

export interface ControlObjective {
  description?: string;
  'include-all'?: Record<string, never>;
  'include-objectives'?: SelectControl[];
}

export interface SelectControl {
  'control-id': string;
}

export interface AssessmentSubject {
  type: string;
  description?: string;
  'include-all'?: Record<string, never>;
  props?: Property[];
}

export interface AssessmentAssets {
  components?: SystemComponent[];
  'assessment-platforms'?: AssessmentPlatform[];
}

export interface AssessmentPlatform {
  uuid: string;
  title?: string;
  props?: Property[];
}

export interface Task {
  uuid: string;
  type: string;
  title?: string;
  description?: string;
  props?: Property[];
  timing?: Timing;
  tasks?: Task[]; // nested sub-tasks
}

export interface Timing {
  'within-date-range'?: DateRange;
}

export interface DateRange {
  start: string;
  end: string;
}

// ---------------------------------------------------------------------------
// Assessment Results types
// ---------------------------------------------------------------------------

export interface AssessmentResults {
  uuid: string;
  metadata: Metadata;
  'import-ap'?: ImportAP;
  'local-definitions'?: ARLocalDefinitions;
  results: Result[];
  'back-matter'?: BackMatter;
}

export interface ImportAP {
  href: string;
}

export interface ARLocalDefinitions {
  'objectives-and-methods'?: Objective[];
  activities?: Activity[];
}

export interface Result {
  uuid: string;
  title: string;
  description?: string;
  start: string;
  end?: string;
  props?: Property[];
  findings?: Finding[];
  observations?: Observation[];
  risks?: Risk[];
}

export interface Finding {
  uuid: string;
  title: string;
  description?: string;
  props?: Property[];
  target: FindingTarget;
  'related-observations'?: RelatedRef[];
  'related-risks'?: RelatedRef[];
}

export interface FindingTarget {
  type: string;
  'target-id': string;
  title?: string;
  description?: string;
  props?: Property[];
  status: TargetStatus;
}

export interface TargetStatus {
  state: string;
  reason?: string;
  remarks?: string;
}

export interface RelatedRef {
  'observation-uuid'?: string;
  'risk-uuid'?: string;
}

export interface Observation {
  uuid: string;
  title?: string;
  description: string;
  props?: Property[];
  methods?: string[];
  types?: string[];
  collected: string;
  expires?: string;
  remarks?: string;
  subjects?: SubjectRef[];
}

export interface SubjectRef {
  'subject-uuid': string;
  type: string;
  title?: string;
  props?: Property[];
}

// ---------------------------------------------------------------------------
// Plan of Action and Milestones types
// ---------------------------------------------------------------------------

export interface PlanOfActionAndMilestones {
  uuid: string;
  metadata: Metadata;
  'import-ssp'?: ImportSSP;
  'system-id'?: SystemID;
  'local-definitions'?: POAMLocalDefs;
  observations?: Observation[];
  risks?: Risk[];
  'poam-items': POAMItem[];
  'back-matter'?: BackMatter;
}

export interface POAMLocalDefs {
  components?: SystemComponent[];
}

export interface Risk {
  uuid: string;
  title: string;
  description: string;
  statement?: string;
  props?: Property[];
  status: string;
  characterizations?: Characterization[];
  remediations?: Remediation[];
  'risk-log'?: RiskLog;
}

export interface Characterization {
  origin?: Origin;
  facets?: Facet[];
}

export interface Origin {
  actors?: Actor[];
}

export interface Actor {
  type: string;
  'actor-uuid': string;
}

export interface Facet {
  name: string;
  system: string;
  value: string;
  props?: Property[];
}

export interface Remediation {
  uuid: string;
  lifecycle: string;
  title: string;
  description: string;
  props?: Property[];
}

/** @deprecated Use Remediation instead. */
export type OscalRemediation = Remediation;

export interface RiskLog {
  entries?: RiskLogEntry[];
}

export interface RiskLogEntry {
  uuid: string;
  title?: string;
  description?: string;
  start: string;
  'status-change'?: string;
  props?: Property[];
}

export interface POAMItem {
  uuid?: string;
  title: string;
  description: string;
  props?: Property[];
  'related-observations'?: RelatedRef[];
  'related-risks'?: RelatedRef[];
}
