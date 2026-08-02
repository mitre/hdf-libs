// Code generated from JSON Schema using quicktype. DO NOT EDIT.
// To parse and unparse this JSON data, add this code to your project and do:
//
//    hDFResults, err := UnmarshalHDFResults(bytes)
//    bytes, err = hDFResults.Marshal()
//
//    hDFBaseline, err := UnmarshalHDFBaseline(bytes)
//    bytes, err = hDFBaseline.Marshal()
//
//    hDFComparison, err := UnmarshalHDFComparison(bytes)
//    bytes, err = hDFComparison.Marshal()
//
//    hDFSystem, err := UnmarshalHDFSystem(bytes)
//    bytes, err = hDFSystem.Marshal()
//
//    hDFPlan, err := UnmarshalHDFPlan(bytes)
//    bytes, err = hDFPlan.Marshal()
//
//    hDFAmendments, err := UnmarshalHDFAmendments(bytes)
//    bytes, err = hDFAmendments.Marshal()
//
//    hDFEvidencePackage, err := UnmarshalHDFEvidencePackage(bytes)
//    bytes, err = hDFEvidencePackage.Marshal()
//
//    hDFRequirementChangeEvent, err := UnmarshalHDFRequirementChangeEvent(bytes)
//    bytes, err = hDFRequirementChangeEvent.Marshal()

package hdf

import "bytes"
import "errors"
import "time"

import "encoding/json"

func UnmarshalHDFResults(data []byte) (HDFResults, error) {
	var r HDFResults
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFResults) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFBaseline(data []byte) (HDFBaseline, error) {
	var r HDFBaseline
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFBaseline) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFComparison(data []byte) (HDFComparison, error) {
	var r HDFComparison
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFComparison) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFSystem(data []byte) (HDFSystem, error) {
	var r HDFSystem
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFSystem) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFPlan(data []byte) (HDFPlan, error) {
	var r HDFPlan
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFPlan) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFAmendments(data []byte) (HDFAmendments, error) {
	var r HDFAmendments
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFAmendments) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFEvidencePackage(data []byte) (HDFEvidencePackage, error) {
	var r HDFEvidencePackage
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFEvidencePackage) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalHDFRequirementChangeEvent(data []byte) (HDFRequirementChangeEvent, error) {
	var r HDFRequirementChangeEvent
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HDFRequirementChangeEvent) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// The top level value containing all assessment results.
type HDFResults struct {
	// Information on the baselines that were evaluated, including findings.                                           
	Baselines                                                                                   []EvaluatedBaseline    `json:"baselines"`
	// The components that were assessed. Each component describes a system element (host,                             
	// container, cloud resource, application, etc.) with optional identity, SBOM, and external                        
	// references.                                                                                                     
	Components                                                                                  []Component            `json:"components,omitempty"`
	// Present ONLY on reconciled result sets: lineage recording the seed snapshot and event                           
	// watermark this document was reassembled from (ADR-0005). Documents produced directly by a                       
	// scan omit this field. When present, generator names the reconciling tool.                                       
	Derivation                                                                                  *Derivation            `json:"derivation,omitempty"`
	// Reserved for tool-specific data not defined in the HDF standard. Use this to preserve                           
	// original tool output, auxiliary data, or custom metadata.                                                       
	Extensions                                                                                  map[string]interface{} `json:"extensions,omitempty"`
	// Optional references to external artifacts (CTI/STIX, BOMs, advisories, runbooks, or any                         
	// URI-addressable artifact) relevant to this assessment as a whole. Inert context; see                            
	// External_Reference.                                                                                             
	ExternalReferences                                                                          []ExternalReference    `json:"externalReferences,omitempty"`
	// Information about the tool that generated this file.                                                            
	Generator                                                                                   *Generator             `json:"generator,omitempty"`
	// Unique identifier for this assessment run.                                                                      
	ID                                                                                          *string                `json:"id,omitempty"`
	// Cryptographic integrity information for verifying this file.                                                    
	Integrity                                                                                   *Integrity             `json:"integrity,omitempty"`
	// Reference to an hdf-plan document describing the assessment plan that produced these                            
	// results. May be a relative path, absolute URI, or fragment identifier.                                          
	PlanRef                                                                                     *string                `json:"planRef,omitempty"`
	// Optional reference to automated remediation resources (Ansible playbooks, Terraform                             
	// scripts, etc.) for fixing failing requirements found in this assessment.                                        
	Remediation                                                                                 *Remediation           `json:"remediation,omitempty"`
	// Information about the test execution environment where the security tool was run.                               
	// Distinct from targets (what is being tested).                                                                   
	Runner                                                                                      *Runner                `json:"runner,omitempty"`
	// Statistics for the assessment run, including duration and result counts.                                        
	Statistics                                                                                  *Statistics            `json:"statistics,omitempty"`
	// Reference to an hdf-system document describing the system under assessment. May be a                            
	// relative path, absolute URI, or fragment identifier.                                                            
	SystemRef                                                                                   *string                `json:"systemRef,omitempty"`
	// When this assessment was executed.                                                                              
	Timestamp                                                                                   *time.Time             `json:"timestamp,omitempty"`
	// The security tool that produced the assessment data in this file.                                               
	Tool                                                                                        *Tool                  `json:"tool,omitempty"`
}

// Information on a baseline that was evaluated, including any findings.
type EvaluatedBaseline struct {
	// The set of dependencies this baseline depends on.                                                              
	Depends                                                                                    []Dependency           `json:"depends,omitempty"`
	// The description - should be more detailed than the summary.                                                    
	Description                                                                                *string                `json:"description,omitempty"`
	// Reserved for tool-specific baseline metadata not defined in the HDF standard.                                  
	Extensions                                                                                 map[string]interface{} `json:"extensions,omitempty"`
	// A set of descriptions for the requirement groups.                                                              
	Groups                                                                                     []RequirementGroup     `json:"groups,omitempty"`
	// Typed inputs used to parameterize this baseline at execution time. See the Input                               
	// primitive for the full schema.                                                                                 
	Inputs                                                                                     []Input                `json:"inputs,omitempty"`
	// Cryptographic integrity information for verifying this baseline has not been tampered                          
	// with.                                                                                                          
	Integrity                                                                                  *Integrity             `json:"integrity,omitempty"`
	// SHA-256 checksum of the original baseline definition file (before execution). This is an                       
	// immutable reference to the baseline as defined, used to detect tampering with baseline                         
	// requirements or metadata.                                                                                      
	OriginalChecksum                                                                           *Checksum              `json:"originalChecksum,omitempty"`
	// The name of the parent baseline if this is a dependency of another.                                            
	ParentBaseline                                                                             *string                `json:"parentBaseline,omitempty"`
	// The set of requirements including any findings. A baseline must have at least one                              
	// requirement.                                                                                                   
	Requirements                                                                               []EvaluatedRequirement `json:"requirements"`
	// SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).                          
	// Used to detect tampering with test results. Compare with currentChecksum to verify                             
	// amendment integrity.                                                                                           
	ResultsChecksum                                                                            *Checksum              `json:"resultsChecksum,omitempty"`
	// An explanation of the baseline status. Example: why it was skipped, failed to load, or                         
	// any other status details.                                                                                      
	StatusMessage                                                                              *string                `json:"statusMessage,omitempty"`
	// The name - must be unique.                                                                                     
	Name                                                                                       string                 `json:"name"`
	// The copyright holder(s).                                                                                       
	Copyright                                                                                  *string                `json:"copyright,omitempty"`
	// The email address or other contact information of the copyright holder(s).                                     
	CopyrightEmail                                                                             *string                `json:"copyrightEmail,omitempty"`
	// Optional references to external artifacts relevant to this baseline (CTI/STIX,                                 
	// advisories, source catalogs, or any URI-addressable artifact). Travels with the baseline                       
	// definition. Inert context; see External_Reference.                                                             
	ExternalReferences                                                                         []ExternalReference    `json:"externalReferences,omitempty"`
	// Optional key-value labels for flexible grouping. Well-known keys: system, component,                           
	// environment, region, team. Values must be strings.                                                             
	Labels                                                                                     map[string]string      `json:"labels,omitempty"`
	// The copyright license. Example: 'Apache-2.0'.                                                                  
	License                                                                                    *string                `json:"license,omitempty"`
	// The maintainer(s).                                                                                             
	Maintainer                                                                                 *string                `json:"maintainer,omitempty"`
	// The status. Example: 'loaded'.                                                                                 
	Status                                                                                     *string                `json:"status,omitempty"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.                               
	Summary                                                                                    *string                `json:"summary,omitempty"`
	// The set of supported platform targets.                                                                         
	Supports                                                                                   []SupportedPlatform    `json:"supports,omitempty"`
	// The title - should be human readable.                                                                          
	Title                                                                                      *string                `json:"title,omitempty"`
	// The version of the baseline.                                                                                   
	Version                                                                                    *string                `json:"version,omitempty"`
}

// A dependency for a baseline. Can include relative paths or URLs for where to find the dependency.
type Dependency struct {
	// The branch name for a git repo.                                    
	Branch                                                        *string `json:"branch,omitempty"`
	// The 'user/profilename' attribute for an Automate server.           
	Compliance                                                    *string `json:"compliance,omitempty"`
	// The location of the git repo. Example:                             
	// 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git'.        
	Git                                                           *string `json:"git,omitempty"`
	// The name or assigned alias.                                        
	Name                                                          *string `json:"name,omitempty"`
	// The relative path if the dependency is locally available.          
	Path                                                          *string `json:"path,omitempty"`
	// The status. Should be: 'loaded', 'failed', or 'skipped'.           
	Status                                                        *string `json:"status,omitempty"`
	// The reason for the status if it is 'failed' or 'skipped'.          
	StatusMessage                                                 *string `json:"statusMessage,omitempty"`
	// The 'user/profilename' attribute for a Supermarket server.         
	Supermarket                                                   *string `json:"supermarket,omitempty"`
	// The address of the dependency.                                     
	URL                                                           *string `json:"url,omitempty"`
}

// A generalized reference to any external artifact by identity and/or location, modeled on the STIX
// 2.1 `external_references` common property. Purpose-agnostic: cite a CVE, an ATT&CK technique, a
// STIX bundle/object, a BOM, a runbook, or any vendor artifact — including kinds with no dedicated
// HDF reference category. `sourceName` names the system; `externalId` cites by id within that
// system; `href` locates it. `sourceName` + `externalId` is equivalently a URN
// (`urn:<sourceName>:<externalId>`, RFC 8141), so the by-identity and by-location forms stay
// interconvertible. A reference is inert context: it overrides nothing, so it carries only
// lightweight optional `addedBy`/`addedAt` attribution, never override machinery.
type ExternalReference struct {
	// When this reference was attached (RFC 3339 / trimmed-UTC per HDF timestamp convention).                         
	AddedAt                                                                                     *time.Time             `json:"addedAt,omitempty"`
	// Who attached this reference. Lightweight, flat attribution — a reference overrides                              
	// nothing, so it has no chaining/superseding/disposition.                                                         
	AddedBy                                                                                     *Identity              `json:"addedBy,omitempty"`
	// Integrity hash of the referenced artifact. Reuses the HDF `Checksum` primitive (not STIX                        
	// `hashes`). Meaningful only with a retrievable `href`.                                                           
	Checksum                                                                                    *Checksum              `json:"checksum,omitempty"`
	// Human-readable description of what is referenced. Satisfies the at-least-one rule on its                        
	// own when neither id nor href is available.                                                                      
	Description                                                                                 *string                `json:"description,omitempty"`
	// Optional lossless embedded copy of the referenced artifact — the raw STIX object, EPSS                          
	// record, advisory, or annotation payload — preserved verbatim. Composes with                                     
	// `href`/`externalId` (which point at the artifact) and `checksum` (which ties the copy to                        
	// the source): a single entry can both point and embed. HDF stays payload-agnostic — the                          
	// content is carried untouched, never normalized into HDF fields — so this does not                               
	// duplicate the source ontology (e.g. STIX rides here unchanged).                                                 
	Document                                                                                    map[string]interface{} `json:"document,omitempty"`
	// Identifier of the artifact within `sourceName` (e.g., 'CVE-2021-44228' for source 'cve',                        
	// 'T1059' for 'mitre-att&ck'). Cite by id without needing a URL. Together with `sourceName`                       
	// this is a URN.                                                                                                  
	ExternalID                                                                                  *string                `json:"externalId,omitempty"`
	// Location of the artifact. `uri-reference` (not `uri`) so a bare internal                                        
	// `#fragment`/`#uuid` reference is expressible alongside absolute URLs.                                           
	// `checksum`/`mediaType` apply only to a retrievable `href`.                                                      
	Href                                                                                        *string                `json:"href,omitempty"`
	// Open token classifying the referenced/embedded payload, turning a bare reference into an                        
	// enrichment envelope. Deliberately open (like `sourceName`/`rel`), not a closed enum.                            
	// Documented starter vocabulary: 'threat-intel' (STIX/CTI object), 'annotation' (human                            
	// triage note), 'exploitation' (EPSS/KEV signal carried as context), 'advisory'                                   
	// (vendor/security advisory). Use the `x-` prefix for custom kinds.                                               
	Kind                                                                                        *string                `json:"kind,omitempty"`
	// IANA media type of the referenced artifact when retrievable (RFC 6838), e.g.,                                   
	// 'application/json'. Meaningful only with `href`.                                                                
	MediaType                                                                                   *string                `json:"mediaType,omitempty"`
	// Open relationship token describing how this reference relates to the referencing object.                        
	// Deliberately open (cf. OSCAL `rel` allow-other, RFC 8288 extension relations). Documented                       
	// starter vocabulary: 'reference' (generic), 'definition' (defines the concept), 'evidence'                       
	// (supporting evidence), 'investigate' (a live pivot to investigate), 'canonical' (the                            
	// authoritative source).                                                                                          
	Rel                                                                                         *string                `json:"rel,omitempty"`
	// Name of the external system/source being referenced (e.g., 'cve', 'mitre-att&ck', 'stix',                       
	// 'taxii', or any vendor label). Open string — not a closed enum. Use the `x-` prefix                             
	// convention for custom/experimental sources, mirroring `bomType`.                                                
	SourceName                                                                                  string                 `json:"sourceName"`
}

// Represents an identity that performed an action, such as capturing evidence or applying an
// override.
type Identity struct {
	// Optional description of the identity or identity system, particularly useful when type is             
	// 'other'.                                                                                              
	Description                                                                                 *string      `json:"description,omitempty"`
	// The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'.                    
	Identifier                                                                                  string       `json:"identifier"`
	// The type of identifier. Use 'email' for email addresses, 'username' for user accounts,                
	// 'system' for deterministic non-interactive automation (CI jobs, cron, scanners), 'agent'              
	// for an AI/LLM agent acting with autonomy — kept distinct from 'system' so auditors can                
	// apply AI-specific scrutiny (e.g. 'an LLM proposed this' vs a deterministic job) and                   
	// satisfy AI-source disclosure under frameworks like the EU AI Act and NIST AI RMF,                     
	// 'simple' for basic string identifiers without additional classification, or 'other' for               
	// custom identity systems.                                                                              
	Type                                                                                        IdentityType `json:"type"`
}

// Cryptographic checksum for baseline integrity verification.
type Checksum struct {
	// The hash algorithm used for the checksum.              
	Algorithm                                   HashAlgorithm `json:"algorithm"`
	// The checksum value.                                    
	Value                                       string        `json:"value"`
}

// Describes a group of requirements, such as those defined in a single file.
type RequirementGroup struct {
	// The unique identifier for the group. Example: the relative path to the file specifying         
	// the requirements.                                                                              
	ID                                                                                       string   `json:"id"`
	// The set of requirements as specified by their ids in this group. Example: 'SV-238196'.         
	Requirements                                                                             []string `json:"requirements"`
	// The title of the group - should be human readable.                                             
	Title                                                                                    *string  `json:"title,omitempty"`
}

// A typed input parameter that bridges governance requirements and scanner automation. Inputs carry
// expected configuration values with type information, comparison operators, and validation
// constraints, enabling traceability from policy through to scan results.
type Input struct {
	// Validation constraints for the input value.                                                                 
	Constraints                                                                                *InputConstraints   `json:"constraints,omitempty"`
	// Human-readable description of what this input controls.                                                     
	Description                                                                                *string             `json:"description,omitempty"`
	// The input name. Must be unique within a baseline or results document. Example:                              
	// 'max_concurrent_sessions'.                                                                                  
	Name                                                                                       string              `json:"name"`
	// The comparison operator used when evaluating this input against observed values.                            
	Operator                                                                                   *ComparisonOperator `json:"operator,omitempty"`
	// Whether this input must be provided. Defaults to false if omitted.                                          
	Required                                                                                   *bool               `json:"required,omitempty"`
	// Whether this input contains sensitive data (passwords, keys). Sensitive values should be                    
	// redacted in output. Defaults to false if omitted.                                                           
	Sensitive                                                                                  *bool               `json:"sensitive,omitempty"`
	// The data type of this input.                                                                                
	Type                                                                                       *InputType          `json:"type,omitempty"`
	// The input value. Type should match the declared type field. Accepts any JSON value.                         
	Value                                                                                      interface{}         `json:"value,omitempty"`
}

// Validation constraints for an input value.
type InputConstraints struct {
	// Enumeration of permitted values.                                                  
	AllowedValues                                                          []interface{} `json:"allowedValues,omitempty"`
	// Maximum allowed value (for Numeric inputs).                                       
	Max                                                                    *float64      `json:"max,omitempty"`
	// Minimum allowed value (for Numeric inputs).                                       
	Min                                                                    *float64      `json:"min,omitempty"`
	// Regular expression pattern the value must match (for String inputs).              
	Pattern                                                                *string       `json:"pattern,omitempty"`
}

// Cryptographic integrity information for verifying the HDF file has not been tampered with. If
// algorithm is provided, checksum must also be provided, and vice versa.
type Integrity struct {
	// The hash algorithm used for the checksum.               
	Algorithm                                   *HashAlgorithm `json:"algorithm,omitempty"`
	// The checksum value.                                     
	Checksum                                    *string        `json:"checksum,omitempty"`
	// Optional cryptographic signature.                       
	Signature                                   *string        `json:"signature,omitempty"`
	// Identifier of who signed this file.                     
	SignedBy                                    *string        `json:"signedBy,omitempty"`
}

// A requirement that has been evaluated, including any findings.
type EvaluatedRequirement struct {
	// Packages affected by this vulnerability finding. Vulnerability-finding-scoped — see                              
	// components[] on hdf-system for component-level package inventories. One entry per matched                        
	// package signature (scanners often report multiple CPE variations per CVE).                                       
	AffectedPackages                                                                            []AffectedPackage       `json:"affectedPackages,omitempty"`
	// Structured CVSS scoring data for vulnerability findings. One entry per CVE — a finding                           
	// may match multiple CVEs (common in vulnerability scanners). Captures vendor-supplied Base                        
	// metrics plus optional consumer-owned Threat / Environmental / Supplemental groups for                            
	// risk adjustment. See cvss.schema.json.                                                                           
	Cvss                                                                                        []Cvss                  `json:"cvss,omitempty"`
	// Common Weakness Enumeration IDs associated with this finding. Use CWE-N format with no                           
	// leading zeros (matches the MITRE catalog convention). For NIST control mappings derived                          
	// from CWE, see tags.nist.                                                                                         
	Cwe                                                                                         []string                `json:"cwe,omitempty"`
	// Array of labeled descriptions. At least one description with label 'default' must be                             
	// present. Convention: place default description first. Common labels: 'default', 'check',                         
	// 'fix', 'rationale'.                                                                                              
	Descriptions                                                                                []Description           `json:"descriptions"`
	// The type of the most recent non-expired override or POAM governing this requirement.                             
	// Indicates why the requirement is in its current state (e.g., waiver, falsePositive,                              
	// riskAdjustment) or what remediation is being tracked (poam). Absent when no overrides or                         
	// POAMs apply.                                                                                                     
	Disposition                                                                                 *OverrideType           `json:"disposition,omitempty"`
	// Checksum of this requirement's resolved effective posture, for per-control change                                
	// detection in continuous monitoring. sha256 over the canonical JSON object with keys                              
	// status, impact, disposition (in that order), holding the resolved effective status,                              
	// resolved effective impact, and governing override type (null when nothing governs), with                         
	// override expiry anchored to the document timestamp. Flips exactly when the operative                             
	// status, impact, or disposition changes; stable under all other churn (result details,                            
	// timestamps, tags). Optional; stamped by tooling (hdf convert, hdf amend apply).                                  
	EffectiveChecksum                                                                           *Checksum               `json:"effectiveChecksum,omitempty"`
	// The current effective impact score (0.0–1.0) after applying the most recent non-expired                          
	// override with an impact field. Absent when no impact overrides apply; consumers should                           
	// use the requirement's impact field in that case.                                                                 
	EffectiveImpact                                                                             *float64                `json:"effectiveImpact,omitempty"`
	// The current effective compliance status of this requirement after applying the most                              
	// recent non-expired override with a status field, or computed from results (worst-wins) if                        
	// no status-bearing overrides exist.                                                                               
	EffectiveStatus                                                                             *ResultStatus           `json:"effectiveStatus,omitempty"`
	// FIRST.org EPSS (Exploit Prediction Scoring System) score for this CVE finding. Used                              
	// alongside CVSS for prioritization — captures the probability the vulnerability will be                           
	// exploited.                                                                                                       
	Epss                                                                                        *Epss                   `json:"epss,omitempty"`
	// Supporting evidence for this requirement's findings, such as screenshots, code samples,                          
	// or log excerpts.                                                                                                 
	Evidence                                                                                    []Evidence              `json:"evidence,omitempty"`
	// CISA Known Exploited Vulnerabilities (KEV) catalog status. When inKev=true, dateAdded and                        
	// dueDate carry the federal patching deadline.                                                                     
	Kev                                                                                         *Kev                    `json:"kev,omitempty"`
	// Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.                          
	// POAMs do NOT change effectiveStatus - they track the work being done to address a                                
	// failure. Separate from statusOverrides which DO change status.                                                   
	Poams                                                                                       []PoamElement           `json:"poams,omitempty"`
	// The set of all tests within the requirement and their results.                                                   
	Results                                                                                     []RequirementResult     `json:"results"`
	// Explicit severity rating. Typically derived from impact score but provided explicitly for                        
	// clarity.                                                                                                         
	Severity                                                                                    *Severity               `json:"severity,omitempty"`
	// The explicit location of the requirement within the source code.                                                 
	SourceLocation                                                                              *SourceLocation         `json:"sourceLocation,omitempty"`
	// Chronological history of all overrides applied to this requirement. Overrides are                                
	// intentional changes to the compliance status and/or impact score (waivers, attestations,                         
	// false positives, risk adjustments). Most recent override should be first in array.                               
	// Preserves full audit trail.                                                                                      
	StatusOverrides                                                                             []StatusOverride        `json:"statusOverrides,omitempty"`
	// The requirement identifier. Example: 'SV-238196'.                                                                
	ID                                                                                          string                  `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).                                                                      
	Impact                                                                                      float64                 `json:"impact"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.                                                    
	Tags                                                                                        map[string]interface{}  `json:"tags"`
	// Whether the requirement is mandatory within its baseline. Distinct from severity (risk                           
	// weight) and status (lifecycle state). Maps cleanly onto: FedRAMP rev5 OSCAL 'CORE' prop,                         
	// FedRAMP 20x inline 'Optional:' markers, CMMC sublevel rows, and CIS Implementation Group                         
	// memberships (IG1/IG2/IG3 may carry richer semantics; layer those onto props[]/tags{}).                           
	// Optional: when omitted, consumers should treat the requirement as 'required' by                                  
	// convention.                                                                                                      
	Applicability                                                                               *Applicability          `json:"applicability,omitempty"`
	// The raw source code of the requirement. Set to null for manual-only requirements or                              
	// requirements not yet implemented; use verificationMethod to disambiguate manual-by-design                        
	// from manual-pending-automation. Note that if this is an overlay, it does not include the                         
	// underlying source code.                                                                                          
	Code                                                                                        *string                 `json:"code,omitempty"`
	// Classification of the control's nature, aligning with NIST SP 800-53 / SP 800-53A                                
	// categories. 'policy' = an authored governance statement; 'procedure' = a documented                              
	// process; 'technical' = an enforced technical configuration; 'management' = a                                     
	// programmatic/management activity; 'operational' = a recurring operational activity (e.g.                         
	// AT, IR, MA families). Optional: when omitted, consumers may infer heuristically from                             
	// family/id but should not assume a default.                                                                       
	ControlType                                                                                 *ControlType            `json:"controlType,omitempty"`
	// Optional references to external artifacts relevant to this requirement (CTI/STIX                                 
	// correlation, advisories, control/definition sources, or any URI-addressable artifact).                           
	// Applies to both baseline requirement definitions and evaluated requirements. Inert                               
	// context; see External_Reference.                                                                                 
	ExternalReferences                                                                          []ExternalReference     `json:"externalReferences,omitempty"`
	// The set of references to external documents.                                                                     
	Refs                                                                                        []Reference             `json:"refs,omitempty"`
	// The title - is nullable.                                                                                         
	Title                                                                                       *string                 `json:"title,omitempty"`
	// How this requirement is intended to be verified. Disambiguates the two cases that null                           
	// 'code' overloads: 'manual-by-design' (the requirement is statement-form and not amenable                         
	// to automation, e.g. FedRAMP 20x KSIs); 'manual-pending-automation' (automation could                             
	// exist but does not yet, e.g. a STIG rule lacking a fix). 'automated' = a check exists and                        
	// runs without operator action; 'hybrid' = part automated, part manual. Optional: when                             
	// omitted, consumers should not infer a default.                                                                   
	VerificationMethod                                                                          *VerificationMethodEnum `json:"verificationMethod,omitempty"`
}

// Represents a package referenced by a vulnerability finding or by an amendment's scope. On
// Evaluated_Requirement.affectedPackages it says 'this CVE affects these package versions'. On
// Standalone_Override.affectedPackages it says 'this amendment is scoped to these packages' (used
// by VEX, OSCAL POA&M, FedRAMP component-aware amendments). NOT a system-level component identifier
// — see `components[]` on hdf-system for those. Validity requires at least one of: (name + version
// + ecosystem), purl alone, or cpe alone. purl and cpe are self-describing identifiers that encode
// name/version implicitly, so either may stand on its own; the name+version+ecosystem combination
// is the explicit form for sources without formal identifiers.
type AffectedPackage struct {
	// Optional CPE 2.3 URI identifying the affected product. Validated leniently: only the                
	// 'cpe:2.3:' prefix and the part-type letter ('a' application, 'h' hardware, 'o' operating            
	// system) are enforced here. Use `hdf-utilities.parseCpe` for full-grammar parsing.                   
	// Example: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*'.                                          
	Cpe                                                                                         *string    `json:"cpe,omitempty"`
	// The packaging ecosystem the package belongs to. Use 'generic' for hardware, firmware, or            
	// anything outside the listed language/OS package managers.                                           
	Ecosystem                                                                                   *Ecosystem `json:"ecosystem,omitempty"`
	// Optional version string identifying the first release that contains the fix for the                 
	// vulnerability. Use the same version syntax as `version`. Example: '1.1.1l' fixes                    
	// 'openssl@1.1.1k'.                                                                                   
	FixedInVersion                                                                              *string    `json:"fixedInVersion,omitempty"`
	// The package name as published in its ecosystem. Examples: 'openssl' (rpm), 'lodash'                 
	// (npm), 'org.apache.logging.log4j:log4j-core' (maven, group:artifact).                               
	Name                                                                                        *string    `json:"name,omitempty"`
	// Optional Package URL (PURL) identifying the affected package. Validated leniently: only             
	// the 'pkg:TYPE/' scheme prefix is enforced here, where TYPE follows the PURL grammar (a              
	// letter followed by letters, digits, '.', '+', or '-') and is matched case-insensitively             
	// to mirror `hdf-utilities.parsePurl`'s accept-and-warn behavior. Use `parsePurl` for full            
	// PURL parsing. Example: 'pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64'.                         
	Purl                                                                                        *string    `json:"purl,omitempty"`
	// The exact version of the package that the vulnerability scanner observed. Use the                   
	// ecosystem's native version string verbatim (e.g., '1.1.1k-7.el8_4' for rpm, '4.17.20' for           
	// npm).                                                                                               
	Version                                                                                     *string    `json:"version,omitempty"`
}

// A CVSS (Common Vulnerability Scoring System) score record for a vulnerability finding. Captures
// the vendor-supplied Base metric group and optional consumer-supplied Threat, Environmental, and
// Supplemental metric groups. Supports all four CVSS major versions (2.0, 3.0, 3.1, 4.0). Vector
// strings are validated against a permissive umbrella grammar; semantic validation (correct metrics
// per version, correct values per metric) is performed by the hdf-utilities `validateCvssVector`
// helper rather than at the schema layer.
type Cvss struct {
	// The Base score (0.0–10.0) computed from the base vector. Reflects the intrinsic,                       
	// vendor-published severity before consumer enrichment.                                                  
	BaseScore                                                                                   *float64      `json:"baseScore,omitempty"`
	// Qualitative severity band corresponding to baseScore. CVSS 2.0 does not natively use                   
	// 'none' or 'critical' bands; map accordingly when populating.                                           
	BaseSeverity                                                                                *CVSSSeverity `json:"baseSeverity,omitempty"`
	// Optional Base metric group vector string as emitted by the source (e.g.,                               
	// 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'). For CVSS 2.0 the version prefix is                    
	// omitted. Some vendor tools emit a final baseScore without the vector — in that case this               
	// field is absent and the score cannot be recomputed or decomposed. The pattern accepts any              
	// version-prefixed or prefix-less metric token sequence; semantic validity of individual                 
	// metrics is checked by hdf-utilities, not by the schema.                                                
	BaseVector                                                                                  *string       `json:"baseVector,omitempty"`
	// Optional final score after combining Base + Threat + Environmental metrics. This is the                
	// score consumers should treat as authoritative for risk decisions when present.                         
	ComputedScore                                                                               *float64      `json:"computedScore,omitempty"`
	// Qualitative severity band corresponding to computedScore. Same band convention as                      
	// baseSeverity.                                                                                          
	ComputedSeverity                                                                            *CVSSSeverity `json:"computedSeverity,omitempty"`
	// Optional score (0.0–10.0) recomputed after applying Environmental metrics.                             
	EnvironmentalScore                                                                          *float64      `json:"environmentalScore,omitempty"`
	// Optional Environmental metric group vector segment (e.g., 'MAV:N/CR:H/IR:H/AR:H').                     
	// Consumer-supplied — reflects the deployment context (criticality, mitigations, network                 
	// exposure).                                                                                             
	EnvironmentalVector                                                                         *string       `json:"environmentalVector,omitempty"`
	// Optional identifier the CVSS data is associated with — most commonly a CVE ID (e.g.,                   
	// 'CVE-2024-12345'), but may also be a vendor advisory ID, GHSA, or similar.                             
	Source                                                                                      *string       `json:"source,omitempty"`
	// Optional Supplemental metric group vector segment (CVSS 4.0 only). Examples:                           
	// 'S:P/AU:N/V:C/RE:M/U:Amber'. Per CVSS 4.0 spec, supplemental metrics convey additional                 
	// context but have no impact on the computed score.                                                      
	SupplementalVector                                                                          *string       `json:"supplementalVector,omitempty"`
	// Optional score (0.0–10.0) recomputed after applying Threat metrics. Always less than or                
	// equal to baseScore in practice.                                                                        
	ThreatScore                                                                                 *float64      `json:"threatScore,omitempty"`
	// Optional Threat metric group vector segment (e.g., 'E:U/RL:O/RC:C' for CVSS 3.1, or 'E:A'              
	// for CVSS 4.0). Consumer-supplied — captures real-world exploitation and remediation                    
	// context the vendor cannot know.                                                                        
	ThreatVector                                                                                *string       `json:"threatVector,omitempty"`
	// The CVSS specification version this entry conforms to. Vendor scanners typically emit 3.1              
	// or 4.0; legacy data may use 2.0 or 3.0.                                                                
	Version                                                                                     Version       `json:"version"`
}

type Description struct {
	// The description text content.                                                                   
	Data                                                                                        string `json:"data"`
	// Description category. The 'default' label is required for the primary description. Common       
	// labels: 'default', 'check', 'fix', 'rationale'. Tools may use custom labels.                    
	Label                                                                                       string `json:"label"`
}

// FIRST.org Exploit Prediction Scoring System (EPSS) data for a single vulnerability. All three
// fields are required when an Epss object is present; the date disambiguates which day's score this
// is, since EPSS recomputes daily.
type Epss struct {
	// ISO 8601 date (YYYY-MM-DD) on which FIRST.org published this EPSS score.                        
	Date                                                                                       string  `json:"date"`
	// Rank of this score relative to all scored CVEs, expressed as a value between 0.0 and 1.0        
	// inclusive. A percentile of 0.99 means this CVE is scored at or above 99% of all scored          
	// CVEs.                                                                                           
	Percentile                                                                                 float64 `json:"percentile"`
	// Exploit probability as a value between 0.0 and 1.0 inclusive. Higher values indicate            
	// greater predicted likelihood of exploitation in the next 30 days. Example: 0.97532 means        
	// roughly a 97.5% predicted probability.                                                          
	Score                                                                                      float64 `json:"score"`
}

// Supporting evidence for a finding or override, such as screenshots, code samples, log excerpts,
// or URLs.
type Evidence struct {
	// Timestamp when this evidence was captured. ISO 8601 format.                                         
	CapturedAt                                                                                *time.Time   `json:"capturedAt,omitempty"`
	// Identity of who or what captured this evidence.                                                     
	CapturedBy                                                                                *Identity    `json:"capturedBy,omitempty"`
	// The evidence content. For screenshots/files: base64-encoded data or URL. For code/logs:             
	// the raw text. For URLs: the URL string.                                                             
	Data                                                                                      string       `json:"data"`
	// Human-readable description of what this evidence shows.                                             
	Description                                                                               *string      `json:"description,omitempty"`
	// Encoding used for the data. Example: 'base64', 'utf-8'.                                             
	Encoding                                                                                  *string      `json:"encoding,omitempty"`
	// MIME type of the evidence. Example: 'image/png', 'text/plain', 'application/json'.                  
	MIMEType                                                                                  *string      `json:"mimeType,omitempty"`
	// Size of the evidence data in bytes.                                                                 
	Size                                                                                      *float64     `json:"size,omitempty"`
	// The type of evidence being provided.                                                                
	Type                                                                                      EvidenceType `json:"type"`
}

// CISA Known Exploited Vulnerabilities (KEV) catalog status. When inKev=true, dateAdded and
// dueDate carry the federal patching deadline.
type Kev struct {
	// ISO 8601 calendar date (YYYY-MM-DD) the vulnerability was added to the CISA KEV catalog.          
	// Required when inKev is true.                                                                      
	DateAdded                                                                                    *string `json:"dateAdded,omitempty"`
	// ISO 8601 calendar date (YYYY-MM-DD) by which federal agencies must remediate per CISA BOD         
	// 22-01. Normally later than dateAdded, but the schema does not enforce ordering because            
	// CISA occasionally adjusts published dates. Required when inKev is true.                           
	DueDate                                                                                      *string `json:"dueDate,omitempty"`
	// Whether this vulnerability is currently in the CISA Known Exploited Vulnerabilities               
	// catalog. When true, dateAdded and dueDate are required.                                           
	InKev                                                                                        bool    `json:"inKev"`
	// CISA's notes describing the vulnerability, observed exploitation, or remediation guidance.        
	Notes                                                                                        *string `json:"notes,omitempty"`
}

// Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
// POAMs do NOT change the effectiveStatus - the requirement remains in its current state
// while the POA&M tracks remediation efforts.
type PoamElement struct {
	// Timestamp when this POA&M was created. ISO 8601 format.                                             
	AppliedAt                                                                                  time.Time   `json:"appliedAt"`
	// Identity of who created this POA&M. For simple cases, use type 'simple' with just an                
	// identifier.                                                                                         
	AppliedBy                                                                                  Identity    `json:"appliedBy"`
	// Supporting evidence for this POA&M, such as documentation of compensating controls or               
	// mitigation implementation.                                                                          
	Evidence                                                                                   []Evidence  `json:"evidence,omitempty"`
	// Required deadline for this POA&M. A POA&M is a time-boxed acceptance of an open finding;            
	// without a deadline it lets a failing requirement duck remediation indefinitely. Source a            
	// real date (e.g. a remediation target or vendor-fix date) — never a wall-clock default.              
	// ISO 8601 format.                                                                                    
	ExpiresAt                                                                                  time.Time   `json:"expiresAt"`
	// Detailed explanation of the plan, including what actions will be taken.                             
	Explanation                                                                                string      `json:"explanation"`
	// Optional array of milestones tracking progress toward completion.                                   
	Milestones                                                                                 []Milestone `json:"milestones,omitempty"`
	// SHA-256 checksum of the previous amendment in chronological order. Creates a                        
	// tamper-evident chain of amendments (similar to blockchain). Null for the first amendment            
	// on a requirement.                                                                                   
	PreviousChecksum                                                                           *Checksum   `json:"previousChecksum,omitempty"`
	// Optional digital signature for enhanced trust and non-repudiation.                                  
	Signature                                                                                  *Signature  `json:"signature,omitempty"`
	// The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via                    
	// compensating controls. 'riskAcceptance' documents decision to accept risk.                          
	// 'vendorDependency' tracks a fix that depends on a vendor releasing a patch or update.               
	Type                                                                                       POAMType    `json:"type"`
}

// A milestone or task within a POA&M remediation plan.
type Milestone struct {
	// Actual completion timestamp. ISO 8601 format.                
	CompletedAt                                     *time.Time      `json:"completedAt,omitempty"`
	// Identity of who completed this milestone.                    
	CompletedBy                                     *Identity       `json:"completedBy,omitempty"`
	// Description of this milestone or task.                       
	Description                                     string          `json:"description"`
	// Estimated completion date. ISO 8601 format.                  
	EstimatedCompletion                             time.Time       `json:"estimatedCompletion"`
	// Current status of this milestone.                            
	Status                                          MilestoneStatus `json:"status"`
}

// A digital signature following W3C Data Integrity Proofs pattern. Supports hardware security
// tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic signing methods
// via JWK, PEM, or Base58 key formats.
type Signature struct {
	// Challenge value from the verifier, used in challenge-response authentication.                    
	Challenge                                                                        *string            `json:"challenge,omitempty"`
	// When the signature was created. ISO 8601 format.                                                 
	Created                                                                          time.Time          `json:"created"`
	// The identity that created this signature.                                                        
	Creator                                                                          Identity           `json:"creator"`
	// Domain restriction for the signature, prevents cross-domain replay attacks.                      
	Domain                                                                           *string            `json:"domain,omitempty"`
	// Random value to prevent replay attacks.                                                          
	Nonce                                                                            *string            `json:"nonce,omitempty"`
	// The purpose of this signature. Example: 'attestation', 'authentication',                         
	// 'assertionMethod'.                                                                               
	ProofPurpose                                                                     string             `json:"proofPurpose"`
	// The base64-encoded or base58-encoded signature value.                                            
	SignatureValue                                                                   string             `json:"signatureValue"`
	// The signature suite type. Example: 'JsonWebSignature2020', 'RsaSignature2018',                   
	// 'Ed25519Signature2020'.                                                                          
	Type                                                                             string             `json:"type"`
	// The verification method containing the public key for signature verification.                    
	VerificationMethod                                                               VerificationMethod `json:"verificationMethod"`
}

// Verification method containing the public key needed to verify a digital signature. Supports
// multiple key formats including JWK (for RSA, EC), PEM, and Base58.
type VerificationMethod struct {
	// The entity that controls this verification method. Can be a DID, URI, or other identifier.                       
	Controller                                                                                   string                 `json:"controller"`
	// Public key in Base58 format, commonly used with Ed25519 keys.                                                    
	PublicKeyBase58                                                                              *string                `json:"publicKeyBase58,omitempty"`
	// Public key in JSON Web Key format.                                                                               
	PublicKeyJwk                                                                                 map[string]interface{} `json:"publicKeyJwk,omitempty"`
	// Public key in PEM format. Example: '-----BEGIN PUBLIC KEY-----...-----END PUBLIC                                 
	// KEY-----'.                                                                                                       
	PublicKeyPem                                                                                 *string                `json:"publicKeyPem,omitempty"`
	// The type of verification method. Example: 'JsonWebKey2020', 'RsaVerificationKey2018',                            
	// 'Ed25519VerificationKey2020'.                                                                                    
	Type                                                                                         string                 `json:"type"`
}

// A reference to an external document.
type Reference struct {
	Ref *Ref    `json:"ref,omitempty"`
	URL *string `json:"url,omitempty"`
	URI *string `json:"uri,omitempty"`
}

// A test within a requirement and its results and findings such as how long it took to run.
type RequirementResult struct {
	// The stacktrace/backtrace of the exception if one occurred.                                        
	Backtrace                                                                               []string     `json:"backtrace,omitempty"`
	// A description of this test. Example: 'limits.conf * is expected to include ["hard",               
	// "maxlogins", "10"]'.                                                                              
	CodeDesc                                                                                string       `json:"codeDesc"`
	// The type of exception if an exception was thrown.                                                 
	Exception                                                                               *string      `json:"exception,omitempty"`
	// An explanation of the test result. Typically provided for failed tests, errors, or to             
	// explain why a test was not applicable or not reviewed.                                            
	Message                                                                                 *string      `json:"message,omitempty"`
	// The resource used in the test. Example: 'file', 'command', 'service'.                             
	Resource                                                                                *string      `json:"resource,omitempty"`
	// The unique identifier of the resource. Example: '/etc/passwd'.                                    
	ResourceID                                                                              *string      `json:"resourceId,omitempty"`
	// The execution time in seconds for the test.                                                       
	RunTime                                                                                 *float64     `json:"runTime,omitempty"`
	// The time at which the test started.                                                               
	StartTime                                                                               time.Time    `json:"startTime"`
	// The status of this test within the requirement. Example: 'failed'.                                
	Status                                                                                  ResultStatus `json:"status"`
}

// The explicit location of a requirement within source code.
type SourceLocation struct {
	// The line on which this requirement is located.                  
	Line                                                      *float64 `json:"line,omitempty"`
	// Path to the file that this requirement originates from.         
	Ref                                                       *string  `json:"ref,omitempty"`
}

// An intentional change to a requirement's compliance status and/or impact score. At least one of
// status or impact must be set. Overrides change the effectiveStatus or impact of the requirement.
// All overrides must have an expiration date to enforce periodic review.
type StatusOverride struct {
	// Timestamp when this override was applied. ISO 8601 format.                                                   
	AppliedAt                                                                                   time.Time           `json:"appliedAt"`
	// Identity of who applied this override. For simple cases, use type 'simple' with just an                      
	// identifier.                                                                                                  
	AppliedBy                                                                                   Identity            `json:"appliedBy"`
	// Structured CVSS scoring data backing this override. Captures the rubric (which                               
	// Environmental/Threat metrics the consumer modified, the recomputed score) used to justify                    
	// a riskAdjustment. For other override types this is optional context.                                         
	Cvss                                                                                        *Cvss               `json:"cvss,omitempty"`
	// Supporting evidence for this override, such as screenshots demonstrating manual                              
	// verification for attestations.                                                                               
	Evidence                                                                                    []Evidence          `json:"evidence,omitempty"`
	// Timestamp when this override expires and must be reviewed/renewed. REQUIRED - no                             
	// permanent overrides allowed. ISO 8601 format.                                                                
	ExpiresAt                                                                                   time.Time           `json:"expiresAt"`
	// Optional references to the external artifacts behind this override (e.g. the STIX                            
	// bundle/object or CTI feed motivating an E:A riskAdjustment). Inert context distinct from                     
	// `evidence`; see External_Reference. Symmetric with Standalone_Override.externalReferences                    
	// for the inline (results-embedded) override carrier.                                                          
	ExternalReferences                                                                          []ExternalReference `json:"externalReferences,omitempty"`
	// Override to the requirement's impact score. At least one of status or impact must be set.                    
	Impact                                                                                      *ImpactOverride     `json:"impact,omitempty"`
	// Structured controlled-vocabulary classification for why this override applies.                               
	// Complements (does not replace) the free-text 'reason' field. Most useful on falsePositive                    
	// and attestation overrides where the structured category enables filtering and lossless                       
	// round-trip with VEX / OSCAL / FedRAMP DR. See the Justification primitive for the                            
	// precedent vocabulary and rationale.                                                                          
	Justification                                                                               *Justification      `json:"justification,omitempty"`
	// SHA-256 checksum of the previous amendment in chronological order. Creates a                                 
	// tamper-evident chain of amendments (similar to blockchain). Null for the first amendment                     
	// on a requirement.                                                                                            
	PreviousChecksum                                                                            *Checksum           `json:"previousChecksum,omitempty"`
	// Explanation for why this override was applied.                                                               
	Reason                                                                                      string              `json:"reason"`
	// Optional digital signature for enhanced trust and non-repudiation. Supports hardware                         
	// security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing                           
	// methods.                                                                                                     
	Signature                                                                                   *Signature          `json:"signature,omitempty"`
	// The new status this override sets for the requirement. Optional when only impact is being                    
	// overridden.                                                                                                  
	Status                                                                                      *ResultStatus       `json:"status,omitempty"`
	// The type of override applied to this requirement.                                                            
	Type                                                                                        OverrideType        `json:"type"`
}

// An override to the requirement's impact score. The prior impact is the original result value or
// the preceding override in the chain.
type ImpactOverride struct {
	// The overridden impact score (0.0–1.0).        
	Value                                    float64 `json:"value"`
}

// A supported platform target. Example: the platform name being 'ubuntu'.
type SupportedPlatform struct {
	// The location of the platform. Can be: 'os', 'aws', 'azure', or 'gcp'.        
	Platform                                                                *string `json:"platform,omitempty"`
	// The platform family. Example: 'redhat'.                                      
	PlatformFamily                                                          *string `json:"platformFamily,omitempty"`
	// The platform name - can include wildcards. Example: 'debian'.                
	PlatformName                                                            *string `json:"platformName,omitempty"`
	// The release of the platform. Example: '20.04' for 'ubuntu'.                  
	Release                                                                 *string `json:"release,omitempty"`
}

// A system component. Uses discriminated union pattern with 'type' field as discriminator. Superset
// of Target with identity, external IDs, and SBOM support.
type Component struct {
	// Names of baselines that apply to this component.                                                           
	BaselineRefs                                                                                []string          `json:"baselineRefs,omitempty"`
	// Component-scoped Bills of Materials (SBOM, ai-model, dataset, or any reserved bomType),                    
	// each carried by passthrough (ref/document) or normalized. Replaces the former                              
	// sbom/sbomRef/sbomFormat trio; a component may carry several BOMs (e.g. an SBOM plus an                     
	// ai-model BOM). See primitives/bom.schema.json.                                                             
	Boms                                                                                        []BillOfMaterials `json:"boms,omitempty"`
	// Stable UUID (RFC 4122) for this component. Required in hdf-system documents, optional in                   
	// hdf-results. Enables cross-document correlation, diffing, and data flow references.                        
	ComponentID                                                                                 *string           `json:"componentId,omitempty"`
	// Description of this component's role or purpose.                                                           
	Description                                                                                 *string           `json:"description,omitempty"`
	// Map of external identifier scheme to value. Well-known schemes: aws (instance ID), azure                   
	// (resource ID), cmdb (asset ID), emass (system ID), cve (CVE ID). Custom schemes are                        
	// allowed.                                                                                                   
	ExternalIDS                                                                                 map[string]string `json:"externalIds,omitempty"`
	// System-specific overrides for baseline input values.                                                       
	InputOverrides                                                                              []InputOverride   `json:"inputOverrides,omitempty"`
	// Cryptographic integrity of this component's underlying artifact — model weights or                         
	// shards, dataset archive, container image, or package bytes. An array supports                              
	// multi-file/sharded artifacts. This is the single, generic home for artifact/subject                        
	// integrity across all component types (it replaced the former per-type Container_Image                      
	// digest and Artifact checksum fields). Distinct from BOM-document integrity (Bom.hashes[])                  
	// and from the document tamper-evidence Integrity type.                                                      
	Integrity                                                                                   []Checksum        `json:"integrity,omitempty"`
	// Optional key-value labels for flexible grouping. Well-known keys: system, component,                       
	// environment, region, team. Values must be strings.                                                         
	Labels                                                                                      map[string]string `json:"labels,omitempty"`
	// Human-readable name for this component.                                                                    
	Name                                                                                        string            `json:"name"`
	// Team or individual responsible for this component. Enables per-component ownership when                    
	// different teams manage different parts of a system.                                                        
	Owner                                                                                       *Identity         `json:"owner,omitempty"`
	// Label selector to match targets belonging to this component during migration. Targets                      
	// with matching labels are automatically included.                                                           
	TargetSelector                                                                              map[string]string `json:"targetSelector,omitempty"`
	// Component type discriminator. Same values as Target types, plus aiModel and dataset (thin                  
	// AI subject components whose detail lives in an attached ai-model / dataset BOM).                           
	Type                                                                                        TargetType        `json:"type"`
	// Directory domain the host is a member of — Active Directory / NetBIOS / LDAP domain (ECS                   
	// host.domain semantics), NOT necessarily the DNS suffix of the FQDN. A standalone or                        
	// workgroup host has a hostname but no domain. Not derivable from the FQDN; populate only                    
	// from a source that carries directory membership.                                                           
	Domain                                                                                      *string           `json:"domain,omitempty"`
	// Fully qualified domain name (e.g. 'web01.prod.example.com'). Distinct from 'hostname'                      
	// (short) and 'domain' (directory domain). ECS recommends storing this lowercase; the                        
	// schema does not enforce case so source fidelity is preserved on round-trip.                                
	FQDN                                                                                        *string           `json:"fqdn,omitempty"`
	// Short, OS-reported host name (the unqualified machine name, e.g. 'web01'). Kept distinct                   
	// from 'fqdn' because an FQDN is not reliably decomposable into hostname + domain                            
	// (standalone/workgroup hosts have no domain; a directory domain is not the FQDN's DNS                       
	// suffix). Aligns with ECS host.hostname and DISA STIG CKL HOST_NAME. Store the short name                   
	// the source reports; do not derive it from the FQDN.                                                        
	Hostname                                                                                    *string           `json:"hostname,omitempty"`
	// IP address of the host.                                                                                    
	IPAddress                                                                                   *string           `json:"ipAddress,omitempty"`
	// MAC address in colon-separated hexadecimal format.                                                         
	MACAddress                                                                                  *string           `json:"macAddress,omitempty"`
	// Operating system name.                                                                                     
	OSName                                                                                      *string           `json:"osName,omitempty"`
	// Operating system version.                                                                                  
	OSVersion                                                                                   *string           `json:"osVersion,omitempty"`
	// Container image ID.                                                                                        
	ImageID                                                                                     *string           `json:"imageId,omitempty"`
	// Container registry. Example: 'docker.io'.                                                                  
	Registry                                                                                    *string           `json:"registry,omitempty"`
	// Repository name. Example: 'library/nginx'.                                                                 
	Repository                                                                                  *string           `json:"repository,omitempty"`
	// Image tag. Example: '1.25'.                                                                                
	Tag                                                                                         *string           `json:"tag,omitempty"`
	// Running container ID.                                                                                      
	ContainerID                                                                                 *string           `json:"containerId,omitempty"`
	// Image the container was started from.                                                                      
	Image                                                                                       *string           `json:"image,omitempty"`
	// Container runtime. Example: 'docker', 'containerd', 'cri-o'.                                               
	Runtime                                                                                     *string           `json:"runtime,omitempty"`
	// Cluster name.                                                                                              
	ClusterName                                                                                 *string           `json:"clusterName,omitempty"`
	// Namespace within the cluster, if applicable.                                                               
	Namespace                                                                                   *string           `json:"namespace,omitempty"`
	// Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'.                                  
	PlatformType                                                                                *string           `json:"platformType,omitempty"`
	// Platform version.                                                                                          
	//                                                                                                            
	// Application version.                                                                                       
	//                                                                                                            
	// Package version.                                                                                           
	//                                                                                                            
	// Database version.                                                                                          
	//                                                                                                            
	// Model version, revision, or checkpoint tag.                                                                
	//                                                                                                            
	// Dataset version, release identifier, or — for highly dynamic datasets — a timestamped                      
	// release marker.                                                                                            
	Version                                                                                     *string           `json:"version,omitempty"`
	// Cloud account identifier.                                                                                  
	AccountID                                                                                   *string           `json:"accountId,omitempty"`
	// Cloud provider.                                                                                            
	Provider                                                                                    *CloudProvider    `json:"provider,omitempty"`
	// Cloud region, if applicable.                                                                               
	//                                                                                                            
	// Cloud region where the resource resides.                                                                   
	Region                                                                                      *string           `json:"region,omitempty"`
	// Amazon Resource Name (AWS only).                                                                           
	Arn                                                                                         *string           `json:"arn,omitempty"`
	// Provider-specific resource identifier.                                                                     
	ResourceID                                                                                  *string           `json:"resourceId,omitempty"`
	// Type of cloud resource. Example: 'ec2:instance', 's3:bucket'.                                              
	ResourceType                                                                                *string           `json:"resourceType,omitempty"`
	// Branch that was scanned.                                                                                   
	Branch                                                                                      *string           `json:"branch,omitempty"`
	// Commit SHA that was scanned.                                                                               
	Commit                                                                                      *string           `json:"commit,omitempty"`
	// Repository URL.                                                                                            
	//                                                                                                            
	// Application URL (for DAST tools).                                                                          
	URL                                                                                         *string           `json:"url,omitempty"`
	// Environment. Example: 'production', 'staging', 'development'.                                              
	Environment                                                                                 *string           `json:"environment,omitempty"`
	// Package manager. Example: 'npm', 'maven', 'pip', 'nuget'.                                                  
	PackageManager                                                                              *string           `json:"packageManager,omitempty"`
	// Package name.                                                                                              
	PackageName                                                                                 *string           `json:"packageName,omitempty"`
	// Network CIDR block.                                                                                        
	CIDR                                                                                        *string           `json:"cidr,omitempty"`
	// Network gateway address.                                                                                   
	Gateway                                                                                     *string           `json:"gateway,omitempty"`
	// Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'.                                        
	Engine                                                                                      *string           `json:"engine,omitempty"`
	// Database host.                                                                                             
	Host                                                                                        *string           `json:"host,omitempty"`
	// Database port.                                                                                             
	Port                                                                                        *int64            `json:"port,omitempty"`
	// Provider/registry identifier for the model. Examples: a Hugging Face repo id                               
	// ('meta-llama/Llama-2-7b-hf') or a model purl. Correlates the component to its ai-model                     
	// BOM(s) and to lineage references from other models.                                                        
	ModelID                                                                                     *string           `json:"modelId,omitempty"`
	// Provider/registry identifier for the dataset. Examples: a Hugging Face dataset repo id                     
	// ('HuggingFaceH4/ultrachat_200k'), a DOI, or a dataset purl. Correlates the component to                    
	// its dataset BOM(s) and to datasetRefs from ai-model components.                                            
	DatasetID                                                                                   *string           `json:"datasetId,omitempty"`
}

type BillOfMaterials struct {
	// The manifest kind. Determines which normalized type-extension (model/dataset/packages)                         
	// may appear.                                                                                                    
	BOMType                                                                                    string                 `json:"bomType"`
	// Normalized dataset extension. Permitted only when bomType is dataset.                                          
	Dataset                                                                                    *DatasetBOMExtension   `json:"dataset,omitempty"`
	// Passthrough by embedding: the native manifest carried opaquely (e.g. a raw CycloneDX or                        
	// SPDX object). HDF does not constrain its internal shape — full manifest validation is a                        
	// tool-level concern.                                                                                            
	Document                                                                                   map[string]interface{} `json:"document,omitempty"`
	// Source manifest format the BOM was produced from or references. Examples: cyclonedx,                           
	// cyclonedx-ml, spdx, spdx-ai, huggingface, croissant. Free-form so new formats need no                          
	// schema change; the converter that emits the BOM owns the value.                                                
	Format                                                                                     string                 `json:"format"`
	// Integrity of the carried BOM *document* itself (the referenced/embedded manifest file),                        
	// NOT the integrity of the BOM's subject artifact. Subject/artifact integrity (model                             
	// weights, dataset archive) is a component-level concern, not carried here. Subject                              
	// identity is inherited from the host component/system; per-node identity lives in the                           
	// type-extension.                                                                                                
	Hashes                                                                                     []Checksum             `json:"hashes,omitempty"`
	// Optional license of the BOM document as a whole (SPDX license expression). Nullable and                        
	// often meaningless (CBOM algorithms, many HBOM parts have no license); per-node licenses                        
	// live in the type-extension, not here.                                                                          
	License                                                                                    *string                `json:"license,omitempty"`
	// Normalized ai-model extension. Permitted only when bomType is ai-model.                                        
	Model                                                                                      *AIModelBOMExtension   `json:"model,omitempty"`
	// Normalized sbom extension: the flattened software package inventory. Permitted only when                       
	// bomType is sbom.                                                                                               
	Packages                                                                                   []SBOMPackage          `json:"packages,omitempty"`
	// Passthrough by reference: URI (relative path, absolute URI, or fragment) to the native                         
	// manifest document. Present for externally-hosted BOMs.                                                         
	Ref                                                                                        *string                `json:"ref,omitempty"`
	// Optional stable identifier for this BOM document (e.g. CycloneDX serialNumber, SPDX                            
	// documentNamespace). Correlates the same BOM across evidence packages.                                          
	UniqueID                                                                                   *string                `json:"uniqueId,omitempty"`
}

// Normalized dataset fields (SPDX 3.0 Dataset profile / MLCommons Croissant aligned). All optional;
// open for partial-fidelity passthrough of unmapped native fields. Symmetric with
// AI_Model_Extension: carries the dataset's own lineage (baseDatasetRefs/derivation) just as the
// model extension carries baseModelRef/adaptationType.
type DatasetBOMExtension struct {
	// References to the source dataset(s) this one was derived from — a dataset componentId, or                       
	// a dataset BOM uniqueId/URI when no component exists. The lineage edge parallel to                               
	// ai-model's baseModelRef; the base dataset may carry its own dataset BOM.                                        
	BaseDatasetRefs                                                                             []string               `json:"baseDatasetRefs,omitempty"`
	// Sensitivity/classification of the data. Examples: public, internal, confidential, pii,                          
	// phi.                                                                                                            
	DataClassification                                                                          *string                `json:"dataClassification,omitempty"`
	// Physical format of the dataset. Examples: parquet, csv, jsonl, tfrecord, webdataset.                            
	DatasetFormat                                                                               *string                `json:"datasetFormat,omitempty"`
	// Relationship of this dataset to baseDatasetRefs, parallel to the model extension's                              
	// adaptationType. Minimal + extensible: filtered (subset by rule), augmented                                      
	// (added/synthesized records), merged (union of sources), sampled (statistical draw).                             
	Derivation                                                                                  *DatasetDerivationType `json:"derivation,omitempty"`
	// Free-text statement of the dataset's intended use (CISA/G7 minimum element).                                    
	IntendedUse                                                                                 *string                `json:"intendedUse,omitempty"`
	// Content modality/kind of the data (CISA/G7 'Dataset content: modality'). Examples: text,                        
	// image, tabular, timeseries, audio. DISTINCT from datasetFormat, which is the physical                           
	// encoding (parquet/csv). Resolves SPDX 3.0 dataset_datasetType, which is content-kind, not                       
	// physical format. String or array of strings.                                                                    
	Modality                                                                                    *Modality              `json:"modality,omitempty"`
	// Free-text description of the dataset's origin and collection process (CISA/G7 'Dataset                          
	// provenance'; SPDX 3.0 dataset_dataCollectionProcess).                                                           
	Provenance                                                                                  *string                `json:"provenance,omitempty"`
	// Number of records/examples in the dataset.                                                                      
	RecordCount                                                                                 *int64                 `json:"recordCount,omitempty"`
	// Free-text summary of the dataset's statistical properties (CISA/G7 minimum element;                             
	// open-ended by design). Intentionally free-text and will remain so permanently:                                  
	// recordCount is the one structured statistic, and restructuring this into an object later                        
	// would break existing consumers, so it stays a string (additive-only).                                           
	StatisticalProperties                                                                       *string                `json:"statisticalProperties,omitempty"`
}

// Normalized AI-model fields, aligned to the CISA/G7 'SBOM for AI' minimum elements. All fields
// optional (standards-correct; only the EU AI Act makes a subset binding for high-risk/GPAI). Left
// open (additionalProperties: true) so a converter can carry unmapped native fields opaquely
// (partial-fidelity pattern). Subject name/version are inherited from the host aiModel component,
// not repeated here.
type AIModelBOMExtension struct {
	// Lineage relationship to baseModelRef, adopting Hugging Face's base_model_relation                             
	// vocabulary (the only typed lineage enum in the ecosystem).                                                    
	AdaptationType                                                                              *ModelAdaptationType `json:"adaptationType,omitempty"`
	// Reference to the base model this one was adapted from (e.g. a Hugging Face repo id or                         
	// purl). Correlates the lineage edge; the base model itself may carry its own ai-model BOM.                     
	BaseModelRef                                                                                *string              `json:"baseModelRef,omitempty"`
	// References to the training/evaluation datasets this model was produced from — preferably                      
	// a dataset component's componentId (correlating to a first-class dataset subject rather                        
	// than duplicating dataset detail, per ADR §10), or a dataset BOM uniqueId/URI when no                          
	// component exists.                                                                                             
	DatasetRefs                                                                                 []string             `json:"datasetRefs,omitempty"`
	// Training hyper-parameters as name/value pairs (epochs, learning-rate, batch-size). This                       
	// is the set of training knobs, NOT the model's trainable parameterCount — the two are                          
	// routinely conflated. CISA/G7 'Model properties: hyper-parameters'; SPDX 3.0                                   
	// ai_hyperparameter.                                                                                            
	Hyperparameters                                                                             []Hyperparameter     `json:"hyperparameters,omitempty"`
	// Model input/output properties (CISA/G7 minimum element): I/O data types, modality,                            
	// context/sequence length, and tokenizer. Sourced from CycloneDX                                                
	// modelParameters.inputs[].format / outputs[].format. All sub-fields optional.                                  
	InputOutput                                                                                 *InputOutput         `json:"inputOutput,omitempty"`
	// Free-text statement of intended use and out-of-scope uses (CISA/G7 minimum element).                          
	IntendedUse                                                                                 *string              `json:"intendedUse,omitempty"`
	// Model's learning/training paradigm. Free-text because the value set varies across                             
	// standards. Examples: supervised, self-supervised, semi-supervised, reinforcement.                             
	// Cross-standard intersection: SPDX 3.0 ai_typeOfModel ∩ CycloneDX                                              
	// modelParameters.approach.type ∩ CISA/G7 learning type.                                                        
	LearningApproach                                                                            *string              `json:"learningApproach,omitempty"`
	// Model architecture family. Examples: transformer, cnn, diffusion, mixture-of-experts.                         
	ModelArchitecture                                                                           *string              `json:"modelArchitecture,omitempty"`
	// Total trainable parameter count. No native CycloneDX/SPDX field exists; first-class here                      
	// because the EU AI Act keys GPAI obligations off model scale.                                                  
	ParameterCount                                                                              *int64               `json:"parameterCount,omitempty"`
	// Reported evaluation metrics as name/value pairs. Values are free-text because metrics are                     
	// heterogeneous (accuracy, f1, BLEU, latency). The item stays open (additionalProperties:                       
	// true) to carry native CycloneDX slice/confidenceInterval detail opaquely. Cross-standard                      
	// intersection: SPDX 3.0 ai_metric ∩ CycloneDX quantitativeAnalysis.performanceMetrics ∩                        
	// CISA/G7 KPI cluster.                                                                                          
	PerformanceMetrics                                                                          []PerformanceMetric  `json:"performanceMetrics,omitempty"`
	// On-disk weight serialization format. Security-critical yet under-modeled by BOM specs:                        
	// pickle/pytorch permits arbitrary code execution on load; safetensors does not. Examples:                      
	// safetensors, pytorch, gguf, onnx, tensorflow.                                                                 
	SerializationFormat                                                                         *string              `json:"serializationFormat,omitempty"`
	// The ML task the model performs. Free-text. Examples: text-classification,                                     
	// sentiment-analysis, object-detection, translation. Sourced from CycloneDX                                     
	// modelParameters.task (SPDX 3.0 ai_domain is domain-level/adjacent, not the task); CISA/G7                     
	// intended-application.                                                                                         
	Task                                                                                        *string              `json:"task,omitempty"`
}

type Hyperparameter struct {
	// Hyper-parameter name. Examples: epochs, learning-rate, batch-size.        
	Name                                                                 *string `json:"name,omitempty"`
	// Hyper-parameter value (free-text).                                        
	Value                                                                *string `json:"value,omitempty"`
}

// Model input/output properties (CISA/G7 minimum element): I/O data types, modality,
// context/sequence length, and tokenizer. Sourced from CycloneDX
// modelParameters.inputs[].format / outputs[].format. All sub-fields optional.
type InputOutput struct {
	// Maximum context/sequence length the model accepts, in tokens.                                   
	ContextLength                                                                            *int64    `json:"contextLength,omitempty"`
	// Input/output data types. Examples: string, byte[], float32, image.                              
	DataTypes                                                                                []string  `json:"dataTypes,omitempty"`
	// Input/output modalities. String or array of strings. Examples: text, image, audio.              
	// Symmetric with Dataset_Extension.modality.                                                      
	Modality                                                                                 *Modality `json:"modality,omitempty"`
	// Tokenizer used for the model's input encoding. Examples: BPE, SentencePiece, tiktoken.          
	Tokenizer                                                                                *string   `json:"tokenizer,omitempty"`
}

type PerformanceMetric struct {
	// Metric name. Examples: accuracy, f1, BLEU, latency.                                             
	Name                                                                                       *string `json:"name,omitempty"`
	// Reported metric value, free-text because metrics are heterogeneous (percentages, scores,        
	// milliseconds).                                                                                  
	Value                                                                                      *string `json:"value,omitempty"`
}

// A single normalized software package entry within an sbom BOM. Minimal identity + version for
// querying/diffing; the full native record remains available via passthrough (document/ref).
type SBOMPackage struct {
	// SPDX license identifiers/expressions for this package.                          
	Licenses                                                                  []string `json:"licenses,omitempty"`
	// Package name.                                                                   
	Name                                                                      string   `json:"name"`
	// Package URL (purl) — the preferred cross-BOM identity key when present.         
	Purl                                                                      *string  `json:"purl,omitempty"`
	// Package version.                                                                
	Version                                                                   *string  `json:"version,omitempty"`
}

// An override of a baseline input value for a specific component. Enables system-specific tailoring
// of baseline parameters.
type InputOverride struct {
	// Identity of the person or system that approved this override.                                       
	ApprovedBy                                                                                 *Identity   `json:"approvedBy,omitempty"`
	// Name of the baseline this override applies to. If omitted, applies to all baselines that            
	// define this input.                                                                                  
	BaselineRef                                                                                *string     `json:"baselineRef,omitempty"`
	// Name of the input being overridden. Must match an Input.name in the referenced baseline.            
	InputName                                                                                  string      `json:"inputName"`
	// Rationale for why this override is needed.                                                          
	Justification                                                                              *string     `json:"justification,omitempty"`
	// The overridden value. Should match the type of the original input.                                  
	Value                                                                                      interface{} `json:"value"`
}

// Derived-document lineage for a reconciled result set (an hdf-results produced by
// applyChangeEvents rather than a scanner). Records exactly which seed and event horizon the
// document represents so it can never masquerade as primary scan evidence. Conceptually PROV
// qualified derivation: derived entity, used entity (seed), activity (event application),
// generation time (asOf).
type Derivation struct {
	// The posture-as-of time of this reconciled view (RFC 3339, trimmed UTC) — the analog of           
	// PROV's generatedAtTime.                                                                          
	AsOf                                                                                      time.Time `json:"asOf"`
	// Number of change events applied to the seed to produce this document.                            
	EventsApplied                                                                             int64     `json:"eventsApplied"`
	// The authoritative snapshot this document was reassembled from, pinned by content.                
	Seed                                                                                      Seed      `json:"seed"`
	// URI of the event-stream producer context whose events were applied (matches the events'          
	// envelope source).                                                                                
	Source                                                                                    string    `json:"source"`
	// The event watermark: the highest per-key sequence number applied. Downstream precedence          
	// rule: a full-scan document supersedes the reconciled view as of its scan time; between           
	// scans, the reconciled document with the highest throughSequence is the current posture.          
	ThroughSequence                                                                           int64     `json:"throughSequence"`
}

// The authoritative snapshot this document was reassembled from, pinned by content.
type Seed struct {
	// Checksum of the seed snapshot, REQUIRED: the derivation pins an immutable snapshot by         
	// content, not just location.                                                                   
	Checksum                                                                                Checksum `json:"checksum"`
	// URI to the seed snapshot document (relative path or absolute URL).                            
	URI                                                                                     string   `json:"uri"`
}

// Information about the tool that generated this HDF file.
type Generator struct {
	// The name of the software that produced this HDF file. Example: 'gosec-to-hdf'.       
	Name                                                                             string `json:"name"`
	// The version of the tool. Example: '5.22.3'.                                          
	Version                                                                          string `json:"version"`
}

// Reference to automated remediation resources for implementing security controls. Points to
// external automation content like Ansible playbooks, Terraform scripts, or vendor-provided
// remediation tools.
type Remediation struct {
	// Optional cryptographic checksum for verifying the integrity of remediation resources            
	// fetched from the URI. Recommended for security when referencing external automation             
	// scripts.                                                                                        
	Checksum                                                                                 *Checksum `json:"checksum,omitempty"`
	// URI pointing to automated remediation resources (Ansible playbooks, Terraform scripts,          
	// etc.). Examples: GitHub repository, DISA STIG Supplemental Automation Content,                  
	// vendor-provided scripts.                                                                        
	URI                                                                                      string    `json:"uri"`
}

// Information about the test execution environment. This is distinct from the target being scanned
// - the runner is where the security tool executes, while targets are what is being assessed.
type Runner struct {
	// The CPU architecture of the runner system. Example: 'x86_64', 'arm64', 'aarch64'.                   
	Architecture                                                                                 *string   `json:"architecture,omitempty"`
	// The container instance identifier. Example: 'a1b2c3d4e5f6', 'security-scan-job-xyz123'.             
	// Can be a Docker container ID, Kubernetes pod name, or other container runtime identifier.           
	ContainerID                                                                                  *string   `json:"containerId,omitempty"`
	// The container image used for the test execution. Example: 'inspec/inspec:latest',                   
	// 'ghcr.io/my-org/scanner:v2.1.0'. Useful for CI/CD pipelines where tests run in containers.          
	ContainerImage                                                                               *string   `json:"containerImage,omitempty"`
	// The directory domain the runner system belongs to (Active Directory / NetBIOS / LDAP),              
	// NOT the DNS suffix of the FQDN. Example: 'CORP'.                                                    
	Domain                                                                                       *string   `json:"domain,omitempty"`
	// The fully qualified domain name of the runner system, when known. Distinct from the short           
	// 'hostname'; kept separate for the same reason as on host components (an FQDN is not                 
	// reliably decomposable). Example: 'ci-runner-01.build.example.com'.                                  
	FQDN                                                                                         *string   `json:"fqdn,omitempty"`
	// The short hostname of the runner system. Example: 'ci-runner-01', 'jenkins-agent-03',               
	// 'k8s-node-worker-03'.                                                                               
	Hostname                                                                                     *string   `json:"hostname,omitempty"`
	// The name of the runner environment. Examples: 'ubuntu', 'macos', 'windows', 'docker',               
	// 'kubernetes-pod', 'manual'.                                                                         
	Name                                                                                         string    `json:"name"`
	// The identity of the person or system responsible for executing the test. This could be a            
	// human auditor manually completing a checklist, an automated CI/CD system, or a security             
	// tool. Optional field to support both automated and manual HDF generation.                           
	Operator                                                                                     *Identity `json:"operator,omitempty"`
	// The version/release of the operating system or runtime. Example: '20.04', '13.2', '11'.             
	Release                                                                                      *string   `json:"release,omitempty"`
}

// Statistics for the assessment run(s) such as duration and result counts.
type Statistics struct {
	// How long (in seconds) this assessment run took.                      
	Duration                                                 *float64       `json:"duration,omitempty"`
	// Breakdowns of requirement statistics by result status.               
	Requirements                                             *StatisticHash `json:"requirements,omitempty"`
}

// Statistics for requirement results, grouped by status.
type StatisticHash struct {
	// Statistics for requirements that encountered an error during assessment.                   
	Error                                                                         *StatisticBlock `json:"error,omitempty"`
	// Statistics for requirements that failed.                                                   
	Failed                                                                        *StatisticBlock `json:"failed,omitempty"`
	// Statistics for requirements that are not applicable to the target.                         
	NotApplicable                                                                 *StatisticBlock `json:"notApplicable,omitempty"`
	// Statistics for requirements that were not reviewed (manual check required).                
	NotReviewed                                                                   *StatisticBlock `json:"notReviewed,omitempty"`
	// Statistics for requirements that passed.                                                   
	Passed                                                                        *StatisticBlock `json:"passed,omitempty"`
}

// Statistics for a given item, such as the total count.
type StatisticBlock struct {
	// The total count. Example: the total number of requirements in a given category for a run.      
	Total                                                                                       int64 `json:"total"`
}

// The security tool that produced the assessment data represented in this HDF file. Aligns with
// SARIF, OSCAL, and CycloneDX terminology.
type Tool struct {
	// The named format of the source data, when it follows a recognized format specification        
	// with its own identity: an interchange format emitted by many tools ('SARIF', 'XCCDF',         
	// 'OSCAL') or one of several named output formats a single tool produces ('FVDL',               
	// 'exec-json', 'FPF'). Never a serialization structure — 'JSON', 'XML', and 'CSV' are           
	// encodings, not formats. Omit for a tool's native output: an absent format means the           
	// tool's own shape, and data arriving as a named format is converted by that format's           
	// converter, which sets this field alongside the producing tool's name.                         
	Format                                                                                   *string `json:"format,omitempty"`
	// The name of the security tool that produced the data. Examples: 'gosec', 'Semgrep',           
	// 'OpenSCAP', 'AWS Config', 'Nessus'. Omit if the tool cannot be identified.                    
	Name                                                                                     *string `json:"name,omitempty"`
	// Version of the source tool, if available in the tool's output. Example: '5.22.3'.             
	Version                                                                                  *string `json:"version,omitempty"`
}

// Information on the set of requirements that can be assessed, including baseline metadata and
// requirement definitions.
type HDFBaseline struct {
	// The set of dependencies this baseline depends on.                                                             
	Depends                                                                                    []Dependency          `json:"depends,omitempty"`
	// The tool that generated this file.                                                                            
	Generator                                                                                  *Generator            `json:"generator,omitempty"`
	// A set of descriptions for the requirement groups.                                                             
	Groups                                                                                     []RequirementGroup    `json:"groups,omitempty"`
	// The input(s) or attribute(s) to be used in the run.                                                           
	Inputs                                                                                     []Input               `json:"inputs,omitempty"`
	// Cryptographic integrity information for verifying this baseline has not been tampered                         
	// with.                                                                                                         
	Integrity                                                                                  *Integrity            `json:"integrity,omitempty"`
	// Optional reference to automated remediation resources (Ansible playbooks, Terraform                           
	// scripts, etc.) for implementing the security controls defined in this baseline.                               
	Remediation                                                                                *Remediation          `json:"remediation,omitempty"`
	// The set of requirements - contains no findings as the assessment has not yet occurred.                        
	Requirements                                                                               []BaselineRequirement `json:"requirements"`
	// The name - must be unique.                                                                                    
	Name                                                                                       string                `json:"name"`
	// The copyright holder(s).                                                                                      
	Copyright                                                                                  *string               `json:"copyright,omitempty"`
	// The email address or other contact information of the copyright holder(s).                                    
	CopyrightEmail                                                                             *string               `json:"copyrightEmail,omitempty"`
	// Optional references to external artifacts relevant to this baseline (CTI/STIX,                                
	// advisories, source catalogs, or any URI-addressable artifact). Travels with the baseline                      
	// definition. Inert context; see External_Reference.                                                            
	ExternalReferences                                                                         []ExternalReference   `json:"externalReferences,omitempty"`
	// Optional key-value labels for flexible grouping. Well-known keys: system, component,                          
	// environment, region, team. Values must be strings.                                                            
	Labels                                                                                     map[string]string     `json:"labels,omitempty"`
	// The copyright license. Example: 'Apache-2.0'.                                                                 
	License                                                                                    *string               `json:"license,omitempty"`
	// The maintainer(s).                                                                                            
	Maintainer                                                                                 *string               `json:"maintainer,omitempty"`
	// The status. Example: 'loaded'.                                                                                
	Status                                                                                     *string               `json:"status,omitempty"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.                              
	Summary                                                                                    *string               `json:"summary,omitempty"`
	// The set of supported platform targets.                                                                        
	Supports                                                                                   []SupportedPlatform   `json:"supports,omitempty"`
	// The title - should be human readable.                                                                         
	Title                                                                                      *string               `json:"title,omitempty"`
	// The version of the baseline.                                                                                  
	Version                                                                                    *string               `json:"version,omitempty"`
}

// A requirement definition without assessment results.
type BaselineRequirement struct {
	// Array of labeled descriptions. At least one description with label 'default' must be                             
	// present. Convention: place default description first. Common labels: 'default', 'check',                         
	// 'fix', 'rationale'.                                                                                              
	Descriptions                                                                                []Description           `json:"descriptions"`
	// Explicit severity rating. Typically derived from impact score but provided explicitly for                        
	// clarity.                                                                                                         
	Severity                                                                                    *Severity               `json:"severity,omitempty"`
	// The requirement identifier. Example: 'SV-238196'.                                                                
	ID                                                                                          string                  `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).                                                                      
	Impact                                                                                      float64                 `json:"impact"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.                                                    
	Tags                                                                                        map[string]interface{}  `json:"tags"`
	// Whether the requirement is mandatory within its baseline. Distinct from severity (risk                           
	// weight) and status (lifecycle state). Maps cleanly onto: FedRAMP rev5 OSCAL 'CORE' prop,                         
	// FedRAMP 20x inline 'Optional:' markers, CMMC sublevel rows, and CIS Implementation Group                         
	// memberships (IG1/IG2/IG3 may carry richer semantics; layer those onto props[]/tags{}).                           
	// Optional: when omitted, consumers should treat the requirement as 'required' by                                  
	// convention.                                                                                                      
	Applicability                                                                               *Applicability          `json:"applicability,omitempty"`
	// The raw source code of the requirement. Set to null for manual-only requirements or                              
	// requirements not yet implemented; use verificationMethod to disambiguate manual-by-design                        
	// from manual-pending-automation. Note that if this is an overlay, it does not include the                         
	// underlying source code.                                                                                          
	Code                                                                                        *string                 `json:"code,omitempty"`
	// Classification of the control's nature, aligning with NIST SP 800-53 / SP 800-53A                                
	// categories. 'policy' = an authored governance statement; 'procedure' = a documented                              
	// process; 'technical' = an enforced technical configuration; 'management' = a                                     
	// programmatic/management activity; 'operational' = a recurring operational activity (e.g.                         
	// AT, IR, MA families). Optional: when omitted, consumers may infer heuristically from                             
	// family/id but should not assume a default.                                                                       
	ControlType                                                                                 *ControlType            `json:"controlType,omitempty"`
	// Optional references to external artifacts relevant to this requirement (CTI/STIX                                 
	// correlation, advisories, control/definition sources, or any URI-addressable artifact).                           
	// Applies to both baseline requirement definitions and evaluated requirements. Inert                               
	// context; see External_Reference.                                                                                 
	ExternalReferences                                                                          []ExternalReference     `json:"externalReferences,omitempty"`
	// The set of references to external documents.                                                                     
	Refs                                                                                        []Reference             `json:"refs,omitempty"`
	// The explicit location of the requirement within the source code.                                                 
	SourceLocation                                                                              *SourceLocation         `json:"sourceLocation,omitempty"`
	// The title - is nullable.                                                                                         
	Title                                                                                       *string                 `json:"title,omitempty"`
	// How this requirement is intended to be verified. Disambiguates the two cases that null                           
	// 'code' overloads: 'manual-by-design' (the requirement is statement-form and not amenable                         
	// to automation, e.g. FedRAMP 20x KSIs); 'manual-pending-automation' (automation could                             
	// exist but does not yet, e.g. a STIG rule lacking a fix). 'automated' = a check exists and                        
	// runs without operator action; 'hybrid' = part automated, part manual. Optional: when                             
	// omitted, consumers should not infer a default.                                                                   
	VerificationMethod                                                                          *VerificationMethodEnum `json:"verificationMethod,omitempty"`
}

// Structured comparison between two or more HDF security assessment documents. Supports temporal,
// baseline, fleet, and multi-source comparison modes.
type HDFComparison struct {
	// Map of annotation IDs to annotation objects, providing context or action items for                              
	// requirement diffs.                                                                                              
	Annotations                                                                                 map[string]Annotation  `json:"annotations,omitempty"`
	// Comparison of baselines between sources.                                                                        
	BaselineDiffs                                                                               []BaselineDiff         `json:"baselineDiffs,omitempty"`
	// The mode of comparison being performed.                                                                         
	ComparisonMode                                                                              ComparisonMode         `json:"comparisonMode"`
	// Comparison of components between two system documents. Used in systemDrift mode. A                              
	// component's BOM changes surface as a field change on its boms[] here.                                           
	ComponentDiffs                                                                              []ComponentDiff        `json:"componentDiffs,omitempty"`
	// External/metadata changes separate from status changes (Terraform pattern).                                     
	Drift                                                                                       []RequirementDiff      `json:"drift,omitempty"`
	// Reserved for tool-specific data not defined in the HDF standard.                                                
	Extensions                                                                                  map[string]interface{} `json:"extensions,omitempty"`
	// Optional references to external artifacts relevant to this comparison (CTI/STIX,                                
	// advisories, or any URI-addressable artifact). Inert context; see External_Reference.                            
	ExternalReferences                                                                          []ExternalReference    `json:"externalReferences,omitempty"`
	// Schema version for this comparison format.                                                                      
	FormatVersion                                                                               FormatVersion          `json:"formatVersion"`
	// Information about the tool that generated this comparison.                                                      
	Generator                                                                                   *Generator             `json:"generator,omitempty"`
	// Cryptographic integrity information for verifying this comparison document.                                     
	Integrity                                                                                   *Integrity             `json:"integrity,omitempty"`
	// Configuration for how requirements were matched across sources.                                                 
	Matching                                                                                    *MatchingConfig        `json:"matching,omitempty"`
	// RESERVED — not emitted by the current systemDrift comparison. systemDrift now reports a                         
	// component's BOM changes as a field change on its boms[] (see componentDiffs), and                               
	// standalone SBOM package diffing is a separate `hdf diff <sbom> <sbom>` output shape. This                       
	// field is retained for a future normalized package-level diff; consumers must not expect                         
	// it from today's systemDrift output.                                                                             
	PackageDiffs                                                                                []PackageDiff          `json:"packageDiffs,omitempty"`
	// Detailed comparison of individual requirements between sources.                                                 
	RequirementDiffs                                                                            []RequirementDiff      `json:"requirementDiffs"`
	// The source documents being compared. At least two sources are required.                                         
	Sources                                                                                     []Source               `json:"sources"`
	// Summary statistics for the overall comparison.                                                                  
	Summary                                                                                     ComparisonSummary      `json:"summary"`
	// URI identifying the system being compared in systemDrift mode.                                                  
	SystemRef                                                                                   *string                `json:"systemRef,omitempty"`
	// When this comparison was performed.                                                                             
	Timestamp                                                                                   *time.Time             `json:"timestamp,omitempty"`
}

// An annotation attached to a comparison, providing context or action items.
type Annotation struct {
	// The category of this annotation.                                                            
	Category                                                                   *AnnotationCategory `json:"category,omitempty"`
	// Detailed description of the annotation.                                                     
	Description                                                                *string             `json:"description,omitempty"`
	// Human-readable label for this annotation.                                                   
	Label                                                                      string              `json:"label"`
	// Whether this annotation requires human confirmation before acting on it.                    
	NeedsConfirmation                                                          *bool               `json:"needsConfirmation,omitempty"`
}

// Comparison of a baseline between sources.
type BaselineDiff struct {
	// The source of any ID mapping used to correlate requirements across baseline versions.                  
	MappingSource                                                                           *string           `json:"mappingSource,omitempty"`
	// Name of the baseline being compared.                                                                   
	Name                                                                                    string            `json:"name"`
	// Version of the baseline in the new source.                                                             
	NewVersion                                                                              *string           `json:"newVersion,omitempty"`
	// Version of the baseline in the old source.                                                             
	OldVersion                                                                              *string           `json:"oldVersion,omitempty"`
	// The state of this baseline in the comparison.                                                          
	State                                                                                   BaselineDiffState `json:"state"`
}

// Comparison of a single component between two system document versions.
type ComponentDiff struct {
	// Component snapshot from the new system document. Null when state is 'absent'.                   
	After                                                                            interface{}       `json:"after,omitempty"`
	// Component snapshot from the old system document. Null when state is 'new'.                      
	Before                                                                           interface{}       `json:"before,omitempty"`
	// Detailed field-level changes between the before and after component snapshots.                  
	FieldChanges                                                                     []FieldChange     `json:"fieldChanges,omitempty"`
	// Component name used for matching across system versions.                                        
	Name                                                                             string            `json:"name"`
	// The state of this component in the comparison.                                                  
	State                                                                            BaselineDiffState `json:"state"`
}

// A single field-level change between two versions of a requirement.
type FieldChange struct {
	// The new value of the field (for 'add' and 'replace' operations).                    
	NewValue                                                                   interface{} `json:"newValue,omitempty"`
	// The previous value of the field (for 'remove' and 'replace' operations).            
	OldValue                                                                   interface{} `json:"oldValue,omitempty"`
	// The type of change operation.                                                       
	Op                                                                         Op          `json:"op"`
	// JSON Pointer path to the changed field.                                             
	Path                                                                       string      `json:"path"`
}

// A comparison of a single requirement between sources, including state, changes, and full
// before/after snapshots.
type RequirementDiff struct {
	// The requirement as it appeared in the new source. Null when state is 'absent'.                                   
	After                                                                                        interface{}            `json:"after"`
	// Sensitive data from the new source that should not be included in the main after snapshot.                       
	AfterSensitive                                                                               map[string]interface{} `json:"afterSensitive,omitempty"`
	// IDs of annotations attached to this requirement diff.                                                            
	AnnotationIDS                                                                                []string               `json:"annotationIds,omitempty"`
	// The requirement as it appeared in the old/reference source. Null when state is 'new'.                            
	Before                                                                                       interface{}            `json:"before"`
	// Sensitive data from the old source that should not be included in the main before                                
	// snapshot.                                                                                                        
	BeforeSensitive                                                                              map[string]interface{} `json:"beforeSensitive,omitempty"`
	// The reasons for the state change.                                                                                
	ChangeReasons                                                                                []ChangeReason         `json:"changeReasons"`
	// Conflicts between multiple scanner results for this requirement.                                                 
	Conflicts                                                                                    []ScannerConflict      `json:"conflicts,omitempty"`
	// Detailed field-level changes between the before and after versions.                                              
	FieldChanges                                                                                 []FieldChange          `json:"fieldChanges"`
	// The canonical requirement identifier used for this diff.                                                         
	ID                                                                                           string                 `json:"id"`
	// Confidence score for the match (0-1).                                                                            
	MatchConfidence                                                                              *float64               `json:"matchConfidence,omitempty"`
	// Whether the match was manually confirmed by a human.                                                             
	MatchManual                                                                                  *bool                  `json:"matchManual,omitempty"`
	// The strategy that was used to match this requirement across sources.                                             
	MatchStrategy                                                                                *MatchStrategy         `json:"matchStrategy,omitempty"`
	// The effective status of the requirement in the new source.                                                       
	NewEffectiveStatus                                                                           *string                `json:"newEffectiveStatus,omitempty"`
	// The requirement ID in the new source, if different from the canonical id.                                        
	NewID                                                                                        *string                `json:"newId,omitempty"`
	// The impact score of the requirement in the new source (0-1).                                                     
	NewImpact                                                                                    *float64               `json:"newImpact,omitempty"`
	// The effective status of the requirement in the old source.                                                       
	OldEffectiveStatus                                                                           *string                `json:"oldEffectiveStatus,omitempty"`
	// The requirement ID in the old source, if different from the canonical id.                                        
	OldID                                                                                        *string                `json:"oldId,omitempty"`
	// The impact score of the requirement in the old source (0-1).                                                     
	OldImpact                                                                                    *float64               `json:"oldImpact,omitempty"`
	// Index into the sources array for multi-source comparisons.                                                       
	SourceIndex                                                                                  *int64                 `json:"sourceIndex,omitempty"`
	// The state of this requirement in the comparison.                                                                 
	State                                                                                        RequirementState       `json:"state"`
	// The requirement title for human readability.                                                                     
	Title                                                                                        *string                `json:"title,omitempty"`
}

// A conflict between scanner results for the same requirement.
type ScannerConflict struct {
	// The field where the conflict occurs.                                             
	Field                                                           string              `json:"field"`
	// How the conflict was resolved.                                                   
	Resolution                                                      *ConflictResolution `json:"resolution,omitempty"`
	// Index of the source whose value was chosen as the resolution.                    
	ResolvedIndex                                                   *int64              `json:"resolvedIndex,omitempty"`
	// The conflicting values from each source.                                         
	Values                                                          []Value             `json:"values"`
}

type Value struct {
	// Zero-based index into the sources array.                                
	SourceIndex                                                    int64       `json:"sourceIndex"`
	// Human-readable label for the source.                                    
	SourceLabel                                                    string      `json:"sourceLabel"`
	// The value reported by this source for the conflicting field.            
	Value                                                          interface{} `json:"value"`
}

// Configuration for how requirements are matched across sources.
type MatchingConfig struct {
	// Ordered list of fallback strategies tried when the primary strategy fails to find a match.                
	FallbackStrategies                                                                           []MatchStrategy `json:"fallbackStrategies,omitempty"`
	// Fields used to compute a fingerprint for fuzzy matching.                                                  
	FingerprintFields                                                                            []string        `json:"fingerprintFields,omitempty"`
	// URI pointing to an external mapping table used for ID translation.                                        
	MappingTableURI                                                                              *string         `json:"mappingTableUri,omitempty"`
	// Minimum confidence score (0-1) required to accept a match.                                                
	MinimumConfidence                                                                            *float64        `json:"minimumConfidence,omitempty"`
	// The primary strategy used to match requirements across sources.                                           
	PrimaryStrategy                                                                              MatchStrategy   `json:"primaryStrategy"`
}

// Comparison of a single BOM node between two BOM versions, matched by purl (software) or
// identifier (models, datasets, hardware, crypto).
type PackageDiff struct {
	// Generic identity key for matching a BOM node across versions when no purl applies — e.g.                 
	// a Hugging Face model ref, dataset uniqueId, crypto algorithm OID, or hardware part                       
	// number. At least one of purl or identifier is required.                                                  
	Identifier                                                                                 *string          `json:"identifier,omitempty"`
	// License identifiers for this package.                                                                    
	Licenses                                                                                   []string         `json:"licenses,omitempty"`
	// Human-readable node name.                                                                                
	Name                                                                                       *string          `json:"name,omitempty"`
	// Package version in the new SBOM.                                                                         
	NewVersion                                                                                 *string          `json:"newVersion,omitempty"`
	// Package version in the old SBOM.                                                                         
	OldVersion                                                                                 *string          `json:"oldVersion,omitempty"`
	// Package URL (purl) — the preferred identity key for matching software packages across                    
	// BOMs. Optional: BOM nodes without a purl (AI models, datasets, hardware parts, crypto                    
	// algorithms) key on identifier instead.                                                                   
	Purl                                                                                       *string          `json:"purl,omitempty"`
	// The state of this package: added (new in new SBOM), removed (absent from new SBOM),                      
	// updated (version changed), unchanged.                                                                    
	State                                                                                      PackageDiffState `json:"state"`
}

// A source document participating in the comparison.
type Source struct {
	// When the source assessment was performed. ISO 8601 format.                               
	AssessmentTimestamp                                                         *time.Time      `json:"assessmentTimestamp,omitempty"`
	// Reference to the baseline used in this source assessment.                                
	BaselineRef                                                                 *BaselineRef    `json:"baselineRef,omitempty"`
	// Cryptographic checksum of the source document for integrity verification.                
	Checksum                                                                    *Checksum       `json:"checksum,omitempty"`
	// The components assessed in this source.                                                  
	Components                                                                  []Component     `json:"components,omitempty"`
	// Human-readable label for this source. Example: 'Before remediation scan'.                
	Label                                                                       string          `json:"label"`
	// The original format of the source document before conversion to HDF.                     
	OriginalFormat                                                              *OriginalFormat `json:"originalFormat,omitempty"`
	// The role of this source in the comparison.                                               
	Role                                                                        SourceRole      `json:"role"`
	// The security tool that produced the assessment data in this source.                      
	Tool                                                                        *Tool           `json:"tool,omitempty"`
	// URI pointing to the source document.                                                     
	URI                                                                         *string         `json:"uri,omitempty"`
}

// Reference to the baseline used in this source assessment.
type BaselineRef struct {
	// Name of the baseline used in this source.           
	Name                                           string  `json:"name"`
	// Version of the baseline used in this source.        
	Version                                        *string `json:"version,omitempty"`
}

// Summary statistics for the overall comparison.
type ComparisonSummary struct {
	// Number of requirements present only in the old source.                                        
	Absent                                                                        *int64             `json:"absent,omitempty"`
	// Average confidence score across all requirement matches (0-1).                                
	AverageMatchConfidence                                                        *float64           `json:"averageMatchConfidence,omitempty"`
	// State counts broken down by severity level.                                                   
	BySeverity                                                                    *SeverityBreakdown `json:"bySeverity,omitempty"`
	// Change in compliance percentage (new - old).                                                  
	ComplianceDelta                                                               *float64           `json:"complianceDelta,omitempty"`
	// Number of requirements that changed from failing to passing.                                  
	Fixed                                                                         *int64             `json:"fixed,omitempty"`
	// Number of requirements successfully matched between sources.                                  
	MatchedCount                                                                  int64              `json:"matchedCount"`
	// Number of requirements that were reorganized without content change.                          
	Moved                                                                         *int64             `json:"moved,omitempty"`
	// Number of requirements present only in the new source.                                        
	New                                                                           *int64             `json:"new,omitempty"`
	// Compliance percentage of the new source (0-100).                                              
	NewCompliancePercent                                                          *float64           `json:"newCompliancePercent,omitempty"`
	// Compliance percentage of the old source (0-100).                                              
	OldCompliancePercent                                                          *float64           `json:"oldCompliancePercent,omitempty"`
	// Summary statistics for each individual source in a multi-source comparison.                   
	PerSource                                                                     []PerSourceSummary `json:"perSource,omitempty"`
	// Number of requirements that changed from passing to failing.                                  
	Regressed                                                                     *int64             `json:"regressed,omitempty"`
	// Total number of unique requirements across all sources.                                       
	Total                                                                         int64              `json:"total"`
	// Number of requirements with the same effective status.                                        
	Unchanged                                                                     *int64             `json:"unchanged,omitempty"`
	// Number of requirements in the new source with no match in the old source.                     
	UnmatchedNewCount                                                             int64              `json:"unmatchedNewCount"`
	// Number of requirements in the old source with no match in the new source.                     
	UnmatchedOldCount                                                             int64              `json:"unmatchedOldCount"`
	// Number of requirements with a generic status change.                                          
	Updated                                                                       *int64             `json:"updated,omitempty"`
}

// Breakdown of state counts by severity level.
type SeverityBreakdown struct {
	// State counts for critical severity requirements.             
	Critical                                           *StateCounts `json:"critical,omitempty"`
	// State counts for high severity requirements.                 
	High                                               *StateCounts `json:"high,omitempty"`
	// State counts for low severity requirements.                  
	Low                                                *StateCounts `json:"low,omitempty"`
	// State counts for medium severity requirements.               
	Medium                                             *StateCounts `json:"medium,omitempty"`
}

// Counts of requirements in each state.
type StateCounts struct {
	// Number of requirements present only in the old source.                     
	Absent                                                                 *int64 `json:"absent,omitempty"`
	// Number of requirements that changed from failing to passing.               
	Fixed                                                                  *int64 `json:"fixed,omitempty"`
	// Number of requirements that were reorganized without content change.       
	Moved                                                                  *int64 `json:"moved,omitempty"`
	// Number of requirements present only in the new source.                     
	New                                                                    *int64 `json:"new,omitempty"`
	// Number of requirements that changed from passing to failing.               
	Regressed                                                              *int64 `json:"regressed,omitempty"`
	// Number of requirements with the same effective status.                     
	Unchanged                                                              *int64 `json:"unchanged,omitempty"`
	// Number of requirements with a generic status change.                       
	Updated                                                                *int64 `json:"updated,omitempty"`
}

// Summary statistics for a single source in a multi-source comparison.
type PerSourceSummary struct {
	// Number of requirements present only in the old source.                                      
	Absent                                                                                  *int64 `json:"absent,omitempty"`
	// Number of requirements that changed from failing to passing.                                
	Fixed                                                                                   *int64 `json:"fixed,omitempty"`
	// Human-readable label for this source.                                                       
	Label                                                                                   string `json:"label"`
	// Number of requirements that were reorganized without content change.                        
	Moved                                                                                   *int64 `json:"moved,omitempty"`
	// Number of requirements present only in the new source.                                      
	New                                                                                     *int64 `json:"new,omitempty"`
	// Number of requirements that changed from passing to failing.                                
	Regressed                                                                               *int64 `json:"regressed,omitempty"`
	// Zero-based index into the sources array identifying which source this summary is for.       
	SourceIndex                                                                             int64  `json:"sourceIndex"`
	// Number of requirements with the same effective status.                                      
	Unchanged                                                                               *int64 `json:"unchanged,omitempty"`
	// Number of requirements with a generic status change.                                        
	Updated                                                                                 *int64 `json:"updated,omitempty"`
}

// Describes a system's authorization boundary, components, and interconnections. Maps to OSCAL SSP
// system-characteristics and FedRAMP system inventory.
type HDFSystem struct {
	// Date the current authorization status was granted. ISO 8601 format.                                           
	AuthorizationDate                                                                           *time.Time           `json:"authorizationDate,omitempty"`
	// Current Authorization to Operate (ATO) status.                                                                
	AuthorizationStatus                                                                         *AuthorizationStatus `json:"authorizationStatus,omitempty"`
	// System-scoped Bills of Materials whose subject is the authorization boundary rather than                      
	// a single component (e.g. a SaaSBOM of services, a KBOM of cluster inventory, an OBOM).                        
	// Component-scoped BOMs (SBOM, ai-model) attach on the component instead. See                                   
	// primitives/bom.schema.json.                                                                                   
	Boms                                                                                        []BillOfMaterials    `json:"boms,omitempty"`
	// Description of the system's authorization boundary. Example: network CIDR blocks, cloud                       
	// VPC IDs, physical locations.                                                                                  
	BoundaryDescription                                                                         *string              `json:"boundaryDescription,omitempty"`
	// FIPS 199 security categorization (impact level).                                                              
	CategorizationLevel                                                                         *CategorizationLevel `json:"categorizationLevel,omitempty"`
	// System components within the authorization boundary. Uses the full polymorphic Component                      
	// type with stable identity (componentId), external references, and generalized BOM                             
	// attachment (boms[]).                                                                                          
	Components                                                                                  []Component          `json:"components"`
	// Declares which controls are common, hybrid, or system-specific, and which component                           
	// provides them. Maps to NIST SP 800-53 control designations and OSCAL                                          
	// leveraged-authorizations.                                                                                     
	ControlDesignations                                                                         []ControlDesignation `json:"controlDesignations,omitempty"`
	// Inter-component data flows describing how components communicate. Supports local,                             
	// cross-system, and external flows. Replaces the interconnections[] field.                                      
	DataFlows                                                                                   []DataFlow           `json:"dataFlows,omitempty"`
	// Description of the system's purpose and mission.                                                              
	Description                                                                                 *string              `json:"description,omitempty"`
	// Optional references to external artifacts describing this system's threat environment or                      
	// context (CTI/STIX, BOMs, advisories, or any URI-addressable artifact). Inert context; see                     
	// External_Reference.                                                                                           
	ExternalReferences                                                                          []ExternalReference  `json:"externalReferences,omitempty"`
	// Information about the tool that generated this system document.                                               
	Generator                                                                                   *Generator           `json:"generator,omitempty"`
	// System identifier from an authoritative source. Example: eMASS system ID, FedRAMP package                     
	// ID.                                                                                                           
	Identifier                                                                                  *string              `json:"identifier,omitempty"`
	// URI identifying the scheme of the system identifier. Example: 'https://emass.mil',                            
	// 'https://fedramp.gov'.                                                                                        
	IdentifierScheme                                                                            *string              `json:"identifierScheme,omitempty"`
	// Cryptographic integrity information for verifying this system document has not been                           
	// tampered with.                                                                                                
	Integrity                                                                                   *Integrity           `json:"integrity,omitempty"`
	// Optional key-value labels for grouping and querying systems.                                                  
	Labels                                                                                      map[string]string    `json:"labels,omitempty"`
	// Human-readable system name. Example: 'Enterprise Portal Production'.                                          
	Name                                                                                        string               `json:"name"`
	// Team or individual responsible for this system's authorization and compliance. Maps to                        
	// OSCAL responsible-party with role 'system-owner'.                                                             
	Owner                                                                                       *Identity            `json:"owner,omitempty"`
	// Stable UUID (RFC 4122) for this system. Enables cross-document correlation independent of                     
	// file location. Optional in casual use, expected in production documents.                                      
	SystemID                                                                                    *string              `json:"systemId,omitempty"`
	// Version of this system document.                                                                              
	Version                                                                                     *string              `json:"version,omitempty"`
}

// Declares a control's designation within a system — whether it is common (provided by another
// component or system), system-specific (implemented locally), or hybrid (shared responsibility).
// Maps to NIST SP 800-53 Appendix C control designations and OSCAL SSP by-component
// provided/inherited semantics.
type ControlDesignation struct {
	// The control identifier (e.g., 'SC-7', 'AC-2 (1)'). Must match a NIST tag in a baseline               
	// requirement's tags.                                                                                  
	ControlID                                                                                   string      `json:"controlId"`
	// Justification for this designation — who provides the control, why it's inherited, and               
	// any relevant authorization references.                                                               
	Description                                                                                 string      `json:"description"`
	// NIST SP 800-53 control designation. 'common': fully provided by another component or                 
	// system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':                
	// shared responsibility between provider and inheritor.                                                
	Designation                                                                                 Designation `json:"designation"`
	// componentIds that inherit this control. If omitted, all components in the system inherit             
	// it.                                                                                                  
	InheritedBy                                                                                 []string    `json:"inheritedBy,omitempty"`
	// componentId of a local component that provides this control. Omit when the provider is an            
	// external system.                                                                                     
	ProvidedBy                                                                                  *string     `json:"providedBy,omitempty"`
	// Reference to another hdf-system document whose component provides this control. Use when             
	// the provider is in a different system. Omit when the provider is local.                              
	SystemRef                                                                                   *string     `json:"systemRef,omitempty"`
}

// A data flow between two endpoints. The 'from' endpoint is always a local component; the 'to'
// endpoint can be local, cross-system, or external. Use 'direction' to indicate whether data flows
// one-way or both ways.
type DataFlow struct {
	// Authentication mechanism used for this connection. Examples: 'mTLS', 'OAuth2', 'API key',            
	// 'SAML', 'Kerberos'.                                                                                  
	Authentication                                                                              *string     `json:"authentication,omitempty"`
	// Human-readable description of this data flow's purpose and the data exchanged.                       
	Description                                                                                 *string     `json:"description,omitempty"`
	// Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'                 
	// means data flows in both directions (e.g., request/response).                                        
	Direction                                                                                   *Direction  `json:"direction,omitempty"`
	// UUID of the local component that is one end of this data flow. Always references a                   
	// component in the current system document.                                                            
	From                                                                                        string      `json:"from"`
	// Network port number.                                                                                 
	Port                                                                                        *int64      `json:"port,omitempty"`
	// Communication protocol. Examples: 'http', 'https', 'grpc', 'ssh', 'jdbc', 'k8s-api',                 
	// 'socket', 'sftp'.                                                                                    
	Protocol                                                                                    *string     `json:"protocol,omitempty"`
	// The other end of this data flow. Can be a local component (UUID), a cross-system                     
	// component reference, or an external endpoint.                                                        
	To                                                                                          interface{} `json:"to"`
}

// Defines an assessment plan — what baselines to run against which targets, with resolved inputs
// and scheduling. Maps to OSCAL Assessment Plan.
type HDFPlan struct {
	// The assessments to perform. Each assessment pairs a baseline with targets and resolved                       
	// inputs.                                                                                                      
	Assessments                                                                                 []Assessment        `json:"assessments"`
	// Description of the plan's purpose and scope.                                                                 
	Description                                                                                 *string             `json:"description,omitempty"`
	// Optional references to external artifacts relevant to this assessment plan (CTI/STIX,                        
	// advisories, methodology docs, or any URI-addressable artifact). Inert context; see                           
	// External_Reference.                                                                                          
	ExternalReferences                                                                          []ExternalReference `json:"externalReferences,omitempty"`
	// Information about the tool that generated this plan.                                                         
	Generator                                                                                   *Generator          `json:"generator,omitempty"`
	// Cryptographic integrity information for verifying this plan document has not been                            
	// tampered with.                                                                                               
	Integrity                                                                                   *Integrity          `json:"integrity,omitempty"`
	// Optional key-value labels for grouping and querying plans.                                                   
	Labels                                                                                      map[string]string   `json:"labels,omitempty"`
	// Human-readable plan name. Example: 'Portal Monthly Assessment'.                                              
	Name                                                                                        string              `json:"name"`
	// Unique identifier for this plan. Optional in casual use, expected in production                              
	// documents. Auto-generated if omitted during creation.                                                        
	PlanID                                                                                      *string             `json:"planId,omitempty"`
	// Optional scheduling configuration for recurring assessments.                                                 
	Schedule                                                                                    *Schedule           `json:"schedule,omitempty"`
	// URI to the hdf-system document this plan targets. Example: 'portal-prod.hdf-system.json'.                    
	SystemRef                                                                                   *string             `json:"systemRef,omitempty"`
	// The type of assessment plan.                                                                                 
	Type                                                                                        *PlanType           `json:"type,omitempty"`
	// Version of this plan document.                                                                               
	Version                                                                                     *string             `json:"version,omitempty"`
}

// A single assessment within a plan — defines which baseline to run against which targets with what
// configuration.
type Assessment struct {
	// Reference to the baseline to evaluate. May be a baseline name (e.g. 'RHEL9-STIG'), a                         
	// relative path to an HDF Baseline document (e.g. 'rhel9-stig.hdf-baseline.json'), or an                       
	// absolute URI.                                                                                                
	BaselineRef                                                                              string                 `json:"baselineRef"`
	// componentId of the system component this assessment targets. Use for direct component                        
	// binding. Alternative to targetSelector.                                                                      
	ComponentRef                                                                             *string                `json:"componentRef,omitempty"`
	// Description of this assessment's purpose.                                                                    
	Description                                                                              *string                `json:"description,omitempty"`
	// Resolved input values for this assessment. Keys are input names, values are the final                        
	// resolved values (after baseline defaults + system overrides).                                                
	Inputs                                                                                   map[string]interface{} `json:"inputs,omitempty"`
	// Runner/scanner configuration for this assessment.                                                            
	Runner                                                                                   *RunnerConfig          `json:"runner,omitempty"`
	// Label selector to match targets for this assessment. Overrides the system component's                        
	// targetSelector if provided.                                                                                  
	TargetSelector                                                                           map[string]string      `json:"targetSelector,omitempty"`
}

// Configuration for the assessment runner/scanner.
type RunnerConfig struct {
	// Name of the assessment runner. Example: 'cinc-auditor', 'inspec', 'openscap'.        
	Name                                                                            *string `json:"name,omitempty"`
	// Version of the runner.                                                               
	Version                                                                         *string `json:"version,omitempty"`
}

// Scheduling configuration for recurring assessments.
type Schedule struct {
	// Cron expression for recurring assessments. Example: '0 2 1 * *' (2 AM on the 1st of each           
	// month).                                                                                            
	Cron                                                                                       *string    `json:"cron,omitempty"`
	// Date after which assessments should no longer run. ISO 8601 format.                                
	EndDate                                                                                    *time.Time `json:"endDate,omitempty"`
	// Email addresses or notification endpoints to alert when assessments complete.                      
	NotifyOnCompletion                                                                         []string   `json:"notifyOnCompletion,omitempty"`
	// Email addresses or notification endpoints to alert when regressions are detected.                  
	NotifyOnRegression                                                                         []string   `json:"notifyOnRegression,omitempty"`
	// Earliest date to begin assessments. ISO 8601 format.                                               
	StartDate                                                                                  *time.Time `json:"startDate,omitempty"`
}

// Waivers, attestations, and POA&Ms that modify requirement compliance status or impact. Amendments
// are standalone documents that can be applied to results via merge operations.
type HDFAmendments struct {
	// Unique identifier for this amendments document. Useful for cross-referencing when                           
	// multiple amendment documents target the same results.                                                       
	AmendmentID                                                                               *string              `json:"amendmentId,omitempty"`
	// Default identity of who created this amendments document. Individual overrides may                          
	// specify their own appliedBy.                                                                                
	AppliedBy                                                                                 *Identity            `json:"appliedBy,omitempty"`
	// Identity of the authorizing official who approved these amendments.                                         
	ApprovedBy                                                                                *Identity            `json:"approvedBy,omitempty"`
	// Description of the amendments' purpose and scope.                                                           
	Description                                                                               *string              `json:"description,omitempty"`
	// Information about the tool that generated this document.                                                    
	Generator                                                                                 *Generator           `json:"generator,omitempty"`
	// Cryptographic integrity information for verifying this amendments document has not been                     
	// tampered with.                                                                                              
	Integrity                                                                                 *Integrity           `json:"integrity,omitempty"`
	// Optional key-value labels for grouping and querying amendments.                                             
	Labels                                                                                    map[string]string    `json:"labels,omitempty"`
	// Human-readable name for this amendments document. Example: 'Portal Q1 2026 Waivers'.                        
	Name                                                                                      string               `json:"name"`
	// The set of amendments (waivers, attestations, POA&Ms, and other overrides).                                 
	Overrides                                                                                 []StandaloneOverride `json:"overrides"`
	// Document-level digital signature covering all amendments.                                                   
	Signature                                                                                 *Signature           `json:"signature,omitempty"`
	// URI to the hdf-system document these amendments apply to.                                                   
	SystemRef                                                                                 *string              `json:"systemRef,omitempty"`
	// Version of this amendments document.                                                                        
	Version                                                                                   *string              `json:"version,omitempty"`
}

// A standalone override to a requirement's compliance status or risk impact. Validation has two
// branches gated on 'type': when type is 'operationalRequirement', neither 'status' nor 'impact'
// may be set — the override records accepted risk without changing the finding
// (documentation-only). For all other types, at least one of 'status' or 'impact' must be set. This
// rule aligns with: (1) OSCAL Assessment Results — finding.target.status and
// finding.associated-risk[].facet[] are separate axes
// (https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/); (2) FedRAMP
// deviation request types — Risk Adjustment changes impact only, Operational Requirement documents
// acceptance only, False Positive changes status
// (https://www.ignyteplatform.com/blog/fedramp/fedramp-deviation-requests-submit/); (3) NIST SP
// 800-37 RMF — risk response (accept/mitigate/transfer) is a separate step from control assessment
// status (https://csrc.nist.gov/pubs/sp/800/37/r2/final).
type StandaloneOverride struct {
	// Software packages this amendment is scoped to, distinct from componentRef (which scopes                      
	// to an HDF-internal Component by UUID). Use when the source amendment format references                       
	// packages by purl/cpe/name+version — e.g., VEX `affects[]` / `products[]`, OSCAL POA&M                        
	// `subjects[]`, FedRAMP component-aware amendments. Symmetric with                                             
	// Evaluated_Requirement.affectedPackages, which scopes findings to the same package                            
	// vocabulary. When omitted, the amendment applies system-wide (or only to componentRef when                    
	// that is set).                                                                                                
	AffectedPackages                                                                            []AffectedPackage   `json:"affectedPackages,omitempty"`
	// When this amendment was applied. ISO 8601 format.                                                            
	AppliedAt                                                                                   time.Time           `json:"appliedAt"`
	// Identity of who applied this amendment.                                                                      
	AppliedBy                                                                                   Identity            `json:"appliedBy"`
	// Name of the baseline containing the requirement. Required when the system has multiple                       
	// baselines with potentially overlapping requirement IDs.                                                      
	BaselineRef                                                                                 *string             `json:"baselineRef,omitempty"`
	// componentId of the component this amendment is scoped to. When set, the amendment only                       
	// applies to the specified component. When omitted, the amendment applies system-wide.                         
	ComponentRef                                                                                *string             `json:"componentRef,omitempty"`
	// Structured CVSS scoring data backing this override. Captures the rubric (which                               
	// Environmental/Threat metrics the consumer modified, the recomputed score) used to justify                    
	// a riskAdjustment. For other override types this is optional context.                                         
	Cvss                                                                                        *Cvss               `json:"cvss,omitempty"`
	// Supporting evidence (screenshots, logs, URLs, documents).                                                    
	Evidence                                                                                    []Evidence          `json:"evidence,omitempty"`
	// When this amendment expires and must be reviewed. No permanent amendments. ISO 8601                          
	// format.                                                                                                      
	ExpiresAt                                                                                   time.Time           `json:"expiresAt"`
	// Optional references to the external artifacts behind this override (e.g. the STIX                            
	// bundle/object, advisory, or CTI feed that motivated it). Inert context distinct from                         
	// `evidence`; see External_Reference.                                                                          
	ExternalReferences                                                                          []ExternalReference `json:"externalReferences,omitempty"`
	// Override to the requirement's impact score. At least one of status or impact must be set.                    
	Impact                                                                                      *ImpactOverride     `json:"impact,omitempty"`
	// componentId of the local component that provides this control. Set when the provider is                      
	// in the same system. Omit for external or cross-system providers; the reason field                            
	// explains the source. Primarily used with type 'inherited'.                                                   
	InheritedFrom                                                                               *string             `json:"inheritedFrom,omitempty"`
	// Structured controlled-vocabulary classification for why this override applies.                               
	// Complements (does not replace) the free-text 'reason' field. Most useful on falsePositive                    
	// and attestation overrides where the structured category enables filtering and lossless                       
	// round-trip with VEX / OSCAL / FedRAMP DR. See the Justification primitive for the                            
	// precedent vocabulary and rationale.                                                                          
	Justification                                                                               *Justification      `json:"justification,omitempty"`
	// Remediation milestones (primarily for POA&M type amendments).                                                
	Milestones                                                                                  []Milestone         `json:"milestones,omitempty"`
	// Checksum of the prior amendment in the chain. Creates a tamper-evident linked list. Null                     
	// for the first amendment.                                                                                     
	PreviousChecksum                                                                            *Checksum           `json:"previousChecksum,omitempty"`
	// Justification for this amendment.                                                                            
	Reason                                                                                      string              `json:"reason"`
	// The ID of the requirement being amended. Must match a requirement ID in the referenced                       
	// baseline.                                                                                                    
	RequirementID                                                                               string              `json:"requirementId"`
	// Digital signature for non-repudiation.                                                                       
	Signature                                                                                   *Signature          `json:"signature,omitempty"`
	// The new status this amendment sets. Optional when only impact is being overridden.                           
	Status                                                                                      *ResultStatus       `json:"status,omitempty"`
	// The type of amendment.                                                                                       
	Type                                                                                        OverrideType        `json:"type"`
}

// Bundles references to all HDF documents for audit, authorization, and compliance review. Each
// content entry references a document by type, URI, and checksum for integrity verification.
type HDFEvidencePackage struct {
	// Summary of assessment completeness and compliance status.                                                            
	CompletenessCheck                                                                           *CompletenessCheck          `json:"completenessCheck,omitempty"`
	// References to HDF documents included in this evidence package.                                                       
	Contents                                                                                    []ContentReference          `json:"contents"`
	// Description of the evidence package's purpose and scope.                                                             
	Description                                                                                 *string                     `json:"description,omitempty"`
	// References to external native-format evidence (log/telemetry corpora and other artifacts)                            
	// carried by URI + integrity hash + format discriminator, without recreating the data                                  
	// inside HDF. Logs in ECS/OCSF/etc. are legitimate accreditation evidence; HDF indexes them                            
	// here rather than transcoding them.                                                                                   
	ExternalEvidence                                                                            []ExternalEvidenceReference `json:"externalEvidence,omitempty"`
	// Optional references to external artifacts relevant to this evidence package (CTI/STIX,                               
	// BOMs, advisories, or any URI-addressable artifact) beyond the document references it                                 
	// already carries. Inert context; see External_Reference.                                                              
	ExternalReferences                                                                          []ExternalReference         `json:"externalReferences,omitempty"`
	// Information about the tool that generated this document.                                                             
	Generator                                                                                   *Generator                  `json:"generator,omitempty"`
	// Cryptographic integrity information for verifying this evidence package has not been                                 
	// tampered with.                                                                                                       
	Integrity                                                                                   *Integrity                  `json:"integrity,omitempty"`
	// Optional key-value labels for grouping and querying evidence packages.                                               
	Labels                                                                                      map[string]string           `json:"labels,omitempty"`
	// Human-readable name for this evidence package. Example: 'Enterprise Portal ATO Evidence -                            
	// Q1 2026'.                                                                                                            
	Name                                                                                        string                      `json:"name"`
	// Unique identifier for this evidence package. Optional in casual use, expected in                                     
	// production ATO submissions. Auto-generated if omitted during creation.                                               
	PackageID                                                                                   *string                     `json:"packageId,omitempty"`
	// URI to the hdf-plan document that drove this assessment. Used for completeness                                       
	// verification — every baseline in the plan should have a corresponding results document in                            
	// this package.                                                                                                        
	PlanRef                                                                                     *string                     `json:"planRef,omitempty"`
	// When this evidence package was prepared. ISO 8601 format.                                                            
	PreparedAt                                                                                  *time.Time                  `json:"preparedAt,omitempty"`
	// Identity of who prepared this evidence package.                                                                      
	PreparedBy                                                                                  *Identity                   `json:"preparedBy,omitempty"`
	// Digital signature covering the entire evidence package.                                                              
	Signature                                                                                   *Signature                  `json:"signature,omitempty"`
	// URI to the hdf-system document this evidence package covers.                                                         
	SystemRef                                                                                   *string                     `json:"systemRef,omitempty"`
	// Version of this evidence package.                                                                                    
	Version                                                                                     *string                     `json:"version,omitempty"`
}

// Informational summary of assessment completeness. Not authoritative — tools should compute these
// from the referenced documents.
type CompletenessCheck struct {
	// Whether all baselines referenced by system components have assessment results.               
	AllBaselinesAssessed                                                              *bool         `json:"allBaselinesAssessed,omitempty"`
	// Whether all system components have at least one matching target in the results.              
	AllComponentsCovered                                                              *bool         `json:"allComponentsCovered,omitempty"`
	// Overall compliance percentage across all assessments.                                        
	CompliancePercent                                                                 *float64      `json:"compliancePercent,omitempty"`
	// Number of waivers/amendments that have expired.                                              
	ExpiredWaivers                                                                    *int64        `json:"expiredWaivers,omitempty"`
	// SBOM coverage across system components.                                                      
	SbomCoverage                                                                      *SBOMCoverage `json:"sbomCoverage,omitempty"`
	// Number of POA&M items that are still open (not completed).                                   
	UnresolvedPoams                                                                   *int64        `json:"unresolvedPoams,omitempty"`
}

// SBOM coverage statistics for the system.
type SBOMCoverage struct {
	// Number of system components that have an associated SBOM.       
	ComponentsWithSbom                                          *int64 `json:"componentsWithSbom,omitempty"`
	// Total number of components in the system.                       
	TotalComponents                                             *int64 `json:"totalComponents,omitempty"`
}

// A reference to an HDF document or BOM/manifest included in the evidence package.
type ContentReference struct {
	// Cryptographic checksum for verifying the referenced document's integrity.                          
	Checksum                                                                                  *Checksum   `json:"checksum,omitempty"`
	// componentId of the component this content entry relates to. Use to link SBOMs, results,            
	// or other documents to a specific system component.                                                 
	ComponentRef                                                                              *string     `json:"componentRef,omitempty"`
	// Optional description of this content entry.                                                        
	Description                                                                               *string     `json:"description,omitempty"`
	// The type of HDF document being referenced.                                                         
	Type                                                                                      ContentType `json:"type"`
	// URI to the document. Can be a relative path or absolute URL.                                       
	URI                                                                                       string      `json:"uri"`
}

// A reference to external native-format evidence (log/telemetry corpus or other artifact) carried
// by URI + integrity hash + format discriminator. Reference-only: the artifact is never embedded
// (corpora can be huge) or transcoded (that would be lossy) — it stays canonical in its native
// format and HDF acts as the structured index.
type ExternalEvidenceReference struct {
	// Cryptographic checksum of the referenced artifact for integrity verification.                                     
	Checksum                                                                                   *Checksum                 `json:"checksum,omitempty"`
	// Optional human-readable description of this evidence entry.                                                       
	Description                                                                                *string                   `json:"description,omitempty"`
	// The native format discriminator of the referenced artifact.                                                       
	Format                                                                                     string                    `json:"format"`
	// Optional producer-declared version of the format (e.g. ECS '9.4.0', OCSF '1.8.0').                                
	// Free-text and untrusted — HDF does not validate it against a registry.                                            
	FormatVersion                                                                              *string                   `json:"formatVersion,omitempty"`
	// Optional IANA media type describing the on-disk serialization, orthogonal to 'format'                             
	// (the semantic standard). Examples: application/x-ndjson, application/json,                                        
	// application/vnd.apache.parquet, text/csv.                                                                         
	MediaType                                                                                  *string                   `json:"mediaType,omitempty"`
	// Optional descriptive metadata about the referenced corpus. Does not affect integrity.                             
	Metadata                                                                                   *ExternalEvidenceMetadata `json:"metadata,omitempty"`
	// URI to the external native-format evidence artifact (log/telemetry corpus, etc.). Can be                          
	// a relative path or absolute URL. The data stays canonical in its native format — HDF                              
	// references it, never parses or transcodes it.                                                                     
	URI                                                                                        string                    `json:"uri"`
}

// Descriptive metadata about a referenced external evidence corpus. Does not affect integrity.
type ExternalEvidenceMetadata struct {
	// The tool/pipeline that collected or produced the corpus. Example: 'aws-security-lake',                           
	// 'elastic-agent'.                                                                                                 
	Collector                                                                                *string                    `json:"collector,omitempty"`
	// Approximate number of records/events in the referenced corpus.                                                   
	RecordCount                                                                              *int64                     `json:"recordCount,omitempty"`
	// The time window the referenced evidence covers.                                                                  
	TimeRange                                                                                *ExternalEvidenceTimeRange `json:"timeRange,omitempty"`
}

// The time window a referenced external evidence corpus covers.
type ExternalEvidenceTimeRange struct {
	// End of the time window the corpus covers (ISO 8601).             
	End                                                      *time.Time `json:"end,omitempty"`
	// Start of the time window the corpus covers (ISO 8601).           
	Start                                                    *time.Time `json:"start,omitempty"`
}

// A single continuous-monitoring wire event: one requirement's effective posture changed on one
// system component. The streaming increment of a systemDrift hdf-comparison — events fold into
// comparisons and reassemble into hdf-results, they never mutate documents in place. One event per
// wire document (NDJSON-friendly). The envelope (identity, ordering, hash chain) is the shared
// Change_Event_Envelope primitive; the payload carries the producer-computable change state, a thin
// before projection, and the full after requirement (the evidence a responder opens the event for).
// Design: ADR-0005.
type HDFRequirementChangeEvent struct {
	// The full requirement as evaluated after the change — required and non-null for every                           
	// state except absent (null there: the requirement left the assessment scope). Full content                      
	// is load-bearing twice over: reassembly parity (applyChangeEvents cannot reproduce changed                      
	// result content from a projection) and triage (the failing results[] ARE the 'why' a                            
	// responder opens the event for).                                                                                
	After                                                                                       interface{}           `json:"after"`
	// Thin projection of the prior effective posture, for at-a-glance alerting without a                             
	// state-store lookup. Null exactly when state is new (no prior posture exists). The full                         
	// prior state is recoverable from the consumer's materialized state; the envelope's                              
	// priorChecksum covers the integrity of that recovery.                                                           
	Before                                                                                      interface{}           `json:"before"`
	// Why the state changed. An overrideExpired flip is a different triage than resultChanged:                       
	// the control did not get worse, a waiver lapsed.                                                                
	ChangeReasons                                                                               []EventChangeReason   `json:"changeReasons,omitempty"`
	// Canonical requirement identifier — the same identity as Requirement_Diff.id and the                            
	// requirement's id in hdf-results. Together with the envelope's (systemRef, componentId)                         
	// this forms the durable entity key. A requirement renumbering is emitted as absent + new                        
	// under the two keys, never an in-place key change; batch comparison reconciles renames via                      
	// its oldId/newId matching.                                                                                      
	RequirementID                                                                               string                `json:"requirementId"`
	// The producer-computable subset of Requirement_State: new | absent | updated | fixed |                          
	// regressed. fixed and regressed carry the direction SARIF's baselineState lacks; project                        
	// down to SARIF's closed 4 values for external interop.                                                          
	State                                                                                       EventRequirementState `json:"state"`
	// componentId of the system component this event concerns.                                                       
	ComponentID                                                                                 string                `json:"componentId"`
	// Identity of this event occurrence, unique per source. (source, eventId) is the                                 
	// deduplication key: consumers may treat events with identical source and eventId as                             
	// duplicates. UUIDv7 (time-ordered) is recommended but not required.                                             
	EventID                                                                                     string                `json:"eventId"`
	// The effectiveChecksum of the entity state this event supersedes, forming a per-key hash                        
	// chain: a mismatch or gap against stored state is detectable, letting a consumer mark the                       
	// key unverified instead of serving stale posture. Null at chain start (no prior state,                          
	// e.g. a new entity or the first event after a seed). The chain provides tamper/gap                              
	// evidence given a trusted head; completeness is anchored out-of-band by periodic                                
	// re-centering rescans.                                                                                          
	PriorChecksum                                                                               interface{}           `json:"priorChecksum"`
	// The versioned schema $id this event validates against, so events self-describe on                              
	// heterogeneous streams. Recommended on every wire event.                                                        
	SchemaRef                                                                                   *string               `json:"schemaRef,omitempty"`
	// Monotonically increasing sequence number per entity key. The ONLY ordering authority for                       
	// folding: consumers keep the greatest sequence per key regardless of arrival order or                           
	// timestamp. Deliberately per-entity-key (event-sourcing aggregate-version practice) rather                      
	// than per-source.                                                                                               
	Sequence                                                                                    int64                 `json:"sequence"`
	// URI identifying the producer context that emitted this event (for example, a scanner                           
	// instance and profile). eventId uniqueness and sequence numbering are scoped per source.                        
	Source                                                                                      string                `json:"source"`
	// URI to the hdf-system document (authorization boundary) this event applies to. Resolves                        
	// to the latest version of the evolving system document.                                                         
	SystemRef                                                                                   string                `json:"systemRef"`
	// Occurrence time of the observed change (RFC 3339, trimmed UTC). Display and audit                              
	// metadata only — NEVER an ordering key; ordering is sequence's job.                                             
	Timestamp                                                                                   time.Time             `json:"timestamp"`
}

// The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
// 'system' for deterministic non-interactive automation (CI jobs, cron, scanners), 'agent'
// for an AI/LLM agent acting with autonomy — kept distinct from 'system' so auditors can
// apply AI-specific scrutiny (e.g. 'an LLM proposed this' vs a deterministic job) and
// satisfy AI-source disclosure under frameworks like the EU AI Act and NIST AI RMF,
// 'simple' for basic string identifiers without additional classification, or 'other' for
// custom identity systems.
type IdentityType string

const (
	Agent              IdentityType = "agent"
	Email              IdentityType = "email"
	IdentityTypeOther  IdentityType = "other"
	IdentityTypeSystem IdentityType = "system"
	Simple             IdentityType = "simple"
	Username           IdentityType = "username"
)

// Supported cryptographic hash algorithms for checksums and integrity verification. blake3 covers
// container-image and other artifact digests that use it.
type HashAlgorithm string

const (
	Blake3 HashAlgorithm = "blake3"
	Sha256 HashAlgorithm = "sha256"
	Sha384 HashAlgorithm = "sha384"
	Sha512 HashAlgorithm = "sha512"
)

// Comparison operator for evaluating the input value against observed values. Numeric:
// eq/ne/lt/le/gt/ge. String: eq/ne/contains/matches. Collection: in/notIn.
type ComparisonOperator string

const (
	Contains ComparisonOperator = "contains"
	Eq       ComparisonOperator = "eq"
	Ge       ComparisonOperator = "ge"
	Gt       ComparisonOperator = "gt"
	In       ComparisonOperator = "in"
	LE       ComparisonOperator = "le"
	Lt       ComparisonOperator = "lt"
	Matches  ComparisonOperator = "matches"
	Ne       ComparisonOperator = "ne"
	NotIn    ComparisonOperator = "notIn"
)

// The data type of the input value. Aligns with InSpec input types.
type InputType string

const (
	Array   InputType = "Array"
	Boolean InputType = "Boolean"
	Hash    InputType = "Hash"
	Numeric InputType = "Numeric"
	Regexp  InputType = "Regexp"
	String  InputType = "String"
)

// The packaging ecosystem the package belongs to. Use 'generic' for hardware, firmware, or
// anything outside the listed language/OS package managers.
type Ecosystem string

const (
	Cargo   Ecosystem = "cargo"
	Deb     Ecosystem = "deb"
	Gem     Ecosystem = "gem"
	Generic Ecosystem = "generic"
	Go      Ecosystem = "go"
	Maven   Ecosystem = "maven"
	Npm     Ecosystem = "npm"
	Nuget   Ecosystem = "nuget"
	Pypi    Ecosystem = "pypi"
	RPM     Ecosystem = "rpm"
)

// Whether the requirement is mandatory within its baseline. Distinct from severity (risk
// weight) and status (lifecycle state). Maps cleanly onto: FedRAMP rev5 OSCAL 'CORE' prop,
// FedRAMP 20x inline 'Optional:' markers, CMMC sublevel rows, and CIS Implementation Group
// memberships (IG1/IG2/IG3 may carry richer semantics; layer those onto props[]/tags{}).
// Optional: when omitted, consumers should treat the requirement as 'required' by
// convention.
type Applicability string

const (
	Advisory Applicability = "advisory"
	Optional Applicability = "optional"
	Required Applicability = "required"
)

// Classification of the control's nature, aligning with NIST SP 800-53 / SP 800-53A
// categories. 'policy' = an authored governance statement; 'procedure' = a documented
// process; 'technical' = an enforced technical configuration; 'management' = a
// programmatic/management activity; 'operational' = a recurring operational activity (e.g.
// AT, IR, MA families). Optional: when omitted, consumers may infer heuristically from
// family/id but should not assume a default.
type ControlType string

const (
	Management  ControlType = "management"
	Operational ControlType = "operational"
	Policy      ControlType = "policy"
	Procedure   ControlType = "procedure"
	Technical   ControlType = "technical"
)

// Qualitative CVSS severity band. Aligns with FIRST/NVD bands: none=0.0, low=0.1-3.9,
// medium=4.0-6.9, high=7.0-8.9, critical=9.0-10.0. Distinct from the broader Severity enum used on
// Requirement_Core (which includes 'informational').
type CVSSSeverity string

const (
	CVSSSeverityCritical CVSSSeverity = "critical"
	CVSSSeverityHigh     CVSSSeverity = "high"
	CVSSSeverityLow      CVSSSeverity = "low"
	CVSSSeverityMedium   CVSSSeverity = "medium"
	None                 CVSSSeverity = "none"
)

// The CVSS specification version this entry conforms to. Vendor scanners typically emit 3.1
// or 4.0; legacy data may use 2.0 or 3.0.
type Version string

const (
	The20 Version = "2.0"
	The30 Version = "3.0"
	The31 Version = "3.1"
	The40 Version = "4.0"
)

// The type of amendment, aligned with FedRAMP deviation request categories. 'waiver': risk accepted
// by Authorizing Official. 'attestation': manually verified by assessor. 'poam': remediation
// tracked (no status change). 'inherited': control provided by another component or system.
// 'falsePositive': scanner incorrectly identified a finding — for compliance scans (STIG, CIS), the
// check actually passes, so status is typically set to 'passed'; for vulnerability scans (CVE,
// SCA), the flagged vulnerability does not apply to this system, so status is typically set to
// 'notApplicable'. The disposition field on the requirement distinguishes false positives from
// genuinely not-applicable findings. 'riskAdjustment': impact score adjusted based on environmental
// context (FedRAMP Risk Adjustment); does not change pass/fail status, only impact via the impact
// field. 'operationalRequirement': deviation required by operational constraints (FedRAMP
// Operational Requirement); the finding cannot be remediated because the system requires the
// affected functionality. Remains an open risk. Migration note: 'exception' was removed in v3.1.0 —
// use 'waiver' with status 'notApplicable' instead.
type OverrideType string

const (
	Attestation            OverrideType = "attestation"
	FalsePositive          OverrideType = "falsePositive"
	Inherited              OverrideType = "inherited"
	OperationalRequirement OverrideType = "operationalRequirement"
	OverrideTypeWaiver     OverrideType = "waiver"
	Poam                   OverrideType = "poam"
	RiskAdjustment         OverrideType = "riskAdjustment"
)

// The status of an individual test result. 'notApplicable' indicates the requirement does not apply
// to the target. 'notReviewed' indicates the requirement was not assessed (e.g., requires manual
// verification).
type ResultStatus string

const (
	Error         ResultStatus = "error"
	Failed        ResultStatus = "failed"
	NotApplicable ResultStatus = "notApplicable"
	NotReviewed   ResultStatus = "notReviewed"
	Passed        ResultStatus = "passed"
)

// The type of evidence being provided.
type EvidenceType string

const (
	Code              EvidenceType = "code"
	EvidenceTypeOther EvidenceType = "other"
	File              EvidenceType = "file"
	Log               EvidenceType = "log"
	Screenshot        EvidenceType = "screenshot"
	URL               EvidenceType = "url"
)

// Current status of this milestone.
type MilestoneStatus string

const (
	Completed  MilestoneStatus = "completed"
	InProgress MilestoneStatus = "inProgress"
	Pending    MilestoneStatus = "pending"
)

// The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
// compensating controls. 'riskAcceptance' documents decision to accept risk.
// 'vendorDependency' tracks a fix that depends on a vendor releasing a patch or update.
type POAMType string

const (
	Mitigation          POAMType = "mitigation"
	POAMTypeRemediation POAMType = "remediation"
	RiskAcceptance      POAMType = "riskAcceptance"
	VendorDependency    POAMType = "vendorDependency"
)

// Severity rating for a requirement. Typically derived from the numeric impact score.
type Severity string

const (
	Informational    Severity = "informational"
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
)

// Structured controlled-vocabulary reason for an override, complementing the free-text 'reason'
// field. 'reason' carries the human-readable rationale an auditor reads; 'justification' carries
// the machine-readable category enabling filtering, aggregation, and lossless round-trip with
// structured ecosystems (VEX, OSCAL, FedRAMP DR). Both fields may be present simultaneously and are
// NOT redundant: 'reason' explains the specific circumstance; 'justification' classifies it.
// Authors SHOULD populate both when a controlled-vocabulary value applies — the enum value alone is
// not self-explanatory to an auditor. The vocabulary is drawn from the VEX ecosystem: the first
// five values are common across OpenVEX, CSAF VEX, and CycloneDX VEX; the remaining six
// (requires_configuration / requires_dependency / requires_environment / protected_by_compiler /
// protected_at_runtime / protected_at_perimeter) are CycloneDX-specific and describe why the
// vulnerable code path is unreachable in the deployed configuration. The enum is extended
// additively across schema versions as other ecosystems' controlled vocabularies are integrated;
// documents using values added in a newer schema version will fail validation against an older
// schema. Consumers SHOULD validate against the schema version declared by the document ($schema)
// rather than assume a fixed vocabulary.
type Justification string

const (
	ComponentNotPresent                         Justification = "component_not_present"
	InlineMitigationsAlreadyExist               Justification = "inline_mitigations_already_exist"
	ProtectedAtPerimeter                        Justification = "protected_at_perimeter"
	ProtectedAtRuntime                          Justification = "protected_at_runtime"
	ProtectedByCompiler                         Justification = "protected_by_compiler"
	RequiresConfiguration                       Justification = "requires_configuration"
	RequiresDependency                          Justification = "requires_dependency"
	RequiresEnvironment                         Justification = "requires_environment"
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	VulnerableCodeNotInExecutePath              Justification = "vulnerable_code_not_in_execute_path"
	VulnerableCodeNotPresent                    Justification = "vulnerable_code_not_present"
)

// How a requirement is intended to be verified. Disambiguates the two cases that null 'code'
// overloads: 'manual-by-design' (the requirement is statement-form and not amenable to automation,
// e.g. FedRAMP 20x KSIs); 'manual-pending-automation' (automation could exist but does not yet,
// e.g. a STIG rule lacking a fix). 'automated' = a check exists and runs without operator action;
// 'hybrid' = part automated, part manual. Named '_Enum' to disambiguate from the unrelated
// Verification_Method DID-context struct.
type VerificationMethodEnum string

const (
	ManualByDesign                  VerificationMethodEnum = "manual-by-design"
	ManualPendingAutomation         VerificationMethodEnum = "manual-pending-automation"
	VerificationMethodEnumAutomated VerificationMethodEnum = "automated"
	VerificationMethodEnumHybrid    VerificationMethodEnum = "hybrid"
)

// Relationship of this dataset to baseDatasetRefs, parallel to the model extension's
// adaptationType. Minimal + extensible: filtered (subset by rule), augmented
// (added/synthesized records), merged (union of sources), sampled (statistical draw).
type DatasetDerivationType string

const (
	Augmented                   DatasetDerivationType = "augmented"
	DatasetDerivationTypeMerged DatasetDerivationType = "merged"
	Filtered                    DatasetDerivationType = "filtered"
	Sampled                     DatasetDerivationType = "sampled"
)

// Lineage relationship to baseModelRef, adopting Hugging Face's base_model_relation
// vocabulary (the only typed lineage enum in the ecosystem).
type ModelAdaptationType string

const (
	Adapter   ModelAdaptationType = "adapter"
	Finetune  ModelAdaptationType = "finetune"
	Merge     ModelAdaptationType = "merge"
	Quantized ModelAdaptationType = "quantized"
)

type CloudProvider string

const (
	Aws                CloudProvider = "aws"
	Azure              CloudProvider = "azure"
	CloudProviderOther CloudProvider = "other"
	Gcp                CloudProvider = "gcp"
	Oci                CloudProvider = "oci"
)

// Component type discriminator. Same values as Target types, plus aiModel and dataset (thin
// AI subject components whose detail lives in an attached ai-model / dataset BOM).
type TargetType string

const (
	AIModel           TargetType = "aiModel"
	Application       TargetType = "application"
	Artifact          TargetType = "artifact"
	CloudAccount      TargetType = "cloudAccount"
	CloudResource     TargetType = "cloudResource"
	ContainerImage    TargetType = "containerImage"
	ContainerInstance TargetType = "containerInstance"
	ContainerPlatform TargetType = "containerPlatform"
	Database          TargetType = "database"
	Dataset           TargetType = "dataset"
	Host              TargetType = "host"
	Network           TargetType = "network"
	Repository        TargetType = "repository"
)

// The category of an annotation attached to a comparison.
type AnnotationCategory string

const (
	AnnotationCategoryRemediation AnnotationCategory = "remediation"
	AnnotationCategoryWaiver      AnnotationCategory = "waiver"
	BaselineChange                AnnotationCategory = "baselineChange"
	Drift                         AnnotationCategory = "drift"
	ScannerNote                   AnnotationCategory = "scannerNote"
)

// The state of this baseline in the comparison.
//
// The state of this component in the comparison.
type BaselineDiffState string

const (
	BaselineDiffStateAbsent    BaselineDiffState = "absent"
	BaselineDiffStateNew       BaselineDiffState = "new"
	BaselineDiffStateUnchanged BaselineDiffState = "unchanged"
	BaselineDiffStateUpdated   BaselineDiffState = "updated"
)

// The mode of comparison. 'temporal' compares the same target over time. 'baseline' compares
// against a golden reference. 'fleet' compares across multiple systems. 'multiSource' compares
// outputs from different scanners. 'baselineEvolution' compares two baseline documents to detect
// requirement changes between versions. 'systemDrift' compares two system documents to detect
// component-level changes.
type ComparisonMode string

const (
	Baseline          ComparisonMode = "baseline"
	BaselineEvolution ComparisonMode = "baselineEvolution"
	Fleet             ComparisonMode = "fleet"
	MultiSource       ComparisonMode = "multiSource"
	SystemDrift       ComparisonMode = "systemDrift"
	Temporal          ComparisonMode = "temporal"
)

// The type of change operation.
type Op string

const (
	Add     Op = "add"
	Remove  Op = "remove"
	Replace Op = "replace"
)

// The reason a requirement's state changed between sources.
type ChangeReason string

const (
	BaselineUpgraded             ChangeReason = "baselineUpgraded"
	ChangeReasonConfigChanged    ChangeReason = "configChanged"
	ChangeReasonImpactChanged    ChangeReason = "impactChanged"
	ChangeReasonOverrideAdded    ChangeReason = "overrideAdded"
	ChangeReasonOverrideExpired  ChangeReason = "overrideExpired"
	ChangeReasonOverrideModified ChangeReason = "overrideModified"
	ChangeReasonOverrideRemoved  ChangeReason = "overrideRemoved"
	ChangeReasonResultChanged    ChangeReason = "resultChanged"
	ControlMapped                ChangeReason = "controlMapped"
	MetadataChanged              ChangeReason = "metadataChanged"
	ScannerChanged               ChangeReason = "scannerChanged"
	TargetChanged                ChangeReason = "targetChanged"
)

// How a conflict between multiple scanner results was resolved.
type ConflictResolution string

const (
	ConflictResolutionManual ConflictResolution = "manual"
	MostRecent               ConflictResolution = "mostRecent"
	MostSevere               ConflictResolution = "mostSevere"
	Unresolved               ConflictResolution = "unresolved"
)

// The strategy used to match requirements across sources. 'exactId' matches by identical IDs.
// 'mappedId' uses an ID mapping table. 'cciMatch'/'nistMatch' match by framework identifiers.
// 'fuzzyTitle'/'fuzzyContent' use text similarity.
type MatchStrategy string

const (
	CciMatch     MatchStrategy = "cciMatch"
	ExactID      MatchStrategy = "exactId"
	FuzzyContent MatchStrategy = "fuzzyContent"
	FuzzyTitle   MatchStrategy = "fuzzyTitle"
	MappedID     MatchStrategy = "mappedId"
	NISTMatch    MatchStrategy = "nistMatch"
)

// SARIF-compatible vocabulary extended for security. 'new' = present only in new source, 'absent' =
// present only in old, 'unchanged' = same effective status, 'updated' = status changed (generic),
// 'fixed' = was failing now passing, 'regressed' = was passing now failing, 'moved' = reorganized
// same content, 'split'/'merged' = reserved for v1.1.
type RequirementState string

const (
	Moved                     RequirementState = "moved"
	RequirementStateAbsent    RequirementState = "absent"
	RequirementStateFixed     RequirementState = "fixed"
	RequirementStateMerged    RequirementState = "merged"
	RequirementStateNew       RequirementState = "new"
	RequirementStateRegressed RequirementState = "regressed"
	RequirementStateUnchanged RequirementState = "unchanged"
	RequirementStateUpdated   RequirementState = "updated"
	Split                     RequirementState = "split"
)

type FormatVersion string

const (
	The100 FormatVersion = "1.0.0"
)

// The state of this package: added (new in new SBOM), removed (absent from new SBOM),
// updated (version changed), unchanged.
type PackageDiffState string

const (
	Added                     PackageDiffState = "added"
	PackageDiffStateUnchanged PackageDiffState = "unchanged"
	PackageDiffStateUpdated   PackageDiffState = "updated"
	Removed                   PackageDiffState = "removed"
)

// The original format of the source document before conversion to HDF.
type OriginalFormat string

const (
	HdfV2    OriginalFormat = "hdf-v2"
	InspecV1 OriginalFormat = "inspec-v1"
	OscalAr  OriginalFormat = "oscal-ar"
	Sarif    OriginalFormat = "sarif"
	Xccdf    OriginalFormat = "xccdf"
)

// The role of a source document in the comparison.
type SourceRole string

const (
	Golden              SourceRole = "golden"
	Old                 SourceRole = "old"
	SourceRoleNew       SourceRole = "new"
	SourceRoleReference SourceRole = "reference"
	SourceRoleSystem    SourceRole = "system"
)

// Authorization to Operate (ATO) status for the system.
type AuthorizationStatus string

const (
	Authorized              AuthorizationStatus = "authorized"
	ConditionallyAuthorized AuthorizationStatus = "conditionallyAuthorized"
	Denied                  AuthorizationStatus = "denied"
	NotYetRequested         AuthorizationStatus = "notYetRequested"
	PendingAuthorization    AuthorizationStatus = "pendingAuthorization"
	Revoked                 AuthorizationStatus = "revoked"
)

// FIPS 199 security categorization level (impact level).
type CategorizationLevel string

const (
	CategorizationLevelHigh CategorizationLevel = "high"
	CategorizationLevelLow  CategorizationLevel = "low"
	Moderate                CategorizationLevel = "moderate"
)

// NIST SP 800-53 control designation. 'common': fully provided by another component or
// system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
// shared responsibility between provider and inheritor.
type Designation string

const (
	Common            Designation = "common"
	DesignationHybrid Designation = "hybrid"
	SystemSpecific    Designation = "system-specific"
)

// Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
// means data flows in both directions (e.g., request/response).
type Direction string

const (
	Bidirectional  Direction = "bidirectional"
	Unidirectional Direction = "unidirectional"
)

// The type of assessment. 'automated' for scanner-driven, 'manual' for human-performed, 'hybrid'
// for both.
type PlanType string

const (
	PlanTypeAutomated PlanType = "automated"
	PlanTypeHybrid    PlanType = "hybrid"
	PlanTypeManual    PlanType = "manual"
)

// The type of document referenced in the evidence package. 'bom' covers any
// Bill-of-Materials/manifest document (SBOM, AI model/dataset, and reserved future kinds) — its
// specific kind is carried by the referenced document's bomType, not by a per-kind Content_Type
// value.
type ContentType string

const (
	BOM           ContentType = "bom"
	HdfAmendments ContentType = "hdf-amendments"
	HdfBaseline   ContentType = "hdf-baseline"
	HdfComparison ContentType = "hdf-comparison"
	HdfPlan       ContentType = "hdf-plan"
	HdfResults    ContentType = "hdf-results"
	HdfSystem     ContentType = "hdf-system"
)

// The producer-computable subset of the comparison vocabulary's Change_Reason, value-identical with
// the parent enum (test-enforced). Batch-only reasons (baselineUpgraded, controlMapped,
// scannerChanged, targetChanged, metadataChanged) require cross-corpus context and are excluded.
type EventChangeReason string

const (
	EventChangeReasonConfigChanged    EventChangeReason = "configChanged"
	EventChangeReasonImpactChanged    EventChangeReason = "impactChanged"
	EventChangeReasonOverrideAdded    EventChangeReason = "overrideAdded"
	EventChangeReasonOverrideExpired  EventChangeReason = "overrideExpired"
	EventChangeReasonOverrideModified EventChangeReason = "overrideModified"
	EventChangeReasonOverrideRemoved  EventChangeReason = "overrideRemoved"
	EventChangeReasonResultChanged    EventChangeReason = "resultChanged"
)

// The producer-computable subset of the comparison vocabulary's Requirement_State. Kept
// value-identical with the parent enum (test-enforced): the batch-only states (moved, split,
// merged) are outputs of cross-document identity resolution a per-key producer cannot compute.
// Declared as a distinct named type (rather than a $ref intersection) so generated Go/TS types keep
// stable, distinct enum names.
type EventRequirementState string

const (
	EventRequirementStateAbsent    EventRequirementState = "absent"
	EventRequirementStateFixed     EventRequirementState = "fixed"
	EventRequirementStateNew       EventRequirementState = "new"
	EventRequirementStateRegressed EventRequirementState = "regressed"
	EventRequirementStateUpdated   EventRequirementState = "updated"
)

type Ref struct {
	AnythingMapArray []map[string]interface{}
	String           *string
}

func (x *Ref) UnmarshalJSON(data []byte) error {
	x.AnythingMapArray = nil
	object, err := unmarshalUnion(data, nil, nil, nil, &x.String, true, &x.AnythingMapArray, false, nil, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
	}
	return nil
}

func (x *Ref) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, nil, x.String, x.AnythingMapArray != nil, x.AnythingMapArray, false, nil, false, nil, false, nil, false)
}

// Content modality/kind of the data (CISA/G7 'Dataset content: modality'). Examples: text,
// image, tabular, timeseries, audio. DISTINCT from datasetFormat, which is the physical
// encoding (parquet/csv). Resolves SPDX 3.0 dataset_datasetType, which is content-kind, not
// physical format. String or array of strings.
//
// Input/output modalities. String or array of strings. Examples: text, image, audio.
// Symmetric with Dataset_Extension.modality.
type Modality struct {
	String      *string
	StringArray []string
}

func (x *Modality) UnmarshalJSON(data []byte) error {
	x.StringArray = nil
	object, err := unmarshalUnion(data, nil, nil, nil, &x.String, true, &x.StringArray, false, nil, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
	}
	return nil
}

func (x *Modality) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, nil, x.String, x.StringArray != nil, x.StringArray, false, nil, false, nil, false, nil, false)
}

func unmarshalUnion(data []byte, pi **int64, pf **float64, pb **bool, ps **string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) (bool, error) {
	if pi != nil {
			*pi = nil
	}
	if pf != nil {
			*pf = nil
	}
	if pb != nil {
			*pb = nil
	}
	if ps != nil {
			*ps = nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
			return false, err
	}

	switch v := tok.(type) {
	case json.Number:
			if pi != nil {
					i, err := v.Int64()
					if err == nil {
							*pi = &i
							return false, nil
					}
			}
			if pf != nil {
					f, err := v.Float64()
					if err == nil {
							*pf = &f
							return false, nil
					}
					return false, errors.New("Unparsable number")
			}
			return false, errors.New("Union does not contain number")
	case float64:
			return false, errors.New("Decoder should not return float64")
	case bool:
			if pb != nil {
					*pb = &v
					return false, nil
			}
			return false, errors.New("Union does not contain bool")
	case string:
			if haveEnum {
					return false, json.Unmarshal(data, pe)
			}
			if ps != nil {
					*ps = &v
					return false, nil
			}
			return false, errors.New("Union does not contain string")
	case nil:
			if nullable {
					return false, nil
			}
			return false, errors.New("Union does not contain null")
	case json.Delim:
			if v == '{' {
					if haveObject {
							return true, json.Unmarshal(data, pc)
					}
					if haveMap {
							return false, json.Unmarshal(data, pm)
					}
					return false, errors.New("Union does not contain object")
			}
			if v == '[' {
					if haveArray {
							return false, json.Unmarshal(data, pa)
					}
					return false, errors.New("Union does not contain array")
			}
			return false, errors.New("Cannot handle delimiter")
	}
	return false, errors.New("Cannot unmarshal union")
}

func marshalUnion(pi *int64, pf *float64, pb *bool, ps *string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) ([]byte, error) {
	if pi != nil {
			return json.Marshal(*pi)
	}
	if pf != nil {
			return json.Marshal(*pf)
	}
	if pb != nil {
			return json.Marshal(*pb)
	}
	if ps != nil {
			return json.Marshal(*ps)
	}
	if haveArray {
			return json.Marshal(pa)
	}
	if haveObject {
			return json.Marshal(pc)
	}
	if haveMap {
			return json.Marshal(pm)
	}
	if haveEnum {
			return json.Marshal(pe)
	}
	if nullable {
			return json.Marshal(nil)
	}
	return nil, errors.New("Union must not be null")
}
