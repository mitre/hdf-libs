// Code generated from JSON Schema using quicktype. DO NOT EDIT.
// To parse and unparse this JSON data, add this code to your project and do:
//
//    hdfResults, err := UnmarshalHdfResults(bytes)
//    bytes, err = hdfResults.Marshal()

package hdf

import "bytes"
import "errors"
import "time"

import "encoding/json"

func UnmarshalHdfResults(data []byte) (HdfResults, error) {
	var r HdfResults
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HdfResults) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// The top level value containing all assessment results.
type HdfResults struct {
	// Information on the baselines that were evaluated, including findings.
	Baselines []EvaluatedBaseline `json:"baselines"`
	// Reserved for tool-specific data not defined in the HDF standard. Use this to preserve
	// original tool output, auxiliary data, or custom metadata.
	Extensions map[string]interface{} `json:"extensions,omitempty"`
	// Information about the tool that generated this file.
	Generator *Generator `json:"generator"`
	// Unique identifier for this assessment run.
	ID *string `json:"id,omitempty"`
	// Cryptographic integrity information for verifying this file.
	Integrity *Integrity `json:"integrity"`
	// Optional reference to automated remediation resources (Ansible playbooks, Terraform
	// scripts, etc.) for fixing failing requirements found in this assessment.
	Remediation *Remediation `json:"remediation"`
	// Information about the test execution environment where the security tool was run.
	// Distinct from targets (what is being tested).
	Runner *Runner `json:"runner"`
	// Statistics for the assessment run, including duration and result counts.
	Statistics Statistics `json:"statistics"`
	// Reference to an hdf-system document describing the system under assessment.
	SystemRef *string `json:"systemRef,omitempty"`
	// Reference to an hdf-plan document describing the assessment plan that produced these results.
	PlanRef *string `json:"planRef,omitempty"`
	// The components that were assessed. Each component describes a system element
	// (host, container, cloud resource, application, etc.).
	Components []Target `json:"components,omitempty"`
	// When this assessment was executed.
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// Information on a baseline that was evaluated, including any findings.
//
// Shared metadata fields for baselines. Used in both standalone baseline documents and
// evaluated baseline results.
type EvaluatedBaseline struct {
	// Typed inputs used to parameterize this baseline at execution time.
	Inputs []map[string]interface{} `json:"inputs"`
	// Cryptographic checksum for baseline integrity verification.
	Checksum Checksum `json:"checksum"`
	// The set of dependencies this baseline depends on.
	Depends []Dependency `json:"depends"`
	// The description - should be more detailed than the summary.
	Description *string `json:"description"`
	// Reserved for tool-specific baseline metadata not defined in the HDF standard.
	Extensions map[string]interface{} `json:"extensions,omitempty"`
	// A set of descriptions for the requirement groups.
	Groups []RequirementGroup `json:"groups"`
	// The version of InSpec used to execute this baseline.
	InspecVersion *string `json:"inspecVersion"`
	// SHA-256 checksum of the original baseline definition file (before execution). This is an
	// immutable reference to the baseline as defined, used to detect tampering with baseline
	// requirements or metadata.
	OriginalChecksum *Checksum `json:"originalChecksum"`
	// The name of the parent baseline if this is a dependency of another.
	ParentBaseline *string `json:"parentBaseline"`
	// The set of requirements including any findings.
	Requirements []EvaluatedRequirement `json:"requirements"`
	// SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).
	// Used to detect tampering with test results. Compare with currentChecksum to verify
	// amendment integrity.
	ResultsChecksum *Checksum `json:"resultsChecksum"`
	// An explanation of the baseline status. Example: why it was skipped, failed to load, or
	// any other status details.
	StatusMessage *string `json:"statusMessage"`
	// The name - must be unique.
	Name string `json:"name"`
	// The set of supported platform targets.
	Supports []SupportedPlatform `json:"supports"`
	// The copyright holder(s).
	Copyright *string `json:"copyright"`
	// The email address or other contact information of the copyright holder(s).
	CopyrightEmail *string `json:"copyrightEmail"`
	// The copyright license. Example: 'Apache-2.0'.
	License *string `json:"license"`
	// The maintainer(s).
	Maintainer *string `json:"maintainer"`
	// The status. Example: 'loaded'.
	Status *string `json:"status"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.
	Summary *string `json:"summary"`
	// The title - should be human readable.
	Title *string `json:"title"`
	// The version of the baseline.
	Version *string `json:"version"`
}

// Cryptographic checksum for baseline integrity verification.
type Checksum struct {
	// The hash algorithm used for the checksum.
	Algorithm HashAlgorithm `json:"algorithm"`
	// The checksum value.
	Value string `json:"value"`
}

// A dependency for a baseline. Can include relative paths or URLs for where to find the
// dependency.
type Dependency struct {
	// The branch name for a git repo.
	Branch *string `json:"branch"`
	// The 'user/profilename' attribute for an Automate server.
	Compliance *string `json:"compliance"`
	// The location of the git repo. Example:
	// 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git'.
	Git *string `json:"git"`
	// The name or assigned alias.
	Name *string `json:"name"`
	// The relative path if the dependency is locally available.
	Path *string `json:"path"`
	// The status. Should be: 'loaded', 'failed', or 'skipped'.
	Status *string `json:"status"`
	// The reason for the status if it is 'failed' or 'skipped'.
	StatusMessage *string `json:"statusMessage"`
	// The 'user/profilename' attribute for a Supermarket server.
	Supermarket *string `json:"supermarket"`
	// The address of the dependency.
	URL *string `json:"url"`
}

// Describes a group of requirements, such as those defined in a single file.
type RequirementGroup struct {
	// The unique identifier for the group. Example: the relative path to the file specifying
	// the requirements.
	ID string `json:"id"`
	// The set of requirements as specified by their ids in this group. Example: 'SV-238196'.
	Requirements []string `json:"requirements"`
	// The title of the group - should be human readable.
	Title *string `json:"title"`
}

// A requirement that has been evaluated, including any findings.
//
// Core requirement fields shared between baseline requirements and evaluated requirements.
// Contains the fundamental requirement definition without assessment results.
type EvaluatedRequirement struct {
	// Array of labeled descriptions. At least one description with label 'default' must be
	// present. Convention: place default description first. Common labels: 'default', 'check',
	// 'fix', 'rationale'.
	Descriptions []Description `json:"descriptions"`
	// The current effective status of this requirement after applying the most recent
	// non-expired override, or computed from results if no overrides exist.
	EffectiveStatus *ResultStatus `json:"effectiveStatus"`
	// Supporting evidence for this requirement's findings, such as screenshots, code samples,
	// or log excerpts.
	Evidence []Evidence `json:"evidence"`
	// Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
	// POAMs do NOT change effectiveStatus - they track the work being done to address a
	// failure. Separate from statusOverrides which DO change status.
	Poams []Poam `json:"poams"`
	// The set of all tests within the requirement and their results.
	Results []RequirementResult `json:"results"`
	// Explicit severity rating. Typically derived from impact score but provided explicitly for
	// clarity.
	Severity *Severity `json:"severity,omitempty"`
	// The explicit location of the requirement within the source code.
	SourceLocation SourceLocation `json:"sourceLocation"`
	// Chronological history of all status overrides applied to this requirement. Status
	// overrides are intentional changes to the compliance status (waivers, attestations). Most
	// recent override should be first in array. Preserves full audit trail.
	StatusOverrides []StatusOverride `json:"statusOverrides"`
	// The requirement identifier. Example: 'SV-238196'.
	ID string `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).
	Impact float64 `json:"impact"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.
	Tags map[string]interface{} `json:"tags"`
	// The raw source code of the requirement. Set to null for manual-only requirements or
	// requirements not yet implemented. Note that if this is an overlay, it does not include
	// the underlying source code.
	Code *string `json:"code"`
	// The set of references to external documents.
	Refs []Reference `json:"refs"`
	// The title - is nullable.
	Title *string `json:"title"`
}

type Description struct {
	// The description text content.
	Data string `json:"data"`
	// Description category. The 'default' label is required for the primary description. Common
	// labels: 'default', 'check', 'fix', 'rationale'. Tools may use custom labels.
	Label string `json:"label"`
}

// Supporting evidence for a finding or override, such as screenshots, code samples, log
// excerpts, or URLs.
type Evidence struct {
	// Timestamp when this evidence was captured. ISO 8601 format.
	CapturedAt *time.Time `json:"capturedAt"`
	// Identity of who or what captured this evidence.
	CapturedBy *Identity `json:"capturedBy"`
	// The evidence content. For screenshots/files: base64-encoded data or URL. For code/logs:
	// the raw text. For URLs: the URL string.
	Data string `json:"data"`
	// Human-readable description of what this evidence shows.
	Description *string `json:"description"`
	// Encoding used for the data. Example: 'base64', 'utf-8'.
	Encoding *string `json:"encoding"`
	// MIME type of the evidence. Example: 'image/png', 'text/plain', 'application/json'.
	MIMEType *string `json:"mimeType"`
	// Size of the evidence data in bytes.
	Size *float64 `json:"size"`
	// The type of evidence being provided.
	Type EvidenceType `json:"type"`
}

// Represents an identity that performed an action, such as capturing evidence or applying
// an override.
//
// Identity of who created this POA&M. For simple cases, use type 'simple' with just an
// identifier.
//
// The identity that created this signature.
//
// Identity of who applied this status override. For simple cases, use type 'simple' with
// just an identifier.
//
// The identity of the person or system responsible for executing the test. This could be a
// human auditor manually completing a checklist, an automated CI/CD system, or a security
// tool. Optional field to support both automated and manual HDF generation.
type Identity struct {
	// Optional description of the identity or identity system, particularly useful when type is
	// 'other'.
	Description *string `json:"description"`
	// The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'.
	Identifier string `json:"identifier"`
	// The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
	// 'system' for automated systems, 'simple' for basic string identifiers without additional
	// classification, or 'other' for custom identity systems.
	Type IdentityType `json:"type"`
}

// Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
// POAMs do NOT change the effectiveStatus - the requirement remains in its current state
// while the POA&M tracks remediation efforts.
type Poam struct {
	// Timestamp when this POA&M was created. ISO 8601 format.
	AppliedAt time.Time `json:"appliedAt"`
	// Identity of who created this POA&M. For simple cases, use type 'simple' with just an
	// identifier.
	AppliedBy Identity `json:"appliedBy"`
	// Supporting evidence for this POA&M, such as documentation of compensating controls or
	// mitigation implementation.
	Evidence []Evidence `json:"evidence"`
	// Optional expiration date for this POA&M requiring review/renewal. ISO 8601 format.
	ExpiresAt *time.Time `json:"expiresAt"`
	// Detailed explanation of the plan, including what actions will be taken.
	Explanation string `json:"explanation"`
	// Optional array of milestones tracking progress toward completion.
	Milestones []Milestone `json:"milestones"`
	// SHA-256 checksum of the previous amendment in chronological order. Creates a
	// tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
	// on a requirement.
	PreviousChecksum *Checksum `json:"previousChecksum"`
	// Optional digital signature for enhanced trust and non-repudiation.
	Signature *Signature `json:"signature"`
	// The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
	// compensating controls. 'riskAcceptance' documents decision to accept risk.
	Type PoamType `json:"type"`
}

// A milestone or task within a POA&M remediation plan.
type Milestone struct {
	// Actual completion timestamp. ISO 8601 format.
	CompletedAt *time.Time `json:"completedAt"`
	// Identity of who completed this milestone.
	CompletedBy *Identity `json:"completedBy"`
	// Description of this milestone or task.
	Description string `json:"description"`
	// Estimated completion date. ISO 8601 format.
	EstimatedCompletion time.Time `json:"estimatedCompletion"`
	// Current status of this milestone.
	Status Status `json:"status"`
}

// A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
// security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
// signing methods via JWK, PEM, or Base58 key formats.
type Signature struct {
	// Challenge value from the verifier, used in challenge-response authentication.
	Challenge *string `json:"challenge"`
	// When the signature was created. ISO 8601 format.
	Created time.Time `json:"created"`
	// The identity that created this signature.
	Creator Identity `json:"creator"`
	// Domain restriction for the signature, prevents cross-domain replay attacks.
	Domain *string `json:"domain"`
	// Random value to prevent replay attacks.
	Nonce *string `json:"nonce"`
	// The purpose of this signature. Example: 'attestation', 'authentication',
	// 'assertionMethod'.
	ProofPurpose string `json:"proofPurpose"`
	// The base64-encoded or base58-encoded signature value.
	SignatureValue string `json:"signatureValue"`
	// The signature suite type. Example: 'JsonWebSignature2020', 'RsaSignature2018',
	// 'Ed25519Signature2020'.
	Type string `json:"type"`
	// The verification method containing the public key for signature verification.
	VerificationMethod VerificationMethod `json:"verificationMethod"`
}

// The verification method containing the public key for signature verification.
//
// Verification method containing the public key needed to verify a digital signature.
// Supports multiple key formats including JWK (for RSA, EC), PEM, and Base58.
type VerificationMethod struct {
	// The entity that controls this verification method. Can be a DID, URI, or other identifier.
	Controller string `json:"controller"`
	// Public key in Base58 format, commonly used with Ed25519 keys.
	PublicKeyBase58 *string `json:"publicKeyBase58"`
	// Public key in JSON Web Key format.
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk"`
	// Public key in PEM format. Example: '-----BEGIN PUBLIC KEY-----...-----END PUBLIC
	// KEY-----'.
	PublicKeyPem *string `json:"publicKeyPem"`
	// The type of verification method. Example: 'JsonWebKey2020', 'RsaVerificationKey2018',
	// 'Ed25519VerificationKey2020'.
	Type string `json:"type"`
}

// A reference to an external document.
//
// A reference using the 'ref' field.
//
// A URL pointing at the reference.
//
// A URI pointing at the reference.
type Reference struct {
	Ref *Ref    `json:"ref"`
	URL *string `json:"url,omitempty"`
	URI *string `json:"uri,omitempty"`
}

// A test within a requirement and its results and findings such as how long it took to run.
type RequirementResult struct {
	// The stacktrace/backtrace of the exception if one occurred.
	Backtrace []string `json:"backtrace"`
	// A description of this test. Example: 'limits.conf * is expected to include ["hard",
	// "maxlogins", "10"]'.
	CodeDesc string `json:"codeDesc"`
	// The type of exception if an exception was thrown.
	Exception *string `json:"exception"`
	// An explanation of the test result. Typically provided for failed tests, errors, or to
	// explain why a test was not applicable or not reviewed.
	Message *string `json:"message"`
	// The resource used in the test. Example: 'file', 'command', 'service'.
	Resource *string `json:"resource"`
	// The unique identifier of the resource. Example: '/etc/passwd'.
	ResourceID *string `json:"resourceId"`
	// The execution time in seconds for the test.
	RunTime *float64 `json:"runTime"`
	// The time at which the test started.
	StartTime time.Time `json:"startTime"`
	// The status of this test within the requirement. Example: 'failed'.
	Status *ResultStatus `json:"status"`
}

// The explicit location of the requirement within the source code.
//
// The explicit location of a requirement within source code.
type SourceLocation struct {
	// The line on which this requirement is located.
	Line *float64 `json:"line"`
	// Path to the file that this requirement originates from.
	Ref *string `json:"ref"`
}

// An intentional change to a requirement's compliance status (waiver or attestation).
// Status overrides change the effectiveStatus of the requirement. All status overrides must
// have an expiration date to enforce periodic review.
type StatusOverride struct {
	// Timestamp when this status override was applied. ISO 8601 format.
	AppliedAt time.Time `json:"appliedAt"`
	// Identity of who applied this status override. For simple cases, use type 'simple' with
	// just an identifier.
	AppliedBy Identity `json:"appliedBy"`
	// Supporting evidence for this status override, such as screenshots demonstrating manual
	// verification for attestations.
	Evidence []Evidence `json:"evidence"`
	// Timestamp when this status override expires and must be reviewed/renewed. REQUIRED - no
	// permanent status overrides allowed. ISO 8601 format.
	ExpiresAt time.Time `json:"expiresAt"`
	// SHA-256 checksum of the previous amendment in chronological order. Creates a
	// tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
	// on a requirement.
	PreviousChecksum *Checksum `json:"previousChecksum"`
	// Explanation for why this status override was applied.
	Reason string `json:"reason"`
	// Optional digital signature for enhanced trust and non-repudiation. Supports hardware
	// security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing
	// methods.
	Signature *Signature `json:"signature"`
	// The new status this override sets for the requirement. This intentionally changes the
	// compliance status.
	Status ResultStatus `json:"status"`
	// The type of status override. 'waiver' indicates risk acceptance. 'attestation' indicates
	// manual verification.
	Type StatusOverrideType `json:"type"`
}

// A supported platform target. Example: the platform name being 'ubuntu'.
type SupportedPlatform struct {
	// The location of the platform. Can be: 'os', 'aws', 'azure', or 'gcp'.
	Platform *string `json:"platform"`
	// The platform family. Example: 'redhat'.
	PlatformFamily *string `json:"platformFamily"`
	// The platform name - can include wildcards. Example: 'debian'.
	PlatformName *string `json:"platformName"`
	// The release of the platform. Example: '20.04' for 'ubuntu'.
	Release *string `json:"release"`
}

// Information about the tool that generated this HDF file.
type Generator struct {
	// The name of the tool that generated this file. Example: 'Chef InSpec'.
	Name string `json:"name"`
	// The version of the tool. Example: '5.22.3'.
	Version string `json:"version"`
}

// Cryptographic integrity information for verifying the HDF file has not been tampered
// with. If algorithm is provided, checksum must also be provided, and vice versa.
type Integrity struct {
	// The hash algorithm used for the checksum.
	Algorithm *HashAlgorithm `json:"algorithm,omitempty"`
	// The checksum value.
	Checksum *string `json:"checksum,omitempty"`
	// Optional cryptographic signature.
	Signature *string `json:"signature"`
	// Identifier of who signed this file.
	SignedBy *string `json:"signedBy"`
}

// Reference to automated remediation resources for implementing security controls. Points
// to external automation content like Ansible playbooks, Terraform scripts, or
// vendor-provided remediation tools.
type Remediation struct {
	// Optional cryptographic checksum for verifying the integrity of remediation resources
	// fetched from the URI. Recommended for security when referencing external automation
	// scripts.
	Checksum *Checksum `json:"checksum"`
	// URI pointing to automated remediation resources (Ansible playbooks, Terraform scripts,
	// etc.). Examples: GitHub repository, DISA STIG Supplemental Automation Content,
	// vendor-provided scripts.
	URI string `json:"uri"`
}

// Information about the test execution environment. This is distinct from the target being
// scanned - the runner is where the security tool executes, while targets are what is being
// assessed.
type Runner struct {
	// The CPU architecture of the runner system. Example: 'x86_64', 'arm64', 'aarch64'.
	Architecture *string `json:"architecture,omitempty"`
	// The container instance identifier. Example: 'a1b2c3d4e5f6', 'security-scan-job-xyz123'.
	// Can be a Docker container ID, Kubernetes pod name, or other container runtime identifier.
	ContainerID *string `json:"containerId,omitempty"`
	// The container image used for the test execution. Example: 'inspec/inspec:latest',
	// 'ghcr.io/my-org/scanner:v2.1.0'. Useful for CI/CD pipelines where tests run in containers.
	ContainerImage *string `json:"containerImage,omitempty"`
	// The hostname of the runner system. Example: 'ci-runner-01', 'jenkins-agent-03',
	// 'k8s-node-worker-03'.
	Hostname *string `json:"hostname,omitempty"`
	// The name of the runner environment. Examples: 'ubuntu', 'macos', 'windows', 'docker',
	// 'kubernetes-pod', 'manual'.
	Name string `json:"name"`
	// The identity of the person or system responsible for executing the test. This could be a
	// human auditor manually completing a checklist, an automated CI/CD system, or a security
	// tool. Optional field to support both automated and manual HDF generation.
	Operator *Identity `json:"operator,omitempty"`
	// The version/release of the operating system or runtime. Example: '20.04', '13.2', '11'.
	Release *string `json:"release,omitempty"`
}

// Statistics for the assessment run, including duration and result counts.
//
// Statistics for the assessment run(s) such as duration and result counts.
type Statistics struct {
	// How long (in seconds) this assessment run took.
	Duration *float64 `json:"duration"`
	// Breakdowns of requirement statistics by result status.
	Requirements *StatisticHash `json:"requirements"`
}

// Statistics for requirement results, grouped by status.
type StatisticHash struct {
	// Statistics for requirements that encountered an error during assessment.
	Error *StatisticBlock `json:"error"`
	// Statistics for requirements that failed.
	Failed *StatisticBlock `json:"failed"`
	// Statistics for requirements that are not applicable to the target.
	NotApplicable *StatisticBlock `json:"notApplicable"`
	// Statistics for requirements that were not reviewed (manual check required).
	NotReviewed *StatisticBlock `json:"notReviewed"`
	// Statistics for requirements that passed.
	Passed *StatisticBlock `json:"passed"`
	// Deprecated: use 'notApplicable' or 'notReviewed' instead. Statistics for requirements
	// that were skipped.
	Skipped *StatisticBlock `json:"skipped"`
}

// Statistics for a given item, such as the total count.
type StatisticBlock struct {
	// The total count. Example: the total number of requirements in a given category for a run.
	Total int64 `json:"total"`
}

// A scan target. Uses discriminated union pattern with 'type' field as discriminator.
//
// A physical or virtual server, workstation, or network device.
//
// Base properties shared by all target types.
//
// A static container image (not running).
//
// A running container instance.
//
// A container orchestration platform (Kubernetes, OpenShift, ECS, etc.) or workloads
// running on it.
//
// A cloud provider account (AWS account, Azure subscription, GCP project).
//
// A specific cloud resource (EC2 instance, S3 bucket, Azure VM, etc.).
//
// A code repository (for SAST tools).
//
// A running application or API (for DAST tools).
//
// A software artifact or dependency (for SCA tools).
//
// A network segment or network device.
//
// A database instance.
type Target struct {
	// Human-readable name for this target.
	Name string `json:"name"`
	// Target type discriminator.
	Type Name `json:"type"`
	// Fully qualified domain name.
	FQDN *string `json:"fqdn"`
	// IP address of the host.
	IPAddress *string `json:"ipAddress"`
	// MAC address of the host in colon-separated hexadecimal format (e.g., '00:1A:2B:3C:4D:5E').
	MACAddress *string `json:"macAddress"`
	// Operating system name.
	OSName *string `json:"osName"`
	// Operating system version.
	OSVersion *string `json:"osVersion"`
	// Image digest for immutable reference. Example: 'sha256:abc123...'. Must be sha256 (64 hex
	// chars), sha512 (128 hex chars), or blake3 (64 hex chars).
	Digest *string `json:"digest"`
	// Container image ID.
	ImageID *string `json:"imageId"`
	// Container registry. Example: 'docker.io'.
	Registry *string `json:"registry"`
	// Repository name. Example: 'library/nginx'.
	Repository *string `json:"repository"`
	// Image tag. Example: '1.25'.
	Tag *string `json:"tag"`
	// Running container ID.
	ContainerID *string `json:"containerId"`
	// Image the container was started from.
	Image *string `json:"image"`
	// Container runtime. Example: 'docker', 'containerd', 'cri-o'.
	Runtime *string `json:"runtime"`
	// Cluster name.
	ClusterName *string `json:"clusterName"`
	// Namespace within the cluster, if applicable.
	Namespace *string `json:"namespace"`
	// Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'.
	PlatformType *string `json:"platformType"`
	// Platform version.
	//
	// Application version.
	//
	// Package version.
	//
	// Database version.
	Version *string `json:"version"`
	// Cloud account identifier. Example: AWS account ID, Azure subscription ID.
	AccountID *string `json:"accountId"`
	// Cloud provider.
	Provider *Provider `json:"provider"`
	// Cloud region, if applicable.
	//
	// Cloud region where the resource resides.
	Region *string `json:"region"`
	// Amazon Resource Name (AWS only).
	Arn *string `json:"arn"`
	// Provider-specific resource identifier.
	ResourceID *string `json:"resourceId"`
	// Type of cloud resource. Example: 'ec2:instance', 's3:bucket'.
	ResourceType *string `json:"resourceType"`
	// Branch that was scanned.
	Branch *string `json:"branch"`
	// Commit SHA that was scanned.
	Commit *string `json:"commit"`
	// Repository URL.
	//
	// Application URL (for DAST tools).
	URL *string `json:"url"`
	// Environment. Example: 'production', 'staging', 'development'.
	Environment *string `json:"environment"`
	// Package checksum for verification.
	Checksum *string `json:"checksum"`
	// Package manager. Example: 'npm', 'maven', 'pip', 'nuget'.
	PackageManager *string `json:"packageManager"`
	// Package name.
	PackageName *string `json:"packageName"`
	// Network CIDR block.
	CIDR *string `json:"cidr"`
	// Network gateway address.
	Gateway *string `json:"gateway"`
	// Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'.
	Engine *string `json:"engine"`
	// Database host.
	Host *string `json:"host"`
	// Database port.
	Port *int64 `json:"port"`
}

// The hash algorithm used for the checksum.
//
// Supported cryptographic hash algorithms for checksums and integrity verification.
type HashAlgorithm string

const (
	Sha256 HashAlgorithm = "sha256"
	Sha384 HashAlgorithm = "sha384"
	Sha512 HashAlgorithm = "sha512"
)

// The status of an individual test result. 'notApplicable' indicates the requirement does
// not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
// requires manual verification).
//
// The new status this override sets for the requirement. This intentionally changes the
// compliance status.
type ResultStatus string

const (
	Error         ResultStatus = "error"
	Failed        ResultStatus = "failed"
	NotApplicable ResultStatus = "notApplicable"
	NotReviewed   ResultStatus = "notReviewed"
	Passed        ResultStatus = "passed"
)

// The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
// 'system' for automated systems, 'simple' for basic string identifiers without additional
// classification, or 'other' for custom identity systems.
type IdentityType string

const (
	Email       IdentityType = "email"
	PurpleOther IdentityType = "other"
	Simple      IdentityType = "simple"
	System      IdentityType = "system"
	Username    IdentityType = "username"
)

// The type of evidence being provided.
type EvidenceType string

const (
	Code        EvidenceType = "code"
	File        EvidenceType = "file"
	FluffyOther EvidenceType = "other"
	Log         EvidenceType = "log"
	Screenshot  EvidenceType = "screenshot"
	URL         EvidenceType = "url"
)

// Current status of this milestone.
type Status string

const (
	Completed  Status = "completed"
	InProgress Status = "inProgress"
	Pending    Status = "pending"
)

// The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
// compensating controls. 'riskAcceptance' documents decision to accept risk.
type PoamType string

const (
	Mitigation      PoamType = "mitigation"
	RiskAcceptance  PoamType = "riskAcceptance"
	TypeRemediation PoamType = "remediation"
)

// Explicit severity rating. Typically derived from impact score but provided explicitly for
// clarity.
type Severity string

const (
	Critical      Severity = "critical"
	High          Severity = "high"
	Informational Severity = "informational"
	Low           Severity = "low"
	Medium        Severity = "medium"
)

// The type of status override. 'waiver' indicates risk acceptance. 'attestation' indicates
// manual verification.
type StatusOverrideType string

const (
	Attestation StatusOverrideType = "attestation"
	Waiver      StatusOverrideType = "waiver"
)

type Provider string

const (
	Aws           Provider = "aws"
	Azure         Provider = "azure"
	Gcp           Provider = "gcp"
	Oci           Provider = "oci"
	ProviderOther Provider = "other"
)

// A human readable/meaningful reference. Example: a book title.
type Name string

const (
	Application       Name = "application"
	Artifact          Name = "artifact"
	CloudAccount      Name = "cloudAccount"
	CloudResource     Name = "cloudResource"
	ContainerImage    Name = "containerImage"
	ContainerInstance Name = "containerInstance"
	ContainerPlatform Name = "containerPlatform"
	Database          Name = "database"
	Host              Name = "host"
	Network           Name = "network"
	Repository        Name = "repository"
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
