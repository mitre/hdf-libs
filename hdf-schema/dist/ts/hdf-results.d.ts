/**
 * The top level value containing all assessment results.
 */
export interface HdfResults {
    /**
     * Information on the baselines that were evaluated, including findings.
     */
    baselines: EvaluatedBaseline[];
    /**
     * The components that were assessed. Each component describes a system element (host,
     * container, cloud resource, application, etc.) with optional identity, SBOM, and external
     * references.
     */
    components?: Component[];
    /**
     * Reserved for tool-specific data not defined in the HDF standard. Use this to preserve
     * original tool output, auxiliary data, or custom metadata.
     */
    extensions?: {
        [key: string]: any;
    };
    /**
     * Information about the tool that generated this file.
     */
    generator?: Generator;
    /**
     * Unique identifier for this assessment run.
     */
    id?: string;
    /**
     * Cryptographic integrity information for verifying this file.
     */
    integrity?: Integrity;
    /**
     * Reference to an hdf-plan document describing the assessment plan that produced these
     * results. May be a relative path, absolute URI, or fragment identifier.
     */
    planRef?: string;
    /**
     * Optional reference to automated remediation resources (Ansible playbooks, Terraform
     * scripts, etc.) for fixing failing requirements found in this assessment.
     */
    remediation?: Remediation;
    /**
     * Information about the test execution environment where the security tool was run.
     * Distinct from targets (what is being tested).
     */
    runner?: Runner;
    /**
     * Statistics for the assessment run, including duration and result counts.
     */
    statistics?: Statistics;
    /**
     * Reference to an hdf-system document describing the system under assessment. May be a
     * relative path, absolute URI, or fragment identifier.
     */
    systemRef?: string;
    /**
     * When this assessment was executed.
     */
    timestamp?: Date;
    /**
     * The security tool that produced the assessment data in this file.
     */
    tool?: Tool;
    [property: string]: any;
}
/**
 * Information on a baseline that was evaluated, including any findings.
 *
 * Shared metadata fields for baselines. Used in both standalone baseline documents and
 * evaluated baseline results.
 */
export interface EvaluatedBaseline {
    /**
     * The set of dependencies this baseline depends on.
     */
    depends?: Dependency[];
    /**
     * The description - should be more detailed than the summary.
     */
    description?: string;
    /**
     * Reserved for tool-specific baseline metadata not defined in the HDF standard.
     */
    extensions?: {
        [key: string]: any;
    };
    /**
     * A set of descriptions for the requirement groups.
     */
    groups?: RequirementGroup[];
    /**
     * Typed inputs used to parameterize this baseline at execution time. See the Input
     * primitive for the full schema.
     */
    inputs?: Input[];
    /**
     * Cryptographic integrity information for verifying this baseline has not been tampered
     * with.
     */
    integrity?: Integrity;
    /**
     * SHA-256 checksum of the original baseline definition file (before execution). This is an
     * immutable reference to the baseline as defined, used to detect tampering with baseline
     * requirements or metadata.
     */
    originalChecksum?: Checksum;
    /**
     * The name of the parent baseline if this is a dependency of another.
     */
    parentBaseline?: string;
    /**
     * The set of requirements including any findings. A baseline must have at least one
     * requirement.
     */
    requirements: EvaluatedRequirement[];
    /**
     * SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).
     * Used to detect tampering with test results. Compare with currentChecksum to verify
     * amendment integrity.
     */
    resultsChecksum?: Checksum;
    /**
     * An explanation of the baseline status. Example: why it was skipped, failed to load, or
     * any other status details.
     */
    statusMessage?: string;
    /**
     * The name - must be unique.
     */
    name: string;
    /**
     * The copyright holder(s).
     */
    copyright?: string;
    /**
     * The email address or other contact information of the copyright holder(s).
     */
    copyrightEmail?: string;
    /**
     * Optional key-value labels for flexible grouping. Well-known keys: system, component,
     * environment, region, team. Values must be strings.
     */
    labels?: {
        [key: string]: string;
    };
    /**
     * The copyright license. Example: 'Apache-2.0'.
     */
    license?: string;
    /**
     * The maintainer(s).
     */
    maintainer?: string;
    /**
     * The status. Example: 'loaded'.
     */
    status?: string;
    /**
     * The summary. Example: the Security Technical Implementation Guide (STIG) header.
     */
    summary?: string;
    /**
     * The set of supported platform targets.
     */
    supports?: SupportedPlatform[];
    /**
     * The title - should be human readable.
     */
    title?: string;
    /**
     * The version of the baseline.
     */
    version?: string;
    [property: string]: any;
}
/**
 * A dependency for a baseline. Can include relative paths or URLs for where to find the
 * dependency.
 */
export interface Dependency {
    /**
     * The branch name for a git repo.
     */
    branch?: string;
    /**
     * The 'user/profilename' attribute for an Automate server.
     */
    compliance?: string;
    /**
     * The location of the git repo. Example:
     * 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git'.
     */
    git?: string;
    /**
     * The name or assigned alias.
     */
    name?: string;
    /**
     * The relative path if the dependency is locally available.
     */
    path?: string;
    /**
     * The status. Should be: 'loaded', 'failed', or 'skipped'.
     */
    status?: string;
    /**
     * The reason for the status if it is 'failed' or 'skipped'.
     */
    statusMessage?: string;
    /**
     * The 'user/profilename' attribute for a Supermarket server.
     */
    supermarket?: string;
    /**
     * The address of the dependency.
     */
    url?: string;
    [property: string]: any;
}
/**
 * Describes a group of requirements, such as those defined in a single file.
 */
export interface RequirementGroup {
    /**
     * The unique identifier for the group. Example: the relative path to the file specifying
     * the requirements.
     */
    id: string;
    /**
     * The set of requirements as specified by their ids in this group. Example: 'SV-238196'.
     */
    requirements: string[];
    /**
     * The title of the group - should be human readable.
     */
    title?: string;
    [property: string]: any;
}
/**
 * A typed input parameter that bridges governance requirements and scanner automation.
 * Inputs carry expected configuration values with type information, comparison operators,
 * and validation constraints, enabling traceability from policy through to scan results.
 */
export interface Input {
    /**
     * Validation constraints for the input value.
     */
    constraints?: InputConstraints;
    /**
     * Human-readable description of what this input controls.
     */
    description?: string;
    /**
     * The input name. Must be unique within a baseline or results document. Example:
     * 'max_concurrent_sessions'.
     */
    name: string;
    /**
     * The comparison operator used when evaluating this input against observed values.
     */
    operator?: ComparisonOperator;
    /**
     * Whether this input must be provided. Defaults to false if omitted.
     */
    required?: boolean;
    /**
     * Whether this input contains sensitive data (passwords, keys). Sensitive values should be
     * redacted in output. Defaults to false if omitted.
     */
    sensitive?: boolean;
    /**
     * The data type of this input.
     */
    type?: InputType;
    /**
     * The input value. Type should match the declared type field. Accepts any JSON value.
     */
    value?: any;
    [property: string]: any;
}
/**
 * Validation constraints for the input value.
 *
 * Validation constraints for an input value.
 */
export interface InputConstraints {
    /**
     * Enumeration of permitted values.
     */
    allowedValues?: any[];
    /**
     * Maximum allowed value (for Numeric inputs).
     */
    max?: number;
    /**
     * Minimum allowed value (for Numeric inputs).
     */
    min?: number;
    /**
     * Regular expression pattern the value must match (for String inputs).
     */
    pattern?: string;
    [property: string]: any;
}
/**
 * The comparison operator used when evaluating this input against observed values.
 *
 * Comparison operator for evaluating the input value against observed values. Numeric:
 * eq/ne/lt/le/gt/ge. String: eq/ne/contains/matches. Collection: in/notIn.
 */
export declare enum ComparisonOperator {
    Contains = "contains",
    Eq = "eq",
    Ge = "ge",
    Gt = "gt",
    In = "in",
    LE = "le",
    Lt = "lt",
    Matches = "matches",
    Ne = "ne",
    NotIn = "notIn"
}
/**
 * The data type of this input.
 *
 * The data type of the input value. Aligns with InSpec input types.
 */
export declare enum InputType {
    Array = "Array",
    Boolean = "Boolean",
    Hash = "Hash",
    Numeric = "Numeric",
    Regexp = "Regexp",
    String = "String"
}
/**
 * Cryptographic integrity information for verifying this baseline has not been tampered
 * with.
 *
 * Cryptographic integrity information for verifying the HDF file has not been tampered
 * with. If algorithm is provided, checksum must also be provided, and vice versa.
 *
 * Cryptographic integrity information for verifying this file.
 */
export interface Integrity {
    /**
     * The hash algorithm used for the checksum.
     */
    algorithm?: HashAlgorithm;
    /**
     * The checksum value.
     */
    checksum?: string;
    /**
     * Optional cryptographic signature.
     */
    signature?: string;
    /**
     * Identifier of who signed this file.
     */
    signedBy?: string;
    [property: string]: any;
}
/**
 * The hash algorithm used for the checksum.
 *
 * Supported cryptographic hash algorithms for checksums and integrity verification.
 */
export declare enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512"
}
/**
 * SHA-256 checksum of the original baseline definition file (before execution). This is an
 * immutable reference to the baseline as defined, used to detect tampering with baseline
 * requirements or metadata.
 *
 * Cryptographic checksum for baseline integrity verification.
 *
 * SHA-256 checksum of the previous amendment in chronological order. Creates a
 * tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
 * on a requirement.
 *
 * SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).
 * Used to detect tampering with test results. Compare with currentChecksum to verify
 * amendment integrity.
 *
 * Optional cryptographic checksum for verifying the integrity of remediation resources
 * fetched from the URI. Recommended for security when referencing external automation
 * scripts.
 */
export interface Checksum {
    /**
     * The hash algorithm used for the checksum.
     */
    algorithm: HashAlgorithm;
    /**
     * The checksum value.
     */
    value: string;
    [property: string]: any;
}
/**
 * A requirement that has been evaluated, including any findings.
 *
 * Core requirement fields shared between baseline requirements and evaluated requirements.
 * Contains the fundamental requirement definition without assessment results.
 */
export interface EvaluatedRequirement {
    /**
     * Array of labeled descriptions. At least one description with label 'default' must be
     * present. Convention: place default description first. Common labels: 'default', 'check',
     * 'fix', 'rationale'.
     */
    descriptions: Description[];
    /**
     * The current effective status of this requirement after applying the most recent
     * non-expired override, or computed from results if no overrides exist.
     */
    effectiveStatus?: ResultStatus;
    /**
     * Supporting evidence for this requirement's findings, such as screenshots, code samples,
     * or log excerpts.
     */
    evidence?: Evidence[];
    /**
     * Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
     * POAMs do NOT change effectiveStatus - they track the work being done to address a
     * failure. Separate from statusOverrides which DO change status.
     */
    poams?: Poam[];
    /**
     * The set of all tests within the requirement and their results.
     */
    results: RequirementResult[];
    /**
     * Explicit severity rating. Typically derived from impact score but provided explicitly for
     * clarity.
     */
    severity?: Severity;
    /**
     * The explicit location of the requirement within the source code.
     */
    sourceLocation?: SourceLocation;
    /**
     * Chronological history of all status overrides applied to this requirement. Status
     * overrides are intentional changes to the compliance status (waivers, attestations). Most
     * recent override should be first in array. Preserves full audit trail.
     */
    statusOverrides?: StatusOverride[];
    /**
     * The requirement identifier. Example: 'SV-238196'.
     */
    id: string;
    /**
     * The impactfulness or severity (0.0 to 1.0).
     */
    impact: number;
    /**
     * A set of tags - usually metadata like CCI, STIG ID, severity.
     */
    tags: {
        [key: string]: any;
    };
    /**
     * The raw source code of the requirement. Set to null for manual-only requirements or
     * requirements not yet implemented. Note that if this is an overlay, it does not include
     * the underlying source code.
     */
    code?: string;
    /**
     * The set of references to external documents.
     */
    refs?: Reference[];
    /**
     * The title - is nullable.
     */
    title?: string;
    [property: string]: any;
}
export interface Description {
    /**
     * The description text content.
     */
    data: string;
    /**
     * Description category. The 'default' label is required for the primary description. Common
     * labels: 'default', 'check', 'fix', 'rationale'. Tools may use custom labels.
     */
    label: string;
    [property: string]: any;
}
/**
 * The current effective status of this requirement after applying the most recent
 * non-expired override, or computed from results if no overrides exist.
 *
 * The status of an individual test result. 'notApplicable' indicates the requirement does
 * not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
 * requires manual verification).
 *
 * The status of this test within the requirement. Example: 'failed'.
 *
 * The new status this override sets for the requirement. This intentionally changes the
 * compliance status.
 */
export declare enum ResultStatus {
    Error = "error",
    Failed = "failed",
    NotApplicable = "notApplicable",
    NotReviewed = "notReviewed",
    Passed = "passed"
}
/**
 * Supporting evidence for a finding or override, such as screenshots, code samples, log
 * excerpts, or URLs.
 */
export interface Evidence {
    /**
     * Timestamp when this evidence was captured. ISO 8601 format.
     */
    capturedAt?: Date;
    /**
     * Identity of who or what captured this evidence.
     */
    capturedBy?: Identity;
    /**
     * The evidence content. For screenshots/files: base64-encoded data or URL. For code/logs:
     * the raw text. For URLs: the URL string.
     */
    data: string;
    /**
     * Human-readable description of what this evidence shows.
     */
    description?: string;
    /**
     * Encoding used for the data. Example: 'base64', 'utf-8'.
     */
    encoding?: string;
    /**
     * MIME type of the evidence. Example: 'image/png', 'text/plain', 'application/json'.
     */
    mimeType?: string;
    /**
     * Size of the evidence data in bytes.
     */
    size?: number;
    /**
     * The type of evidence being provided.
     */
    type: EvidenceType;
    [property: string]: any;
}
/**
 * Identity of who or what captured this evidence.
 *
 * Represents an identity that performed an action, such as capturing evidence or applying
 * an override.
 *
 * Identity of who created this POA&M. For simple cases, use type 'simple' with just an
 * identifier.
 *
 * Identity of who completed this milestone.
 *
 * The identity that created this signature.
 *
 * Identity of who applied this status override. For simple cases, use type 'simple' with
 * just an identifier.
 *
 * Identity of the person or system that approved this override.
 *
 * Team or individual responsible for this component. Enables per-component ownership when
 * different teams manage different parts of a system.
 *
 * The identity of the person or system responsible for executing the test. This could be a
 * human auditor manually completing a checklist, an automated CI/CD system, or a security
 * tool. Optional field to support both automated and manual HDF generation.
 */
export interface Identity {
    /**
     * Optional description of the identity or identity system, particularly useful when type is
     * 'other'.
     */
    description?: string;
    /**
     * The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'.
     */
    identifier: string;
    /**
     * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
     * 'system' for automated systems, 'simple' for basic string identifiers without additional
     * classification, or 'other' for custom identity systems.
     */
    type: OperatorType;
    [property: string]: any;
}
/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export declare enum OperatorType {
    Email = "email",
    Other = "other",
    Simple = "simple",
    System = "system",
    Username = "username"
}
/**
 * The type of evidence being provided.
 */
export declare enum EvidenceType {
    Code = "code",
    File = "file",
    Log = "log",
    Other = "other",
    Screenshot = "screenshot",
    URL = "url"
}
/**
 * Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
 * POAMs do NOT change the effectiveStatus - the requirement remains in its current state
 * while the POA&M tracks remediation efforts.
 */
export interface Poam {
    /**
     * Timestamp when this POA&M was created. ISO 8601 format.
     */
    appliedAt: Date;
    /**
     * Identity of who created this POA&M. For simple cases, use type 'simple' with just an
     * identifier.
     */
    appliedBy: Identity;
    /**
     * Supporting evidence for this POA&M, such as documentation of compensating controls or
     * mitigation implementation.
     */
    evidence?: Evidence[];
    /**
     * Optional expiration date for this POA&M requiring review/renewal. ISO 8601 format.
     */
    expiresAt?: Date;
    /**
     * Detailed explanation of the plan, including what actions will be taken.
     */
    explanation: string;
    /**
     * Optional array of milestones tracking progress toward completion.
     */
    milestones?: Milestone[];
    /**
     * SHA-256 checksum of the previous amendment in chronological order. Creates a
     * tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
     * on a requirement.
     */
    previousChecksum?: Checksum;
    /**
     * Optional digital signature for enhanced trust and non-repudiation.
     */
    signature?: Signature;
    /**
     * The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
     * compensating controls. 'riskAcceptance' documents decision to accept risk.
     */
    type: PoamType;
    [property: string]: any;
}
/**
 * A milestone or task within a POA&M remediation plan.
 */
export interface Milestone {
    /**
     * Actual completion timestamp. ISO 8601 format.
     */
    completedAt?: Date;
    /**
     * Identity of who completed this milestone.
     */
    completedBy?: Identity;
    /**
     * Description of this milestone or task.
     */
    description: string;
    /**
     * Estimated completion date. ISO 8601 format.
     */
    estimatedCompletion: Date;
    /**
     * Current status of this milestone.
     */
    status: Status;
    [property: string]: any;
}
/**
 * Current status of this milestone.
 */
export declare enum Status {
    Completed = "completed",
    InProgress = "inProgress",
    Pending = "pending"
}
/**
 * Optional digital signature for enhanced trust and non-repudiation.
 *
 * A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
 * security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
 * signing methods via JWK, PEM, or Base58 key formats.
 *
 * Optional digital signature for enhanced trust and non-repudiation. Supports hardware
 * security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing
 * methods.
 */
export interface Signature {
    /**
     * Challenge value from the verifier, used in challenge-response authentication.
     */
    challenge?: string;
    /**
     * When the signature was created. ISO 8601 format.
     */
    created: Date;
    /**
     * The identity that created this signature.
     */
    creator: Identity;
    /**
     * Domain restriction for the signature, prevents cross-domain replay attacks.
     */
    domain?: string;
    /**
     * Random value to prevent replay attacks.
     */
    nonce?: string;
    /**
     * The purpose of this signature. Example: 'attestation', 'authentication',
     * 'assertionMethod'.
     */
    proofPurpose: string;
    /**
     * The base64-encoded or base58-encoded signature value.
     */
    signatureValue: string;
    /**
     * The signature suite type. Example: 'JsonWebSignature2020', 'RsaSignature2018',
     * 'Ed25519Signature2020'.
     */
    type: string;
    /**
     * The verification method containing the public key for signature verification.
     */
    verificationMethod: VerificationMethod;
    [property: string]: any;
}
/**
 * The verification method containing the public key for signature verification.
 *
 * Verification method containing the public key needed to verify a digital signature.
 * Supports multiple key formats including JWK (for RSA, EC), PEM, and Base58.
 */
export interface VerificationMethod {
    /**
     * The entity that controls this verification method. Can be a DID, URI, or other identifier.
     */
    controller: string;
    /**
     * Public key in Base58 format, commonly used with Ed25519 keys.
     */
    publicKeyBase58?: string;
    /**
     * Public key in JSON Web Key format.
     */
    publicKeyJwk?: {
        [key: string]: any;
    };
    /**
     * Public key in PEM format. Example: '-----BEGIN PUBLIC KEY-----...-----END PUBLIC
     * KEY-----'.
     */
    publicKeyPem?: string;
    /**
     * The type of verification method. Example: 'JsonWebKey2020', 'RsaVerificationKey2018',
     * 'Ed25519VerificationKey2020'.
     */
    type: string;
    [property: string]: any;
}
/**
 * The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
 * compensating controls. 'riskAcceptance' documents decision to accept risk.
 */
export declare enum PoamType {
    Mitigation = "mitigation",
    Remediation = "remediation",
    RiskAcceptance = "riskAcceptance"
}
/**
 * A reference to an external document.
 *
 * A reference using the 'ref' field.
 *
 * A URL pointing at the reference.
 *
 * A URI pointing at the reference.
 */
export interface Reference {
    ref?: {
        [key: string]: any;
    }[] | string;
    url?: string;
    uri?: string;
    [property: string]: any;
}
/**
 * A test within a requirement and its results and findings such as how long it took to run.
 */
export interface RequirementResult {
    /**
     * The stacktrace/backtrace of the exception if one occurred.
     */
    backtrace?: string[];
    /**
     * A description of this test. Example: 'limits.conf * is expected to include ["hard",
     * "maxlogins", "10"]'.
     */
    codeDesc: string;
    /**
     * The type of exception if an exception was thrown.
     */
    exception?: string;
    /**
     * An explanation of the test result. Typically provided for failed tests, errors, or to
     * explain why a test was not applicable or not reviewed.
     */
    message?: string;
    /**
     * The resource used in the test. Example: 'file', 'command', 'service'.
     */
    resource?: string;
    /**
     * The unique identifier of the resource. Example: '/etc/passwd'.
     */
    resourceId?: string;
    /**
     * The execution time in seconds for the test.
     */
    runTime?: number;
    /**
     * The time at which the test started.
     */
    startTime: Date;
    /**
     * The status of this test within the requirement. Example: 'failed'.
     */
    status: ResultStatus;
    [property: string]: any;
}
/**
 * Explicit severity rating. Typically derived from impact score but provided explicitly for
 * clarity.
 *
 * Severity rating for a requirement. Typically derived from the numeric impact score.
 */
export declare enum Severity {
    Critical = "critical",
    High = "high",
    Informational = "informational",
    Low = "low",
    Medium = "medium"
}
/**
 * The explicit location of the requirement within the source code.
 *
 * The explicit location of a requirement within source code.
 */
export interface SourceLocation {
    /**
     * The line on which this requirement is located.
     */
    line?: number;
    /**
     * Path to the file that this requirement originates from.
     */
    ref?: string;
    [property: string]: any;
}
/**
 * An intentional change to a requirement's compliance status (waiver or attestation).
 * Status overrides change the effectiveStatus of the requirement. All status overrides must
 * have an expiration date to enforce periodic review.
 */
export interface StatusOverride {
    /**
     * Timestamp when this status override was applied. ISO 8601 format.
     */
    appliedAt: Date;
    /**
     * Identity of who applied this status override. For simple cases, use type 'simple' with
     * just an identifier.
     */
    appliedBy: Identity;
    /**
     * Supporting evidence for this status override, such as screenshots demonstrating manual
     * verification for attestations.
     */
    evidence?: Evidence[];
    /**
     * Timestamp when this status override expires and must be reviewed/renewed. REQUIRED - no
     * permanent status overrides allowed. ISO 8601 format.
     */
    expiresAt: Date;
    /**
     * SHA-256 checksum of the previous amendment in chronological order. Creates a
     * tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
     * on a requirement.
     */
    previousChecksum?: Checksum;
    /**
     * Explanation for why this status override was applied.
     */
    reason: string;
    /**
     * Optional digital signature for enhanced trust and non-repudiation. Supports hardware
     * security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing
     * methods.
     */
    signature?: Signature;
    /**
     * The new status this override sets for the requirement. This intentionally changes the
     * compliance status.
     */
    status: ResultStatus;
    /**
     * The type of status override applied to this requirement.
     */
    type: OverrideType;
    [property: string]: any;
}
/**
 * The type of status override applied to this requirement.
 *
 * The type of amendment. 'waiver': risk accepted (AO). 'attestation': manually verified
 * (assessor). 'exception': not applicable (system owner + AO). 'poam': remediation tracked
 * (no status change). 'inherited': control provided by another component or system
 * (overrides to notApplicable/passed).
 */
export declare enum OverrideType {
    Attestation = "attestation",
    Exception = "exception",
    Inherited = "inherited",
    Poam = "poam",
    Waiver = "waiver"
}
/**
 * A supported platform target. Example: the platform name being 'ubuntu'.
 */
export interface SupportedPlatform {
    /**
     * The location of the platform. Can be: 'os', 'aws', 'azure', or 'gcp'.
     */
    platform?: string;
    /**
     * The platform family. Example: 'redhat'.
     */
    platformFamily?: string;
    /**
     * The platform name - can include wildcards. Example: 'debian'.
     */
    platformName?: string;
    /**
     * The release of the platform. Example: '20.04' for 'ubuntu'.
     */
    release?: string;
    [property: string]: any;
}
/**
 * A system component. Uses discriminated union pattern with 'type' field as discriminator.
 * Superset of Target with identity, external IDs, and SBOM support.
 *
 * A physical or virtual server, workstation, or network device.
 *
 * Base properties shared by all component types. Extends the Target concept with stable
 * identity, external references, and SBOM embedding.
 *
 * A static container image (not running).
 *
 * A running container instance.
 *
 * A container orchestration platform (Kubernetes, OpenShift, ECS, etc.).
 *
 * A cloud provider account (AWS account, Azure subscription, GCP project).
 *
 * A specific cloud resource (EC2 instance, S3 bucket, Azure VM, etc.).
 *
 * A code repository (for SAST tools).
 *
 * A running application or API (for DAST tools).
 *
 * A software artifact or dependency (for SCA tools).
 *
 * A network segment or network device.
 *
 * A database instance.
 */
export interface Component {
    /**
     * Names of baselines that apply to this component.
     */
    baselineRefs?: string[];
    /**
     * Stable UUID (RFC 4122) for this component. Required in hdf-system documents, optional in
     * hdf-results. Enables cross-document correlation, diffing, and data flow references.
     */
    componentId?: string;
    /**
     * Description of this component's role or purpose.
     */
    description?: string;
    /**
     * Map of external identifier scheme to value. Well-known schemes: aws (instance ID), azure
     * (resource ID), cmdb (asset ID), emass (system ID), cve (CVE ID). Custom schemes are
     * allowed.
     */
    externalIds?: {
        [key: string]: string;
    };
    /**
     * System-specific overrides for baseline input values.
     */
    inputOverrides?: InputOverride[];
    /**
     * Optional key-value labels for flexible grouping. Well-known keys: system, component,
     * environment, region, team. Values must be strings.
     */
    labels?: {
        [key: string]: string;
    };
    /**
     * Human-readable name for this component.
     */
    name: string;
    /**
     * Team or individual responsible for this component. Enables per-component ownership when
     * different teams manage different parts of a system.
     */
    owner?: Identity;
    /**
     * Embedded CycloneDX or SPDX SBOM document representing this component's software
     * inventory. The sbomFormat field determines which format constraints apply.
     */
    sbom?: any;
    /**
     * Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present.
     */
    sbomFormat?: SbomFormat;
    /**
     * URI reference to an external CycloneDX or SPDX SBOM document for this component. May be a
     * relative path, absolute URI, or fragment identifier.
     */
    sbomRef?: string;
    /**
     * Label selector to match targets belonging to this component during migration. Targets
     * with matching labels are automatically included.
     */
    targetSelector?: {
        [key: string]: string;
    };
    /**
     * Component type discriminator. Same values as Target types.
     */
    type: Copyright;
    /**
     * Fully qualified domain name.
     */
    fqdn?: string;
    /**
     * IP address of the host.
     */
    ipAddress?: string;
    /**
     * MAC address in colon-separated hexadecimal format.
     */
    macAddress?: string;
    /**
     * Operating system name.
     */
    osName?: string;
    /**
     * Operating system version.
     */
    osVersion?: string;
    /**
     * Image digest for immutable reference.
     */
    digest?: string;
    /**
     * Container image ID.
     */
    imageId?: string;
    /**
     * Container registry. Example: 'docker.io'.
     */
    registry?: string;
    /**
     * Repository name. Example: 'library/nginx'.
     */
    repository?: string;
    /**
     * Image tag. Example: '1.25'.
     */
    tag?: string;
    /**
     * Running container ID.
     */
    containerId?: string;
    /**
     * Image the container was started from.
     */
    image?: string;
    /**
     * Container runtime. Example: 'docker', 'containerd', 'cri-o'.
     */
    runtime?: string;
    /**
     * Cluster name.
     */
    clusterName?: string;
    /**
     * Namespace within the cluster, if applicable.
     */
    namespace?: string;
    /**
     * Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'.
     */
    platformType?: string;
    /**
     * Platform version.
     *
     * Application version.
     *
     * Package version.
     *
     * Database version.
     */
    version?: string;
    /**
     * Cloud account identifier.
     */
    accountId?: string;
    /**
     * Cloud provider.
     */
    provider?: CloudProvider | null;
    /**
     * Cloud region, if applicable.
     *
     * Cloud region where the resource resides.
     */
    region?: string;
    /**
     * Amazon Resource Name (AWS only).
     */
    arn?: string;
    /**
     * Provider-specific resource identifier.
     */
    resourceId?: string;
    /**
     * Type of cloud resource. Example: 'ec2:instance', 's3:bucket'.
     */
    resourceType?: string;
    /**
     * Branch that was scanned.
     */
    branch?: string;
    /**
     * Commit SHA that was scanned.
     */
    commit?: string;
    /**
     * Repository URL.
     *
     * Application URL (for DAST tools).
     */
    url?: string;
    /**
     * Environment. Example: 'production', 'staging', 'development'.
     */
    environment?: string;
    /**
     * Package checksum for verification.
     */
    checksum?: string;
    /**
     * Package manager. Example: 'npm', 'maven', 'pip', 'nuget'.
     */
    packageManager?: string;
    /**
     * Package name.
     */
    packageName?: string;
    /**
     * Network CIDR block.
     */
    cidr?: string;
    /**
     * Network gateway address.
     */
    gateway?: string;
    /**
     * Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'.
     */
    engine?: string;
    /**
     * Database host.
     */
    host?: string;
    /**
     * Database port.
     */
    port?: number;
    [property: string]: any;
}
/**
 * An override of a baseline input value for a specific component. Enables system-specific
 * tailoring of baseline parameters.
 */
export interface InputOverride {
    /**
     * Identity of the person or system that approved this override.
     */
    approvedBy?: Identity;
    /**
     * Name of the baseline this override applies to. If omitted, applies to all baselines that
     * define this input.
     */
    baselineRef?: string;
    /**
     * Name of the input being overridden. Must match an Input.name in the referenced baseline.
     */
    inputName: string;
    /**
     * Rationale for why this override is needed.
     */
    justification?: string;
    /**
     * The overridden value. Should match the type of the original input.
     */
    value: any;
    [property: string]: any;
}
export declare enum CloudProvider {
    Aws = "aws",
    Azure = "azure",
    Gcp = "gcp",
    Oci = "oci",
    Other = "other"
}
/**
 * Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present.
 */
export declare enum SbomFormat {
    Cyclonedx = "cyclonedx",
    Spdx = "spdx"
}
/**
 * A human readable/meaningful reference. Example: a book title.
 *
 * IP address of the host.
 */
export declare enum Copyright {
    Application = "application",
    Artifact = "artifact",
    CloudAccount = "cloudAccount",
    CloudResource = "cloudResource",
    ContainerImage = "containerImage",
    ContainerInstance = "containerInstance",
    ContainerPlatform = "containerPlatform",
    Database = "database",
    Host = "host",
    Network = "network",
    Repository = "repository"
}
/**
 * Information about the tool that generated this file.
 *
 * Information about the tool that generated this HDF file.
 */
export interface Generator {
    /**
     * The name of the software that produced this HDF file. Example: 'gosec-to-hdf'.
     */
    name: string;
    /**
     * The version of the tool. Example: '5.22.3'.
     */
    version: string;
    [property: string]: any;
}
/**
 * Optional reference to automated remediation resources (Ansible playbooks, Terraform
 * scripts, etc.) for fixing failing requirements found in this assessment.
 *
 * Reference to automated remediation resources for implementing security controls. Points
 * to external automation content like Ansible playbooks, Terraform scripts, or
 * vendor-provided remediation tools.
 */
export interface Remediation {
    /**
     * Optional cryptographic checksum for verifying the integrity of remediation resources
     * fetched from the URI. Recommended for security when referencing external automation
     * scripts.
     */
    checksum?: Checksum;
    /**
     * URI pointing to automated remediation resources (Ansible playbooks, Terraform scripts,
     * etc.). Examples: GitHub repository, DISA STIG Supplemental Automation Content,
     * vendor-provided scripts.
     */
    uri: string;
    [property: string]: any;
}
/**
 * Information about the test execution environment where the security tool was run.
 * Distinct from targets (what is being tested).
 *
 * Information about the test execution environment. This is distinct from the target being
 * scanned - the runner is where the security tool executes, while targets are what is being
 * assessed.
 */
export interface Runner {
    /**
     * The CPU architecture of the runner system. Example: 'x86_64', 'arm64', 'aarch64'.
     */
    architecture?: string;
    /**
     * The container instance identifier. Example: 'a1b2c3d4e5f6', 'security-scan-job-xyz123'.
     * Can be a Docker container ID, Kubernetes pod name, or other container runtime identifier.
     */
    containerId?: string;
    /**
     * The container image used for the test execution. Example: 'inspec/inspec:latest',
     * 'ghcr.io/my-org/scanner:v2.1.0'. Useful for CI/CD pipelines where tests run in containers.
     */
    containerImage?: string;
    /**
     * The hostname of the runner system. Example: 'ci-runner-01', 'jenkins-agent-03',
     * 'k8s-node-worker-03'.
     */
    hostname?: string;
    /**
     * The name of the runner environment. Examples: 'ubuntu', 'macos', 'windows', 'docker',
     * 'kubernetes-pod', 'manual'.
     */
    name: string;
    /**
     * The identity of the person or system responsible for executing the test. This could be a
     * human auditor manually completing a checklist, an automated CI/CD system, or a security
     * tool. Optional field to support both automated and manual HDF generation.
     */
    operator?: Identity;
    /**
     * The version/release of the operating system or runtime. Example: '20.04', '13.2', '11'.
     */
    release?: string;
    [property: string]: any;
}
/**
 * Statistics for the assessment run, including duration and result counts.
 *
 * Statistics for the assessment run(s) such as duration and result counts.
 */
export interface Statistics {
    /**
     * How long (in seconds) this assessment run took.
     */
    duration?: number;
    /**
     * Breakdowns of requirement statistics by result status.
     */
    requirements?: StatisticHash;
    [property: string]: any;
}
/**
 * Breakdowns of requirement statistics by result status.
 *
 * Statistics for requirement results, grouped by status.
 */
export interface StatisticHash {
    /**
     * Statistics for requirements that encountered an error during assessment.
     */
    error?: StatisticBlock;
    /**
     * Statistics for requirements that failed.
     */
    failed?: StatisticBlock;
    /**
     * Statistics for requirements that are not applicable to the target.
     */
    notApplicable?: StatisticBlock;
    /**
     * Statistics for requirements that were not reviewed (manual check required).
     */
    notReviewed?: StatisticBlock;
    /**
     * Statistics for requirements that passed.
     */
    passed?: StatisticBlock;
    [property: string]: any;
}
/**
 * Statistics for requirements that encountered an error during assessment.
 *
 * Statistics for a given item, such as the total count.
 *
 * Statistics for requirements that failed.
 *
 * Statistics for requirements that are not applicable to the target.
 *
 * Statistics for requirements that were not reviewed (manual check required).
 *
 * Statistics for requirements that passed.
 */
export interface StatisticBlock {
    /**
     * The total count. Example: the total number of requirements in a given category for a run.
     */
    total: number;
    [property: string]: any;
}
/**
 * The security tool that produced the assessment data in this file.
 *
 * The security tool that produced the assessment data represented in this HDF file. Aligns
 * with SARIF, OSCAL, and CycloneDX terminology.
 */
export interface Tool {
    /**
     * The file format, if it is a recognized named format shared by multiple tools. Examples:
     * 'SARIF', 'XCCDF'. Omit for tool-specific formats where the tool name already implies the
     * format (Nessus XML, gosec JSON).
     */
    format?: string;
    /**
     * The name of the security tool that produced the data. Examples: 'gosec', 'Semgrep',
     * 'OpenSCAP', 'AWS Config', 'Nessus'. Omit if the tool cannot be identified.
     */
    name?: string;
    /**
     * Version of the source tool, if available in the tool's output. Example: '5.22.3'.
     */
    version?: string;
    [property: string]: any;
}
