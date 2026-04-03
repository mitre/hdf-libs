/**
 * Information on the set of requirements that can be assessed, including baseline metadata
 * and requirement definitions.
 *
 * Shared metadata fields for baselines. Used in both standalone baseline documents and
 * evaluated baseline results.
 */
export interface HdfBaseline {
    /**
     * The set of dependencies this baseline depends on.
     */
    depends?: Dependency[];
    /**
     * The tool that generated this file.
     */
    generator?: Generator;
    /**
     * A set of descriptions for the requirement groups.
     */
    groups?: RequirementGroup[];
    /**
     * The input(s) or attribute(s) to be used in the run.
     */
    inputs?: Input[];
    /**
     * Cryptographic integrity information for verifying this baseline has not been tampered
     * with.
     */
    integrity?: Integrity;
    /**
     * Optional reference to automated remediation resources (Ansible playbooks, Terraform
     * scripts, etc.) for implementing the security controls defined in this baseline.
     */
    remediation?: Remediation;
    /**
     * The set of requirements - contains no findings as the assessment has not yet occurred.
     */
    requirements: BaselineRequirement[];
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
    labels?: { [key: string]: string };
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
 * The tool that generated this file.
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
export enum ComparisonOperator {
    Contains = "contains",
    Eq = "eq",
    Ge = "ge",
    Gt = "gt",
    In = "in",
    LE = "le",
    Lt = "lt",
    Matches = "matches",
    Ne = "ne",
    NotIn = "notIn",
}

/**
 * The data type of this input.
 *
 * The data type of the input value. Aligns with InSpec input types.
 */
export enum InputType {
    Array = "Array",
    Boolean = "Boolean",
    Hash = "Hash",
    Numeric = "Numeric",
    Regexp = "Regexp",
    String = "String",
}

/**
 * Cryptographic integrity information for verifying this baseline has not been tampered
 * with.
 *
 * Cryptographic integrity information for verifying the HDF file has not been tampered
 * with. If algorithm is provided, checksum must also be provided, and vice versa.
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
export enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512",
}

/**
 * Optional reference to automated remediation resources (Ansible playbooks, Terraform
 * scripts, etc.) for implementing the security controls defined in this baseline.
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
 * Optional cryptographic checksum for verifying the integrity of remediation resources
 * fetched from the URI. Recommended for security when referencing external automation
 * scripts.
 *
 * Cryptographic checksum for baseline integrity verification.
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
 * A requirement definition without assessment results.
 *
 * Core requirement fields shared between baseline requirements and evaluated requirements.
 * Contains the fundamental requirement definition without assessment results.
 */
export interface BaselineRequirement {
    /**
     * Array of labeled descriptions. At least one description with label 'default' must be
     * present. Convention: place default description first. Common labels: 'default', 'check',
     * 'fix', 'rationale'.
     */
    descriptions: Description[];
    /**
     * Explicit severity rating. Typically derived from impact score but provided explicitly for
     * clarity.
     */
    severity?: Severity;
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
    tags: { [key: string]: any };
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
     * The explicit location of the requirement within the source code.
     */
    sourceLocation?: SourceLocation;
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
 * A reference to an external document.
 *
 * A reference using the 'ref' field.
 *
 * A URL pointing at the reference.
 *
 * A URI pointing at the reference.
 */
export interface Reference {
    ref?: { [key: string]: any }[] | string;
    url?: string;
    uri?: string;
    [property: string]: any;
}

/**
 * Explicit severity rating. Typically derived from impact score but provided explicitly for
 * clarity.
 *
 * Severity rating for a requirement. Typically derived from the numeric impact score.
 */
export enum Severity {
    Critical = "critical",
    High = "high",
    Informational = "informational",
    Low = "low",
    Medium = "medium",
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
