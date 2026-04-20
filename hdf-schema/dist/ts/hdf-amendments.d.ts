/**
 * Waivers, attestations, and POA&Ms that modify requirement compliance status or impact.
 * Amendments are standalone documents that can be applied to results via merge operations.
 */
export interface HdfAmendments {
    /**
     * Unique identifier for this amendments document. Useful for cross-referencing when
     * multiple amendment documents target the same results.
     */
    amendmentId?: string;
    /**
     * Default identity of who created this amendments document. Individual overrides may
     * specify their own appliedBy.
     */
    appliedBy?: Identity;
    /**
     * Identity of the authorizing official who approved these amendments.
     */
    approvedBy?: Identity;
    /**
     * Description of the amendments' purpose and scope.
     */
    description?: string;
    /**
     * Information about the tool that generated this document.
     */
    generator?: Generator;
    /**
     * Cryptographic integrity information for verifying this amendments document has not been
     * tampered with.
     */
    integrity?: Integrity;
    /**
     * Optional key-value labels for grouping and querying amendments.
     */
    labels?: {
        [key: string]: string;
    };
    /**
     * Human-readable name for this amendments document. Example: 'Portal Q1 2026 Waivers'.
     */
    name: string;
    /**
     * The set of amendments (waivers, attestations, exceptions, POA&Ms).
     */
    overrides: StandaloneOverride[];
    /**
     * Document-level digital signature covering all amendments.
     */
    signature?: Signature;
    /**
     * URI to the hdf-system document these amendments apply to.
     */
    systemRef?: string;
    /**
     * Version of this amendments document.
     */
    version?: string;
    [property: string]: any;
}
/**
 * Default identity of who created this amendments document. Individual overrides may
 * specify their own appliedBy.
 *
 * Represents an identity that performed an action, such as capturing evidence or applying
 * an override.
 *
 * Identity of the authorizing official who approved these amendments.
 *
 * Identity of who applied this amendment.
 *
 * Identity of who or what captured this evidence.
 *
 * Identity of who completed this milestone.
 *
 * The identity that created this signature.
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
    type: AppliedByType;
    [property: string]: any;
}
/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export declare enum AppliedByType {
    Email = "email",
    Other = "other",
    Simple = "simple",
    System = "system",
    Username = "username"
}
/**
 * Information about the tool that generated this document.
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
 * Cryptographic integrity information for verifying this amendments document has not been
 * tampered with.
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
export declare enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512"
}
/**
 * A standalone amendment that modifies a requirement's compliance status and/or impact
 * score. At least one of status or impact must be set. Extends the inline Override concept
 * with requirementId and baselineRef for use outside of results documents.
 */
export interface StandaloneOverride {
    /**
     * When this amendment was applied. ISO 8601 format.
     */
    appliedAt: Date;
    /**
     * Identity of who applied this amendment.
     */
    appliedBy: Identity;
    /**
     * Name of the baseline containing the requirement. Required when the system has multiple
     * baselines with potentially overlapping requirement IDs.
     */
    baselineRef?: string;
    /**
     * componentId of the component this amendment is scoped to. When set, the amendment only
     * applies to the specified component. When omitted, the amendment applies system-wide.
     */
    componentRef?: string;
    /**
     * Supporting evidence (screenshots, logs, URLs, documents).
     */
    evidence?: Evidence[];
    /**
     * When this amendment expires and must be reviewed. No permanent amendments. ISO 8601
     * format.
     */
    expiresAt: Date;
    /**
     * Override to the requirement's impact score. At least one of status or impact must be set.
     */
    impact?: ImpactOverride;
    /**
     * componentId of the local component that provides this control. Set when the provider is
     * in the same system. Omit for external or cross-system providers; the reason field
     * explains the source. Primarily used with type 'inherited'.
     */
    inheritedFrom?: string;
    /**
     * Remediation milestones (primarily for POA&M type amendments).
     */
    milestones?: Milestone[];
    /**
     * Checksum of the prior amendment in the chain. Creates a tamper-evident linked list. Null
     * for the first amendment.
     */
    previousChecksum?: Checksum;
    /**
     * Justification for this amendment.
     */
    reason: string;
    /**
     * The ID of the requirement being amended. Must match a requirement ID in the referenced
     * baseline.
     */
    requirementId: string;
    /**
     * Digital signature for non-repudiation.
     */
    signature?: Signature;
    /**
     * The new status this amendment sets. Optional when only impact is being overridden.
     */
    status?: ResultStatus;
    /**
     * The type of amendment.
     */
    type: OverrideType;
    [property: string]: any;
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
 * Override to the requirement's impact score. At least one of status or impact must be
 * set.
 *
 * An override to the requirement's impact score. The prior impact is the original result
 * value or the preceding override in the chain.
 */
export interface ImpactOverride {
    /**
     * The overridden impact score (0.0–1.0).
     */
    value: number;
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
 * Checksum of the prior amendment in the chain. Creates a tamper-evident linked list. Null
 * for the first amendment.
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
 * Digital signature for non-repudiation.
 *
 * A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
 * security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
 * signing methods via JWK, PEM, or Base58 key formats.
 *
 * Document-level digital signature covering all amendments.
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
 * The new status this amendment sets. Optional when only impact is being overridden.
 *
 * The status of an individual test result. 'notApplicable' indicates the requirement does
 * not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
 * requires manual verification).
 */
export declare enum ResultStatus {
    Error = "error",
    Failed = "failed",
    NotApplicable = "notApplicable",
    NotReviewed = "notReviewed",
    Passed = "passed"
}
/**
 * The type of amendment.
 *
 * The type of amendment, aligned with FedRAMP deviation request categories. 'waiver': risk
 * accepted by Authorizing Official. 'attestation': manually verified by assessor. 'poam':
 * remediation tracked (no status change). 'inherited': control provided by another
 * component or system. 'falsePositive': scanner incorrectly identified a finding — for
 * compliance scans (STIG, CIS), the check actually passes, so status is typically set to
 * 'passed'; for vulnerability scans (CVE, SCA), the flagged vulnerability does not apply to
 * this system, so status is typically set to 'notApplicable'. The disposition field on the
 * requirement distinguishes false positives from genuinely not-applicable findings.
 * 'riskAdjustment': impact score adjusted based on environmental context (FedRAMP Risk
 * Adjustment); does not change pass/fail status, only impact via the impact field.
 * 'operationalRequirement': deviation required by operational constraints (FedRAMP
 * Operational Requirement); the finding cannot be remediated because the system requires
 * the affected functionality. Remains an open risk. Migration note: 'exception' was removed
 * in v3.1.0 — use 'waiver' with status 'notApplicable' instead.
 */
export declare enum OverrideType {
    Attestation = "attestation",
    FalsePositive = "falsePositive",
    Inherited = "inherited",
    OperationalRequirement = "operationalRequirement",
    Poam = "poam",
    RiskAdjustment = "riskAdjustment",
    Waiver = "waiver"
}
