/**
 * Bundles references to all HDF documents for audit, authorization, and compliance review.
 * Each content entry references a document by type, URI, and checksum for integrity
 * verification.
 */
export interface HdfEvidencePackage {
    /**
     * Summary of assessment completeness and compliance status.
     */
    completenessCheck?: CompletenessCheck;
    /**
     * References to HDF documents included in this evidence package.
     */
    contents: ContentReference[];
    /**
     * Description of the evidence package's purpose and scope.
     */
    description?: string;
    /**
     * Information about the tool that generated this document.
     */
    generator?: Generator;
    /**
     * Cryptographic integrity information for verifying this evidence package has not been
     * tampered with.
     */
    integrity?: Integrity;
    /**
     * Optional key-value labels for grouping and querying evidence packages.
     */
    labels?: { [key: string]: string };
    /**
     * Human-readable name for this evidence package. Example: 'Enterprise Portal ATO Evidence -
     * Q1 2026'.
     */
    name: string;
    /**
     * Unique identifier for this evidence package. Optional in casual use, expected in
     * production ATO submissions. Auto-generated if omitted during creation.
     */
    packageId?: string;
    /**
     * URI to the hdf-plan document that drove this assessment. Used for completeness
     * verification — every baseline in the plan should have a corresponding results document in
     * this package.
     */
    planRef?: string;
    /**
     * When this evidence package was prepared. ISO 8601 format.
     */
    preparedAt?: Date;
    /**
     * Identity of who prepared this evidence package.
     */
    preparedBy?: Identity;
    /**
     * Digital signature covering the entire evidence package.
     */
    signature?: Signature;
    /**
     * URI to the hdf-system document this evidence package covers.
     */
    systemRef?: string;
    /**
     * Version of this evidence package.
     */
    version?: string;
    [property: string]: any;
}

/**
 * Summary of assessment completeness and compliance status.
 *
 * Informational summary of assessment completeness. Not authoritative — tools should
 * compute these from the referenced documents.
 */
export interface CompletenessCheck {
    /**
     * Whether all baselines referenced by system components have assessment results.
     */
    allBaselinesAssessed?: boolean;
    /**
     * Whether all system components have at least one matching target in the results.
     */
    allComponentsCovered?: boolean;
    /**
     * Overall compliance percentage across all assessments.
     */
    compliancePercent?: number;
    /**
     * Number of waivers/amendments that have expired.
     */
    expiredWaivers?: number;
    /**
     * SBOM coverage across system components.
     */
    sbomCoverage?: SBOMCoverage;
    /**
     * Number of POA&M items that are still open (not completed).
     */
    unresolvedPoams?: number;
    [property: string]: any;
}

/**
 * SBOM coverage across system components.
 *
 * SBOM coverage statistics for the system.
 */
export interface SBOMCoverage {
    /**
     * Number of system components that have an associated SBOM.
     */
    componentsWithSbom?: number;
    /**
     * Total number of components in the system.
     */
    totalComponents?: number;
    [property: string]: any;
}

/**
 * A reference to an HDF document or SBOM included in the evidence package.
 */
export interface ContentReference {
    /**
     * Cryptographic checksum for verifying the referenced document's integrity.
     */
    checksum?: Checksum;
    /**
     * componentId of the component this content entry relates to. Use to link SBOMs, results,
     * or other documents to a specific system component.
     */
    componentRef?: string;
    /**
     * Optional description of this content entry.
     */
    description?: string;
    /**
     * The type of HDF document being referenced.
     */
    type: ContentType;
    /**
     * URI to the document. Can be a relative path or absolute URL.
     */
    uri: string;
    [property: string]: any;
}

/**
 * Cryptographic checksum for verifying the referenced document's integrity.
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
 * The type of HDF document being referenced.
 *
 * The type of document referenced in the evidence package.
 */
export enum ContentType {
    HdfAmendments = "hdf-amendments",
    HdfBaseline = "hdf-baseline",
    HdfComparison = "hdf-comparison",
    HdfPlan = "hdf-plan",
    HdfResults = "hdf-results",
    HdfSystem = "hdf-system",
    Sbom = "sbom",
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
 * Cryptographic integrity information for verifying this evidence package has not been
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
 * Identity of who prepared this evidence package.
 *
 * Represents an identity that performed an action, such as capturing evidence or applying
 * an override.
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
    type: Type;
    [property: string]: any;
}

/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export enum Type {
    Email = "email",
    Other = "other",
    Simple = "simple",
    System = "system",
    Username = "username",
}

/**
 * Digital signature covering the entire evidence package.
 *
 * A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
 * security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
 * signing methods via JWK, PEM, or Base58 key formats.
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
    publicKeyJwk?: { [key: string]: any };
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
