/**
 * Current Authorization to Operate (ATO) status.
 *
 * Authorization to Operate (ATO) status for the system.
 */
export var AuthorizationStatus;
(function (AuthorizationStatus) {
    AuthorizationStatus["Authorized"] = "authorized";
    AuthorizationStatus["ConditionallyAuthorized"] = "conditionallyAuthorized";
    AuthorizationStatus["Denied"] = "denied";
    AuthorizationStatus["NotYetRequested"] = "notYetRequested";
    AuthorizationStatus["PendingAuthorization"] = "pendingAuthorization";
    AuthorizationStatus["Revoked"] = "revoked";
})(AuthorizationStatus || (AuthorizationStatus = {}));
/**
 * FIPS 199 security categorization (impact level).
 *
 * FIPS 199 security categorization level (impact level).
 */
export var CategorizationLevel;
(function (CategorizationLevel) {
    CategorizationLevel["High"] = "high";
    CategorizationLevel["Low"] = "low";
    CategorizationLevel["Moderate"] = "moderate";
})(CategorizationLevel || (CategorizationLevel = {}));
/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export var Type;
(function (Type) {
    Type["Email"] = "email";
    Type["Other"] = "other";
    Type["Simple"] = "simple";
    Type["System"] = "system";
    Type["Username"] = "username";
})(Type || (Type = {}));
export var CloudProvider;
(function (CloudProvider) {
    CloudProvider["Aws"] = "aws";
    CloudProvider["Azure"] = "azure";
    CloudProvider["Gcp"] = "gcp";
    CloudProvider["Oci"] = "oci";
    CloudProvider["Other"] = "other";
})(CloudProvider || (CloudProvider = {}));
/**
 * Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present.
 */
export var SbomFormat;
(function (SbomFormat) {
    SbomFormat["Cyclonedx"] = "cyclonedx";
    SbomFormat["Spdx"] = "spdx";
})(SbomFormat || (SbomFormat = {}));
/**
 * IP address of the host.
 */
export var BoundaryDescription;
(function (BoundaryDescription) {
    BoundaryDescription["Application"] = "application";
    BoundaryDescription["Artifact"] = "artifact";
    BoundaryDescription["CloudAccount"] = "cloudAccount";
    BoundaryDescription["CloudResource"] = "cloudResource";
    BoundaryDescription["ContainerImage"] = "containerImage";
    BoundaryDescription["ContainerInstance"] = "containerInstance";
    BoundaryDescription["ContainerPlatform"] = "containerPlatform";
    BoundaryDescription["Database"] = "database";
    BoundaryDescription["Host"] = "host";
    BoundaryDescription["Network"] = "network";
    BoundaryDescription["Repository"] = "repository";
})(BoundaryDescription || (BoundaryDescription = {}));
/**
 * NIST SP 800-53 control designation. 'common': fully provided by another component or
 * system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
 * shared responsibility between provider and inheritor.
 */
export var Designation;
(function (Designation) {
    Designation["Common"] = "common";
    Designation["Hybrid"] = "hybrid";
    Designation["SystemSpecific"] = "system-specific";
})(Designation || (Designation = {}));
/**
 * Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
 * means data flows in both directions (e.g., request/response).
 */
export var Direction;
(function (Direction) {
    Direction["Bidirectional"] = "bidirectional";
    Direction["Unidirectional"] = "unidirectional";
})(Direction || (Direction = {}));
/**
 * The hash algorithm used for the checksum.
 *
 * Supported cryptographic hash algorithms for checksums and integrity verification.
 */
export var HashAlgorithm;
(function (HashAlgorithm) {
    HashAlgorithm["Sha256"] = "sha256";
    HashAlgorithm["Sha384"] = "sha384";
    HashAlgorithm["Sha512"] = "sha512";
})(HashAlgorithm || (HashAlgorithm = {}));
