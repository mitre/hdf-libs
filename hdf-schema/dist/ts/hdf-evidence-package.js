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
/**
 * The type of HDF document being referenced.
 *
 * The type of document referenced in the evidence package.
 */
export var ContentType;
(function (ContentType) {
    ContentType["HdfAmendments"] = "hdf-amendments";
    ContentType["HdfBaseline"] = "hdf-baseline";
    ContentType["HdfComparison"] = "hdf-comparison";
    ContentType["HdfPlan"] = "hdf-plan";
    ContentType["HdfResults"] = "hdf-results";
    ContentType["HdfSystem"] = "hdf-system";
    ContentType["Sbom"] = "sbom";
})(ContentType || (ContentType = {}));
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
