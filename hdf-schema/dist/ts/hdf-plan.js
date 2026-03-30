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
 * The type of assessment plan.
 *
 * The type of assessment. 'automated' for scanner-driven, 'manual' for human-performed,
 * 'hybrid' for both.
 */
export var PlanType;
(function (PlanType) {
    PlanType["Automated"] = "automated";
    PlanType["Hybrid"] = "hybrid";
    PlanType["Manual"] = "manual";
})(PlanType || (PlanType = {}));
