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
 * Explicit severity rating. Typically derived from impact score but provided explicitly for
 * clarity.
 */
export var Severity;
(function (Severity) {
    Severity["Critical"] = "critical";
    Severity["High"] = "high";
    Severity["Informational"] = "informational";
    Severity["Low"] = "low";
    Severity["Medium"] = "medium";
})(Severity || (Severity = {}));
