/**
 * The comparison operator used when evaluating this input against observed values.
 *
 * Comparison operator for evaluating the input value against observed values. Numeric:
 * eq/ne/lt/le/gt/ge. String: eq/ne/contains/matches. Collection: in/notIn.
 */
export var ComparisonOperator;
(function (ComparisonOperator) {
    ComparisonOperator["Contains"] = "contains";
    ComparisonOperator["Eq"] = "eq";
    ComparisonOperator["Ge"] = "ge";
    ComparisonOperator["Gt"] = "gt";
    ComparisonOperator["In"] = "in";
    ComparisonOperator["LE"] = "le";
    ComparisonOperator["Lt"] = "lt";
    ComparisonOperator["Matches"] = "matches";
    ComparisonOperator["Ne"] = "ne";
    ComparisonOperator["NotIn"] = "notIn";
})(ComparisonOperator || (ComparisonOperator = {}));
/**
 * The data type of this input.
 *
 * The data type of the input value. Aligns with InSpec input types.
 */
export var InputType;
(function (InputType) {
    InputType["Array"] = "Array";
    InputType["Boolean"] = "Boolean";
    InputType["Hash"] = "Hash";
    InputType["Numeric"] = "Numeric";
    InputType["Regexp"] = "Regexp";
    InputType["String"] = "String";
})(InputType || (InputType = {}));
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
 *
 * Severity rating for a requirement. Typically derived from the numeric impact score.
 */
export var Severity;
(function (Severity) {
    Severity["Critical"] = "critical";
    Severity["High"] = "high";
    Severity["Informational"] = "informational";
    Severity["Low"] = "low";
    Severity["Medium"] = "medium";
})(Severity || (Severity = {}));
