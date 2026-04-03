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
export var ResultStatus;
(function (ResultStatus) {
    ResultStatus["Error"] = "error";
    ResultStatus["Failed"] = "failed";
    ResultStatus["NotApplicable"] = "notApplicable";
    ResultStatus["NotReviewed"] = "notReviewed";
    ResultStatus["Passed"] = "passed";
})(ResultStatus || (ResultStatus = {}));
/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export var OperatorType;
(function (OperatorType) {
    OperatorType["Email"] = "email";
    OperatorType["Other"] = "other";
    OperatorType["Simple"] = "simple";
    OperatorType["System"] = "system";
    OperatorType["Username"] = "username";
})(OperatorType || (OperatorType = {}));
/**
 * The type of evidence being provided.
 */
export var EvidenceType;
(function (EvidenceType) {
    EvidenceType["Code"] = "code";
    EvidenceType["File"] = "file";
    EvidenceType["Log"] = "log";
    EvidenceType["Other"] = "other";
    EvidenceType["Screenshot"] = "screenshot";
    EvidenceType["URL"] = "url";
})(EvidenceType || (EvidenceType = {}));
/**
 * Current status of this milestone.
 */
export var Status;
(function (Status) {
    Status["Completed"] = "completed";
    Status["InProgress"] = "inProgress";
    Status["Pending"] = "pending";
})(Status || (Status = {}));
/**
 * The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
 * compensating controls. 'riskAcceptance' documents decision to accept risk.
 */
export var PoamType;
(function (PoamType) {
    PoamType["Mitigation"] = "mitigation";
    PoamType["Remediation"] = "remediation";
    PoamType["RiskAcceptance"] = "riskAcceptance";
})(PoamType || (PoamType = {}));
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
/**
 * The type of status override applied to this requirement.
 *
 * The type of amendment. 'waiver': risk accepted (AO). 'attestation': manually verified
 * (assessor). 'exception': not applicable (system owner + AO). 'poam': remediation tracked
 * (no status change). 'inherited': control provided by another component or system
 * (overrides to notApplicable/passed).
 */
export var OverrideType;
(function (OverrideType) {
    OverrideType["Attestation"] = "attestation";
    OverrideType["Exception"] = "exception";
    OverrideType["Inherited"] = "inherited";
    OverrideType["Poam"] = "poam";
    OverrideType["Waiver"] = "waiver";
})(OverrideType || (OverrideType = {}));
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
 * A human readable/meaningful reference. Example: a book title.
 *
 * IP address of the host.
 */
export var Copyright;
(function (Copyright) {
    Copyright["Application"] = "application";
    Copyright["Artifact"] = "artifact";
    Copyright["CloudAccount"] = "cloudAccount";
    Copyright["CloudResource"] = "cloudResource";
    Copyright["ContainerImage"] = "containerImage";
    Copyright["ContainerInstance"] = "containerInstance";
    Copyright["ContainerPlatform"] = "containerPlatform";
    Copyright["Database"] = "database";
    Copyright["Host"] = "host";
    Copyright["Network"] = "network";
    Copyright["Repository"] = "repository";
})(Copyright || (Copyright = {}));
