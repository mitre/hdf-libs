/**
 * The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
 * 'system' for automated systems, 'simple' for basic string identifiers without additional
 * classification, or 'other' for custom identity systems.
 */
export var AppliedByType;
(function (AppliedByType) {
    AppliedByType["Email"] = "email";
    AppliedByType["Other"] = "other";
    AppliedByType["Simple"] = "simple";
    AppliedByType["System"] = "system";
    AppliedByType["Username"] = "username";
})(AppliedByType || (AppliedByType = {}));
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
 * The new status this amendment sets. Optional when only impact is being overridden.
 *
 * The status of an individual test result. 'notApplicable' indicates the requirement does
 * not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
 * requires manual verification).
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
 * the affected functionality. Remains an open risk.
 */
export var OverrideType;
(function (OverrideType) {
    OverrideType["Attestation"] = "attestation";
    OverrideType["FalsePositive"] = "falsePositive";
    OverrideType["Inherited"] = "inherited";
    OverrideType["OperationalRequirement"] = "operationalRequirement";
    OverrideType["Poam"] = "poam";
    OverrideType["RiskAdjustment"] = "riskAdjustment";
    OverrideType["Waiver"] = "waiver";
})(OverrideType || (OverrideType = {}));
