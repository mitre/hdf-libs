/**
 * The category of this annotation.
 *
 * The category of an annotation attached to a comparison.
 */
export var AnnotationCategory;
(function (AnnotationCategory) {
    AnnotationCategory["BaselineChange"] = "baselineChange";
    AnnotationCategory["Drift"] = "drift";
    AnnotationCategory["Remediation"] = "remediation";
    AnnotationCategory["ScannerNote"] = "scannerNote";
    AnnotationCategory["Waiver"] = "waiver";
})(AnnotationCategory || (AnnotationCategory = {}));
/**
 * The state of this baseline in the comparison.
 *
 * The state of this component in the comparison.
 */
export var BaselineDiffState;
(function (BaselineDiffState) {
    BaselineDiffState["Absent"] = "absent";
    BaselineDiffState["New"] = "new";
    BaselineDiffState["Unchanged"] = "unchanged";
    BaselineDiffState["Updated"] = "updated";
})(BaselineDiffState || (BaselineDiffState = {}));
/**
 * The mode of comparison being performed.
 *
 * The mode of comparison. 'temporal' compares the same target over time. 'baseline'
 * compares against a golden reference. 'fleet' compares across multiple systems.
 * 'multiSource' compares outputs from different scanners. 'baselineEvolution' compares two
 * baseline documents to detect requirement changes between versions. 'systemDrift' compares
 * two system documents to detect component-level changes.
 */
export var ComparisonMode;
(function (ComparisonMode) {
    ComparisonMode["Baseline"] = "baseline";
    ComparisonMode["BaselineEvolution"] = "baselineEvolution";
    ComparisonMode["Fleet"] = "fleet";
    ComparisonMode["MultiSource"] = "multiSource";
    ComparisonMode["SystemDrift"] = "systemDrift";
    ComparisonMode["Temporal"] = "temporal";
})(ComparisonMode || (ComparisonMode = {}));
/**
 * The type of change operation.
 */
export var Op;
(function (Op) {
    Op["Add"] = "add";
    Op["Remove"] = "remove";
    Op["Replace"] = "replace";
})(Op || (Op = {}));
/**
 * The reason a requirement's state changed between sources.
 */
export var ChangeReason;
(function (ChangeReason) {
    ChangeReason["BaselineUpgraded"] = "baselineUpgraded";
    ChangeReason["ConfigChanged"] = "configChanged";
    ChangeReason["ControlMapped"] = "controlMapped";
    ChangeReason["ImpactChanged"] = "impactChanged";
    ChangeReason["MetadataChanged"] = "metadataChanged";
    ChangeReason["OverrideAdded"] = "overrideAdded";
    ChangeReason["OverrideExpired"] = "overrideExpired";
    ChangeReason["OverrideModified"] = "overrideModified";
    ChangeReason["OverrideRemoved"] = "overrideRemoved";
    ChangeReason["ResultChanged"] = "resultChanged";
    ChangeReason["ScannerChanged"] = "scannerChanged";
    ChangeReason["TargetChanged"] = "targetChanged";
})(ChangeReason || (ChangeReason = {}));
/**
 * How the conflict was resolved.
 *
 * How a conflict between multiple scanner results was resolved.
 */
export var ConflictResolution;
(function (ConflictResolution) {
    ConflictResolution["Manual"] = "manual";
    ConflictResolution["MostRecent"] = "mostRecent";
    ConflictResolution["MostSevere"] = "mostSevere";
    ConflictResolution["Unresolved"] = "unresolved";
})(ConflictResolution || (ConflictResolution = {}));
/**
 * The strategy that was used to match this requirement across sources.
 *
 * The strategy used to match requirements across sources. 'exactId' matches by identical
 * IDs. 'mappedId' uses an ID mapping table. 'cciMatch'/'nistMatch' match by framework
 * identifiers. 'fuzzyTitle'/'fuzzyContent' use text similarity.
 *
 * The primary strategy used to match requirements across sources.
 */
export var MatchStrategy;
(function (MatchStrategy) {
    MatchStrategy["CciMatch"] = "cciMatch";
    MatchStrategy["ExactID"] = "exactId";
    MatchStrategy["FuzzyContent"] = "fuzzyContent";
    MatchStrategy["FuzzyTitle"] = "fuzzyTitle";
    MatchStrategy["MappedID"] = "mappedId";
    MatchStrategy["NISTMatch"] = "nistMatch";
})(MatchStrategy || (MatchStrategy = {}));
/**
 * The state of this requirement in the comparison.
 *
 * SARIF-compatible vocabulary extended for security. 'new' = present only in new source,
 * 'absent' = present only in old, 'unchanged' = same effective status, 'updated' = status
 * changed (generic), 'fixed' = was failing now passing, 'regressed' = was passing now
 * failing, 'moved' = reorganized same content, 'split'/'merged' = reserved for v1.1.
 */
export var RequirementState;
(function (RequirementState) {
    RequirementState["Absent"] = "absent";
    RequirementState["Fixed"] = "fixed";
    RequirementState["Merged"] = "merged";
    RequirementState["Moved"] = "moved";
    RequirementState["New"] = "new";
    RequirementState["Regressed"] = "regressed";
    RequirementState["Split"] = "split";
    RequirementState["Unchanged"] = "unchanged";
    RequirementState["Updated"] = "updated";
})(RequirementState || (RequirementState = {}));
export var FormatVersion;
(function (FormatVersion) {
    FormatVersion["The100"] = "1.0.0";
})(FormatVersion || (FormatVersion = {}));
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
 * The state of this package: added (new in new SBOM), removed (absent from new SBOM),
 * updated (version changed), unchanged.
 */
export var PackageDiffState;
(function (PackageDiffState) {
    PackageDiffState["Added"] = "added";
    PackageDiffState["Removed"] = "removed";
    PackageDiffState["Unchanged"] = "unchanged";
    PackageDiffState["Updated"] = "updated";
})(PackageDiffState || (PackageDiffState = {}));
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
export var Description;
(function (Description) {
    Description["Application"] = "application";
    Description["Artifact"] = "artifact";
    Description["CloudAccount"] = "cloudAccount";
    Description["CloudResource"] = "cloudResource";
    Description["ContainerImage"] = "containerImage";
    Description["ContainerInstance"] = "containerInstance";
    Description["ContainerPlatform"] = "containerPlatform";
    Description["Database"] = "database";
    Description["Host"] = "host";
    Description["Network"] = "network";
    Description["Repository"] = "repository";
})(Description || (Description = {}));
/**
 * The original format of the source document before conversion to HDF.
 */
export var OriginalFormat;
(function (OriginalFormat) {
    OriginalFormat["HdfV2"] = "hdf-v2";
    OriginalFormat["InspecV1"] = "inspec-v1";
    OriginalFormat["OscalAr"] = "oscal-ar";
    OriginalFormat["Sarif"] = "sarif";
    OriginalFormat["Xccdf"] = "xccdf";
})(OriginalFormat || (OriginalFormat = {}));
/**
 * The role of this source in the comparison.
 *
 * The role of a source document in the comparison.
 */
export var SourceRole;
(function (SourceRole) {
    SourceRole["Golden"] = "golden";
    SourceRole["New"] = "new";
    SourceRole["Old"] = "old";
    SourceRole["Reference"] = "reference";
    SourceRole["System"] = "system";
})(SourceRole || (SourceRole = {}));
