/**
 * Structured comparison between two or more HDF security assessment documents. Supports
 * temporal, baseline, fleet, and multi-source comparison modes.
 */
export interface HdfComparison {
    /**
     * Map of annotation IDs to annotation objects, providing context or action items for
     * requirement diffs.
     */
    annotations?: { [key: string]: Annotation };
    /**
     * Comparison of baselines between sources.
     */
    baselineDiffs?: BaselineDiff[];
    /**
     * The mode of comparison being performed.
     */
    comparisonMode: ComparisonMode;
    /**
     * Comparison of components between two system documents. Used in systemDrift mode.
     */
    componentDiffs?: ComponentDiff[];
    /**
     * External/metadata changes separate from status changes (Terraform pattern).
     */
    drift?: RequirementDiff[];
    /**
     * Reserved for tool-specific data not defined in the HDF standard.
     */
    extensions?: { [key: string]: any };
    /**
     * Schema version for this comparison format.
     */
    formatVersion: FormatVersion;
    /**
     * Information about the tool that generated this comparison.
     */
    generator?: Generator;
    /**
     * Cryptographic integrity information for verifying this comparison document.
     */
    integrity?: Integrity;
    /**
     * Configuration for how requirements were matched across sources.
     */
    matching?: MatchingConfig;
    /**
     * Comparison of packages between two SBOMs. Used in systemDrift mode for SBOM comparison.
     */
    packageDiffs?: PackageDiff[];
    /**
     * Detailed comparison of individual requirements between sources.
     */
    requirementDiffs: RequirementDiff[];
    /**
     * The source documents being compared. At least two sources are required.
     */
    sources: Source[];
    /**
     * Summary statistics for the overall comparison.
     */
    summary: ComparisonSummary;
    /**
     * URI identifying the system being compared in systemDrift mode.
     */
    systemRef?: string;
    /**
     * When this comparison was performed.
     */
    timestamp?: Date;
    [property: string]: any;
}

/**
 * An annotation attached to a comparison, providing context or action items.
 */
export interface Annotation {
    /**
     * The category of this annotation.
     */
    category?: AnnotationCategory;
    /**
     * Detailed description of the annotation.
     */
    description?: string;
    /**
     * Human-readable label for this annotation.
     */
    label: string;
    /**
     * Whether this annotation requires human confirmation before acting on it.
     */
    needsConfirmation?: boolean;
    [property: string]: any;
}

/**
 * The category of this annotation.
 *
 * The category of an annotation attached to a comparison.
 */
export enum AnnotationCategory {
    BaselineChange = "baselineChange",
    Drift = "drift",
    Remediation = "remediation",
    ScannerNote = "scannerNote",
    Waiver = "waiver",
}

/**
 * Comparison of a baseline between sources.
 */
export interface BaselineDiff {
    /**
     * The source of any ID mapping used to correlate requirements across baseline versions.
     */
    mappingSource?: string;
    /**
     * Name of the baseline being compared.
     */
    name: string;
    /**
     * Version of the baseline in the new source.
     */
    newVersion?: string;
    /**
     * Version of the baseline in the old source.
     */
    oldVersion?: string;
    /**
     * The state of this baseline in the comparison.
     */
    state: BaselineDiffState;
    [property: string]: any;
}

/**
 * The state of this baseline in the comparison.
 *
 * The state of this component in the comparison.
 */
export enum BaselineDiffState {
    Absent = "absent",
    New = "new",
    Unchanged = "unchanged",
    Updated = "updated",
}

/**
 * The mode of comparison being performed.
 *
 * The mode of comparison. 'temporal' compares the same target over time. 'baseline'
 * compares against a golden reference. 'fleet' compares across multiple systems.
 * 'multiSource' compares outputs from different scanners. 'baselineEvolution' compares two
 * baseline documents to detect requirement changes between versions. 'systemDrift' compares
 * two system documents to detect component-level changes.
 */
export enum ComparisonMode {
    Baseline = "baseline",
    BaselineEvolution = "baselineEvolution",
    Fleet = "fleet",
    MultiSource = "multiSource",
    SystemDrift = "systemDrift",
    Temporal = "temporal",
}

/**
 * Comparison of a single component between two system document versions.
 */
export interface ComponentDiff {
    /**
     * Component snapshot from the new system document.
     */
    after?: any;
    /**
     * Component snapshot from the old system document.
     */
    before?: any;
    /**
     * Detailed field-level changes between the before and after component snapshots.
     */
    fieldChanges?: FieldChange[];
    /**
     * Component name used for matching across system versions.
     */
    name: string;
    /**
     * The state of this component in the comparison.
     */
    state: BaselineDiffState;
    [property: string]: any;
}

/**
 * A single field-level change between two versions of a requirement.
 */
export interface FieldChange {
    /**
     * The new value of the field (for 'add' and 'replace' operations).
     */
    newValue?: any;
    /**
     * The previous value of the field (for 'remove' and 'replace' operations).
     */
    oldValue?: any;
    /**
     * The type of change operation.
     */
    op: Op;
    /**
     * JSON Pointer path to the changed field.
     */
    path: string;
    [property: string]: any;
}

/**
 * The type of change operation.
 */
export enum Op {
    Add = "add",
    Remove = "remove",
    Replace = "replace",
}

/**
 * A comparison of a single requirement between sources, including state, changes, and full
 * before/after snapshots.
 */
export interface RequirementDiff {
    /**
     * The requirement as it appeared in the new source. Null when state is 'absent'.
     */
    after: any;
    /**
     * Sensitive data from the new source that should not be included in the main after snapshot.
     */
    afterSensitive?: { [key: string]: any };
    /**
     * IDs of annotations attached to this requirement diff.
     */
    annotationIds?: string[];
    /**
     * The requirement as it appeared in the old/reference source. Null when state is 'new'.
     */
    before: any;
    /**
     * Sensitive data from the old source that should not be included in the main before
     * snapshot.
     */
    beforeSensitive?: { [key: string]: any };
    /**
     * The reasons for the state change.
     */
    changeReasons: ChangeReason[];
    /**
     * Conflicts between multiple scanner results for this requirement.
     */
    conflicts?: ScannerConflict[];
    /**
     * Detailed field-level changes between the before and after versions.
     */
    fieldChanges: FieldChange[];
    /**
     * The canonical requirement identifier used for this diff.
     */
    id: string;
    /**
     * Confidence score for the match (0-1).
     */
    matchConfidence?: number;
    /**
     * Whether the match was manually confirmed by a human.
     */
    matchManual?: boolean;
    /**
     * The strategy that was used to match this requirement across sources.
     */
    matchStrategy?: MatchStrategy;
    /**
     * The effective status of the requirement in the new source.
     */
    newEffectiveStatus?: string;
    /**
     * The requirement ID in the new source, if different from the canonical id.
     */
    newId?: string;
    /**
     * The impact score of the requirement in the new source (0-1).
     */
    newImpact?: number;
    /**
     * The effective status of the requirement in the old source.
     */
    oldEffectiveStatus?: string;
    /**
     * The requirement ID in the old source, if different from the canonical id.
     */
    oldId?: string;
    /**
     * The impact score of the requirement in the old source (0-1).
     */
    oldImpact?: number;
    /**
     * Index into the sources array for multi-source comparisons.
     */
    sourceIndex?: number;
    /**
     * The state of this requirement in the comparison.
     */
    state: RequirementState;
    /**
     * The requirement title for human readability.
     */
    title?: string;
    [property: string]: any;
}

/**
 * The reason a requirement's state changed between sources.
 */
export enum ChangeReason {
    BaselineUpgraded = "baselineUpgraded",
    ConfigChanged = "configChanged",
    ControlMapped = "controlMapped",
    ImpactChanged = "impactChanged",
    MetadataChanged = "metadataChanged",
    OverrideAdded = "overrideAdded",
    OverrideExpired = "overrideExpired",
    OverrideModified = "overrideModified",
    OverrideRemoved = "overrideRemoved",
    ResultChanged = "resultChanged",
    ScannerChanged = "scannerChanged",
    TargetChanged = "targetChanged",
}

/**
 * A conflict between scanner results for the same requirement.
 */
export interface ScannerConflict {
    /**
     * The field where the conflict occurs.
     */
    field: string;
    /**
     * How the conflict was resolved.
     */
    resolution?: ConflictResolution;
    /**
     * Index of the source whose value was chosen as the resolution.
     */
    resolvedIndex?: number;
    /**
     * The conflicting values from each source.
     */
    values: Value[];
    [property: string]: any;
}

/**
 * How the conflict was resolved.
 *
 * How a conflict between multiple scanner results was resolved.
 */
export enum ConflictResolution {
    Manual = "manual",
    MostRecent = "mostRecent",
    MostSevere = "mostSevere",
    Unresolved = "unresolved",
}

export interface Value {
    /**
     * Zero-based index into the sources array.
     */
    sourceIndex: number;
    /**
     * Human-readable label for the source.
     */
    sourceLabel: string;
    /**
     * The value reported by this source for the conflicting field.
     */
    value: any;
    [property: string]: any;
}

/**
 * The strategy that was used to match this requirement across sources.
 *
 * The strategy used to match requirements across sources. 'exactId' matches by identical
 * IDs. 'mappedId' uses an ID mapping table. 'cciMatch'/'nistMatch' match by framework
 * identifiers. 'fuzzyTitle'/'fuzzyContent' use text similarity.
 *
 * The primary strategy used to match requirements across sources.
 */
export enum MatchStrategy {
    CciMatch = "cciMatch",
    ExactID = "exactId",
    FuzzyContent = "fuzzyContent",
    FuzzyTitle = "fuzzyTitle",
    MappedID = "mappedId",
    NISTMatch = "nistMatch",
}

/**
 * The state of this requirement in the comparison.
 *
 * SARIF-compatible vocabulary extended for security. 'new' = present only in new source,
 * 'absent' = present only in old, 'unchanged' = same effective status, 'updated' = status
 * changed (generic), 'fixed' = was failing now passing, 'regressed' = was passing now
 * failing, 'moved' = reorganized same content, 'split'/'merged' = reserved for v1.1.
 */
export enum RequirementState {
    Absent = "absent",
    Fixed = "fixed",
    Merged = "merged",
    Moved = "moved",
    New = "new",
    Regressed = "regressed",
    Split = "split",
    Unchanged = "unchanged",
    Updated = "updated",
}

export enum FormatVersion {
    The100 = "1.0.0",
}

/**
 * Information about the tool that generated this comparison.
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
 * Cryptographic integrity information for verifying this comparison document.
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
export enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512",
}

/**
 * Configuration for how requirements were matched across sources.
 *
 * Configuration for how requirements are matched across sources.
 */
export interface MatchingConfig {
    /**
     * Ordered list of fallback strategies tried when the primary strategy fails to find a match.
     */
    fallbackStrategies?: MatchStrategy[];
    /**
     * Fields used to compute a fingerprint for fuzzy matching.
     */
    fingerprintFields?: string[];
    /**
     * URI pointing to an external mapping table used for ID translation.
     */
    mappingTableUri?: string;
    /**
     * Minimum confidence score (0-1) required to accept a match.
     */
    minimumConfidence?: number;
    /**
     * The primary strategy used to match requirements across sources.
     */
    primaryStrategy: MatchStrategy;
    [property: string]: any;
}

/**
 * Comparison of a single package between two SBOM versions, matched by purl.
 */
export interface PackageDiff {
    /**
     * License identifiers for this package.
     */
    licenses?: string[];
    /**
     * Human-readable package name.
     */
    name?: string;
    /**
     * Package version in the new SBOM.
     */
    newVersion?: string;
    /**
     * Package version in the old SBOM.
     */
    oldVersion?: string;
    /**
     * Package URL (purl) used as the identity key for matching across SBOMs.
     */
    purl: string;
    /**
     * The state of this package: added (new in new SBOM), removed (absent from new SBOM),
     * updated (version changed), unchanged.
     */
    state: PackageDiffState;
    [property: string]: any;
}

/**
 * The state of this package: added (new in new SBOM), removed (absent from new SBOM),
 * updated (version changed), unchanged.
 */
export enum PackageDiffState {
    Added = "added",
    Removed = "removed",
    Unchanged = "unchanged",
    Updated = "updated",
}

/**
 * A source document participating in the comparison.
 */
export interface Source {
    /**
     * When the source assessment was performed. ISO 8601 format.
     */
    assessmentTimestamp?: Date;
    /**
     * Reference to the baseline used in this source assessment.
     */
    baselineRef?: BaselineRef;
    /**
     * Cryptographic checksum of the source document for integrity verification.
     */
    checksum?: Checksum;
    /**
     * The components assessed in this source.
     */
    components?: Component[];
    /**
     * Human-readable label for this source. Example: 'Before remediation scan'.
     */
    label: string;
    /**
     * The original format of the source document before conversion to HDF.
     */
    originalFormat?: OriginalFormat;
    /**
     * The role of this source in the comparison.
     */
    role: SourceRole;
    /**
     * The security tool that produced the assessment data in this source.
     */
    tool?: Tool;
    /**
     * URI pointing to the source document.
     */
    uri?: string;
    [property: string]: any;
}

/**
 * Reference to the baseline used in this source assessment.
 */
export interface BaselineRef {
    /**
     * Name of the baseline used in this source.
     */
    name: string;
    /**
     * Version of the baseline used in this source.
     */
    version?: string;
    [property: string]: any;
}

/**
 * Cryptographic checksum of the source document for integrity verification.
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
 * A system component. Uses discriminated union pattern with 'type' field as discriminator.
 * Superset of Target with identity, external IDs, and SBOM support.
 *
 * A physical or virtual server, workstation, or network device.
 *
 * Base properties shared by all component types. Extends the Target concept with stable
 * identity, external references, and SBOM embedding.
 *
 * A static container image (not running).
 *
 * A running container instance.
 *
 * A container orchestration platform (Kubernetes, OpenShift, ECS, etc.).
 *
 * A cloud provider account (AWS account, Azure subscription, GCP project).
 *
 * A specific cloud resource (EC2 instance, S3 bucket, Azure VM, etc.).
 *
 * A code repository (for SAST tools).
 *
 * A running application or API (for DAST tools).
 *
 * A software artifact or dependency (for SCA tools).
 *
 * A network segment or network device.
 *
 * A database instance.
 */
export interface Component {
    /**
     * Names of baselines that apply to this component.
     */
    baselineRefs?: string[];
    /**
     * Stable UUID (RFC 4122) for this component. Required in hdf-system documents, optional in
     * hdf-results. Enables cross-document correlation, diffing, and data flow references.
     */
    componentId?: string;
    /**
     * Description of this component's role or purpose.
     */
    description?: string;
    /**
     * Map of external identifier scheme to value. Well-known schemes: aws (instance ID), azure
     * (resource ID), cmdb (asset ID), emass (system ID), cve (CVE ID). Custom schemes are
     * allowed.
     */
    externalIds?: { [key: string]: string };
    /**
     * System-specific overrides for baseline input values.
     */
    inputOverrides?: InputOverride[];
    /**
     * Optional key-value labels for flexible grouping. Well-known keys: system, component,
     * environment, region, team. Values must be strings.
     */
    labels?: { [key: string]: string };
    /**
     * Human-readable name for this component.
     */
    name: string;
    /**
     * Team or individual responsible for this component. Enables per-component ownership when
     * different teams manage different parts of a system.
     */
    owner?: Identity;
    /**
     * Embedded CycloneDX or SPDX SBOM document representing this component's software
     * inventory. The sbomFormat field determines which format constraints apply.
     */
    sbom?: any;
    /**
     * Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present.
     */
    sbomFormat?: SbomFormat;
    /**
     * URI reference to an external CycloneDX or SPDX SBOM document for this component. May be a
     * relative path, absolute URI, or fragment identifier.
     */
    sbomRef?: string;
    /**
     * Label selector to match targets belonging to this component during migration. Targets
     * with matching labels are automatically included.
     */
    targetSelector?: { [key: string]: string };
    /**
     * Component type discriminator. Same values as Target types.
     */
    type: Description;
    /**
     * Fully qualified domain name.
     */
    fqdn?: string;
    /**
     * IP address of the host.
     */
    ipAddress?: string;
    /**
     * MAC address in colon-separated hexadecimal format.
     */
    macAddress?: string;
    /**
     * Operating system name.
     */
    osName?: string;
    /**
     * Operating system version.
     */
    osVersion?: string;
    /**
     * Image digest for immutable reference.
     */
    digest?: string;
    /**
     * Container image ID.
     */
    imageId?: string;
    /**
     * Container registry. Example: 'docker.io'.
     */
    registry?: string;
    /**
     * Repository name. Example: 'library/nginx'.
     */
    repository?: string;
    /**
     * Image tag. Example: '1.25'.
     */
    tag?: string;
    /**
     * Running container ID.
     */
    containerId?: string;
    /**
     * Image the container was started from.
     */
    image?: string;
    /**
     * Container runtime. Example: 'docker', 'containerd', 'cri-o'.
     */
    runtime?: string;
    /**
     * Cluster name.
     */
    clusterName?: string;
    /**
     * Namespace within the cluster, if applicable.
     */
    namespace?: string;
    /**
     * Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'.
     */
    platformType?: string;
    /**
     * Platform version.
     *
     * Application version.
     *
     * Package version.
     *
     * Database version.
     */
    version?: string;
    /**
     * Cloud account identifier.
     */
    accountId?: string;
    /**
     * Cloud provider.
     */
    provider?: CloudProvider | null;
    /**
     * Cloud region, if applicable.
     *
     * Cloud region where the resource resides.
     */
    region?: string;
    /**
     * Amazon Resource Name (AWS only).
     */
    arn?: string;
    /**
     * Provider-specific resource identifier.
     */
    resourceId?: string;
    /**
     * Type of cloud resource. Example: 'ec2:instance', 's3:bucket'.
     */
    resourceType?: string;
    /**
     * Branch that was scanned.
     */
    branch?: string;
    /**
     * Commit SHA that was scanned.
     */
    commit?: string;
    /**
     * Repository URL.
     *
     * Application URL (for DAST tools).
     */
    url?: string;
    /**
     * Environment. Example: 'production', 'staging', 'development'.
     */
    environment?: string;
    /**
     * Package checksum for verification.
     */
    checksum?: string;
    /**
     * Package manager. Example: 'npm', 'maven', 'pip', 'nuget'.
     */
    packageManager?: string;
    /**
     * Package name.
     */
    packageName?: string;
    /**
     * Network CIDR block.
     */
    cidr?: string;
    /**
     * Network gateway address.
     */
    gateway?: string;
    /**
     * Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'.
     */
    engine?: string;
    /**
     * Database host.
     */
    host?: string;
    /**
     * Database port.
     */
    port?: number;
    [property: string]: any;
}

/**
 * An override of a baseline input value for a specific component. Enables system-specific
 * tailoring of baseline parameters.
 */
export interface InputOverride {
    /**
     * Identity of the person or system that approved this override.
     */
    approvedBy?: Identity;
    /**
     * Name of the baseline this override applies to. If omitted, applies to all baselines that
     * define this input.
     */
    baselineRef?: string;
    /**
     * Name of the input being overridden. Must match an Input.name in the referenced baseline.
     */
    inputName: string;
    /**
     * Rationale for why this override is needed.
     */
    justification?: string;
    /**
     * The overridden value. Should match the type of the original input.
     */
    value: any;
    [property: string]: any;
}

/**
 * Identity of the person or system that approved this override.
 *
 * Represents an identity that performed an action, such as capturing evidence or applying
 * an override.
 *
 * Team or individual responsible for this component. Enables per-component ownership when
 * different teams manage different parts of a system.
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

export enum CloudProvider {
    Aws = "aws",
    Azure = "azure",
    Gcp = "gcp",
    Oci = "oci",
    Other = "other",
}

/**
 * Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present.
 */
export enum SbomFormat {
    Cyclonedx = "cyclonedx",
    Spdx = "spdx",
}

/**
 * IP address of the host.
 */
export enum Description {
    Application = "application",
    Artifact = "artifact",
    CloudAccount = "cloudAccount",
    CloudResource = "cloudResource",
    ContainerImage = "containerImage",
    ContainerInstance = "containerInstance",
    ContainerPlatform = "containerPlatform",
    Database = "database",
    Host = "host",
    Network = "network",
    Repository = "repository",
}

/**
 * The original format of the source document before conversion to HDF.
 */
export enum OriginalFormat {
    HdfV2 = "hdf-v2",
    InspecV1 = "inspec-v1",
    OscalAr = "oscal-ar",
    Sarif = "sarif",
    Xccdf = "xccdf",
}

/**
 * The role of this source in the comparison.
 *
 * The role of a source document in the comparison.
 */
export enum SourceRole {
    Golden = "golden",
    New = "new",
    Old = "old",
    Reference = "reference",
    System = "system",
}

/**
 * The security tool that produced the assessment data in this source.
 *
 * The security tool that produced the assessment data represented in this HDF file. Aligns
 * with SARIF, OSCAL, and CycloneDX terminology.
 */
export interface Tool {
    /**
     * The file format, if it is a recognized named format shared by multiple tools. Examples:
     * 'SARIF', 'XCCDF'. Omit for tool-specific formats where the tool name already implies the
     * format (Nessus XML, gosec JSON).
     */
    format?: string;
    /**
     * The name of the security tool that produced the data. Examples: 'gosec', 'Semgrep',
     * 'OpenSCAP', 'AWS Config', 'Nessus'. Omit if the tool cannot be identified.
     */
    name?: string;
    /**
     * Version of the source tool, if available in the tool's output. Example: '5.22.3'.
     */
    version?: string;
    [property: string]: any;
}

/**
 * Summary statistics for the overall comparison.
 */
export interface ComparisonSummary {
    /**
     * Number of requirements present only in the old source.
     */
    absent?: number;
    /**
     * Average confidence score across all requirement matches (0-1).
     */
    averageMatchConfidence?: number;
    /**
     * State counts broken down by severity level.
     */
    bySeverity?: SeverityBreakdown;
    /**
     * Change in compliance percentage (new - old).
     */
    complianceDelta?: number;
    /**
     * Number of requirements that changed from failing to passing.
     */
    fixed?: number;
    /**
     * Number of requirements successfully matched between sources.
     */
    matchedCount: number;
    /**
     * Number of requirements that were reorganized without content change.
     */
    moved?: number;
    /**
     * Number of requirements present only in the new source.
     */
    new?: number;
    /**
     * Compliance percentage of the new source (0-100).
     */
    newCompliancePercent?: number;
    /**
     * Compliance percentage of the old source (0-100).
     */
    oldCompliancePercent?: number;
    /**
     * Summary statistics for each individual source in a multi-source comparison.
     */
    perSource?: PerSourceSummary[];
    /**
     * Number of requirements that changed from passing to failing.
     */
    regressed?: number;
    /**
     * Total number of unique requirements across all sources.
     */
    total: number;
    /**
     * Number of requirements with the same effective status.
     */
    unchanged?: number;
    /**
     * Number of requirements in the new source with no match in the old source.
     */
    unmatchedNewCount: number;
    /**
     * Number of requirements in the old source with no match in the new source.
     */
    unmatchedOldCount: number;
    /**
     * Number of requirements with a generic status change.
     */
    updated?: number;
    [property: string]: any;
}

/**
 * State counts broken down by severity level.
 *
 * Breakdown of state counts by severity level.
 */
export interface SeverityBreakdown {
    /**
     * State counts for critical severity requirements.
     */
    critical?: StateCounts;
    /**
     * State counts for high severity requirements.
     */
    high?: StateCounts;
    /**
     * State counts for low severity requirements.
     */
    low?: StateCounts;
    /**
     * State counts for medium severity requirements.
     */
    medium?: StateCounts;
    [property: string]: any;
}

/**
 * State counts for critical severity requirements.
 *
 * Counts of requirements in each state.
 *
 * State counts for high severity requirements.
 *
 * State counts for low severity requirements.
 *
 * State counts for medium severity requirements.
 */
export interface StateCounts {
    /**
     * Number of requirements present only in the old source.
     */
    absent?: number;
    /**
     * Number of requirements that changed from failing to passing.
     */
    fixed?: number;
    /**
     * Number of requirements that were reorganized without content change.
     */
    moved?: number;
    /**
     * Number of requirements present only in the new source.
     */
    new?: number;
    /**
     * Number of requirements that changed from passing to failing.
     */
    regressed?: number;
    /**
     * Number of requirements with the same effective status.
     */
    unchanged?: number;
    /**
     * Number of requirements with a generic status change.
     */
    updated?: number;
    [property: string]: any;
}

/**
 * Summary statistics for a single source in a multi-source comparison.
 */
export interface PerSourceSummary {
    /**
     * Number of requirements present only in the old source.
     */
    absent?: number;
    /**
     * Number of requirements that changed from failing to passing.
     */
    fixed?: number;
    /**
     * Human-readable label for this source.
     */
    label: string;
    /**
     * Number of requirements that were reorganized without content change.
     */
    moved?: number;
    /**
     * Number of requirements present only in the new source.
     */
    new?: number;
    /**
     * Number of requirements that changed from passing to failing.
     */
    regressed?: number;
    /**
     * Zero-based index into the sources array identifying which source this summary is for.
     */
    sourceIndex: number;
    /**
     * Number of requirements with the same effective status.
     */
    unchanged?: number;
    /**
     * Number of requirements with a generic status change.
     */
    updated?: number;
    [property: string]: any;
}
