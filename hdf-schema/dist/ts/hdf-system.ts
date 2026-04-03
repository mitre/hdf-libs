/**
 * Describes a system's authorization boundary, components, and interconnections. Maps to
 * OSCAL SSP system-characteristics and FedRAMP system inventory.
 */
export interface HdfSystem {
    /**
     * Date the current authorization status was granted. ISO 8601 format.
     */
    authorizationDate?: Date;
    /**
     * Current Authorization to Operate (ATO) status.
     */
    authorizationStatus?: AuthorizationStatus;
    /**
     * Description of the system's authorization boundary. Example: network CIDR blocks, cloud
     * VPC IDs, physical locations.
     */
    boundaryDescription?: string;
    /**
     * FIPS 199 security categorization (impact level).
     */
    categorizationLevel?: CategorizationLevel;
    /**
     * System components within the authorization boundary. Uses the full polymorphic Component
     * type with stable identity (componentId), external references, and SBOM support.
     */
    components: Component[];
    /**
     * Declares which controls are common, hybrid, or system-specific, and which component
     * provides them. Maps to NIST SP 800-53 control designations and OSCAL
     * leveraged-authorizations.
     */
    controlDesignations?: ControlDesignation[];
    /**
     * Inter-component data flows describing how components communicate. Supports local,
     * cross-system, and external flows. Replaces the interconnections[] field.
     */
    dataFlows?: DataFlow[];
    /**
     * Description of the system's purpose and mission.
     */
    description?: string;
    /**
     * Information about the tool that generated this system document.
     */
    generator?: Generator;
    /**
     * System identifier from an authoritative source. Example: eMASS system ID, FedRAMP package
     * ID.
     */
    identifier?: string;
    /**
     * URI identifying the scheme of the system identifier. Example: 'https://emass.mil',
     * 'https://fedramp.gov'.
     */
    identifierScheme?: string;
    /**
     * Cryptographic integrity information for verifying this system document has not been
     * tampered with.
     */
    integrity?: Integrity;
    /**
     * Optional key-value labels for grouping and querying systems.
     */
    labels?: { [key: string]: string };
    /**
     * Human-readable system name. Example: 'Enterprise Portal Production'.
     */
    name: string;
    /**
     * Team or individual responsible for this system's authorization and compliance. Maps to
     * OSCAL responsible-party with role 'system-owner'.
     */
    owner?: Identity;
    /**
     * Stable UUID (RFC 4122) for this system. Enables cross-document correlation independent of
     * file location. Optional in casual use, expected in production documents.
     */
    systemId?: string;
    /**
     * Version of this system document.
     */
    version?: string;
    [property: string]: any;
}

/**
 * Current Authorization to Operate (ATO) status.
 *
 * Authorization to Operate (ATO) status for the system.
 */
export enum AuthorizationStatus {
    Authorized = "authorized",
    ConditionallyAuthorized = "conditionallyAuthorized",
    Denied = "denied",
    NotYetRequested = "notYetRequested",
    PendingAuthorization = "pendingAuthorization",
    Revoked = "revoked",
}

/**
 * FIPS 199 security categorization (impact level).
 *
 * FIPS 199 security categorization level (impact level).
 */
export enum CategorizationLevel {
    High = "high",
    Low = "low",
    Moderate = "moderate",
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
    type: BoundaryDescription;
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
 *
 * Team or individual responsible for this system's authorization and compliance. Maps to
 * OSCAL responsible-party with role 'system-owner'.
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
export enum BoundaryDescription {
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
 * Declares a control's designation within a system — whether it is common (provided by
 * another component or system), system-specific (implemented locally), or hybrid (shared
 * responsibility). Maps to NIST SP 800-53 Appendix C control designations and OSCAL SSP
 * by-component provided/inherited semantics.
 */
export interface ControlDesignation {
    /**
     * The control identifier (e.g., 'SC-7', 'AC-2 (1)'). Must match a NIST tag in a baseline
     * requirement's tags.
     */
    controlId: string;
    /**
     * Justification for this designation — who provides the control, why it's inherited, and
     * any relevant authorization references.
     */
    description: string;
    /**
     * NIST SP 800-53 control designation. 'common': fully provided by another component or
     * system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
     * shared responsibility between provider and inheritor.
     */
    designation: Designation;
    /**
     * componentIds that inherit this control. If omitted, all components in the system inherit
     * it.
     */
    inheritedBy?: string[];
    /**
     * componentId of a local component that provides this control. Omit when the provider is an
     * external system.
     */
    providedBy?: string;
    /**
     * Reference to another hdf-system document whose component provides this control. Use when
     * the provider is in a different system. Omit when the provider is local.
     */
    systemRef?: string;
    [property: string]: any;
}

/**
 * NIST SP 800-53 control designation. 'common': fully provided by another component or
 * system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
 * shared responsibility between provider and inheritor.
 */
export enum Designation {
    Common = "common",
    Hybrid = "hybrid",
    SystemSpecific = "system-specific",
}

/**
 * A data flow between two endpoints. The 'from' endpoint is always a local component; the
 * 'to' endpoint can be local, cross-system, or external. Use 'direction' to indicate
 * whether data flows one-way or both ways.
 */
export interface DataFlow {
    /**
     * Authentication mechanism used for this connection. Examples: 'mTLS', 'OAuth2', 'API key',
     * 'SAML', 'Kerberos'.
     */
    authentication?: string;
    /**
     * Human-readable description of this data flow's purpose and the data exchanged.
     */
    description?: string;
    /**
     * Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
     * means data flows in both directions (e.g., request/response).
     */
    direction?: Direction;
    /**
     * UUID of the local component that is one end of this data flow. Always references a
     * component in the current system document.
     */
    from: string;
    /**
     * Network port number.
     */
    port?: number;
    /**
     * Communication protocol. Examples: 'http', 'https', 'grpc', 'ssh', 'jdbc', 'k8s-api',
     * 'socket', 'sftp'.
     */
    protocol?: string;
    /**
     * The other end of this data flow. Can be a local component (UUID), a cross-system
     * component reference, or an external endpoint.
     */
    to: any;
    [property: string]: any;
}

/**
 * Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
 * means data flows in both directions (e.g., request/response).
 */
export enum Direction {
    Bidirectional = "bidirectional",
    Unidirectional = "unidirectional",
}

/**
 * Information about the tool that generated this system document.
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
 * Cryptographic integrity information for verifying this system document has not been
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
 * The hash algorithm used for the checksum.
 *
 * Supported cryptographic hash algorithms for checksums and integrity verification.
 */
export enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512",
}
