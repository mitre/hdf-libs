from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, List, Dict, TypeVar, Type, cast, Callable
from uuid import UUID
from datetime import datetime
import dateutil.parser


T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


class AuthorizationStatus(Enum):
    """Current Authorization to Operate (ATO) status.
    
    Authorization to Operate (ATO) status for the system.
    """
    AUTHORIZED = "authorized"
    CONDITIONALLY_AUTHORIZED = "conditionallyAuthorized"
    DENIED = "denied"
    NOT_YET_REQUESTED = "notYetRequested"
    PENDING_AUTHORIZATION = "pendingAuthorization"
    REVOKED = "revoked"


class CategorizationLevel(Enum):
    """FIPS 199 security categorization (impact level).
    
    FIPS 199 security categorization level (impact level).
    """
    HIGH = "high"
    LOW = "low"
    MODERATE = "moderate"


class TypeEnum(Enum):
    """The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
    'system' for automated systems, 'simple' for basic string identifiers without additional
    classification, or 'other' for custom identity systems.
    """
    EMAIL = "email"
    OTHER = "other"
    SIMPLE = "simple"
    SYSTEM = "system"
    USERNAME = "username"


@dataclass
class Identity:
    """Identity of the person or system that approved this override.
    
    Represents an identity that performed an action, such as capturing evidence or applying
    an override.
    
    Team or individual responsible for this component. Enables per-component ownership when
    different teams manage different parts of a system.
    
    Team or individual responsible for this system's authorization and compliance. Maps to
    OSCAL responsible-party with role 'system-owner'.
    """
    identifier: str
    """The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'."""

    type: TypeEnum
    """The type of identifier. Use 'email' for email addresses, 'username' for user accounts,
    'system' for automated systems, 'simple' for basic string identifiers without additional
    classification, or 'other' for custom identity systems.
    """
    description: Optional[str] = None
    """Optional description of the identity or identity system, particularly useful when type is
    'other'.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'Identity':
        assert isinstance(obj, dict)
        identifier = from_str(obj.get("identifier"))
        type = TypeEnum(obj.get("type"))
        description = from_union([from_str, from_none], obj.get("description"))
        return Identity(identifier, type, description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["identifier"] = from_str(self.identifier)
        result["type"] = to_enum(TypeEnum, self.type)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        return result


@dataclass
class InputOverride:
    """An override of a baseline input value for a specific component. Enables system-specific
    tailoring of baseline parameters.
    """
    input_name: str
    """Name of the input being overridden. Must match an Input.name in the referenced baseline."""

    value: Any
    """The overridden value. Should match the type of the original input."""

    approved_by: Optional[Identity] = None
    """Identity of the person or system that approved this override."""

    baseline_ref: Optional[str] = None
    """Name of the baseline this override applies to. If omitted, applies to all baselines that
    define this input.
    """
    justification: Optional[str] = None
    """Rationale for why this override is needed."""

    @staticmethod
    def from_dict(obj: Any) -> 'InputOverride':
        assert isinstance(obj, dict)
        input_name = from_str(obj.get("inputName"))
        value = obj.get("value")
        approved_by = from_union([Identity.from_dict, from_none], obj.get("approvedBy"))
        baseline_ref = from_union([from_str, from_none], obj.get("baselineRef"))
        justification = from_union([from_str, from_none], obj.get("justification"))
        return InputOverride(input_name, value, approved_by, baseline_ref, justification)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inputName"] = from_str(self.input_name)
        result["value"] = self.value
        if self.approved_by is not None:
            result["approvedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.approved_by)
        if self.baseline_ref is not None:
            result["baselineRef"] = from_union([from_str, from_none], self.baseline_ref)
        if self.justification is not None:
            result["justification"] = from_union([from_str, from_none], self.justification)
        return result


class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OCI = "oci"
    OTHER = "other"


class SbomFormat(Enum):
    """Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class BoundaryDescription(Enum):
    """IP address of the host."""

    APPLICATION = "application"
    ARTIFACT = "artifact"
    CLOUD_ACCOUNT = "cloudAccount"
    CLOUD_RESOURCE = "cloudResource"
    CONTAINER_IMAGE = "containerImage"
    CONTAINER_INSTANCE = "containerInstance"
    CONTAINER_PLATFORM = "containerPlatform"
    DATABASE = "database"
    HOST = "host"
    NETWORK = "network"
    REPOSITORY = "repository"


@dataclass
class Component:
    """A system component. Uses discriminated union pattern with 'type' field as discriminator.
    Superset of Target with identity, external IDs, and SBOM support.
    
    A physical or virtual server, workstation, or network device.
    
    Base properties shared by all component types. Extends the Target concept with stable
    identity, external references, and SBOM embedding.
    
    A static container image (not running).
    
    A running container instance.
    
    A container orchestration platform (Kubernetes, OpenShift, ECS, etc.).
    
    A cloud provider account (AWS account, Azure subscription, GCP project).
    
    A specific cloud resource (EC2 instance, S3 bucket, Azure VM, etc.).
    
    A code repository (for SAST tools).
    
    A running application or API (for DAST tools).
    
    A software artifact or dependency (for SCA tools).
    
    A network segment or network device.
    
    A database instance.
    """
    name: str
    """Human-readable name for this component."""

    type: BoundaryDescription
    """Component type discriminator. Same values as Target types."""

    baseline_refs: Optional[List[str]] = None
    """Names of baselines that apply to this component."""

    component_id: Optional[UUID] = None
    """Stable UUID (RFC 4122) for this component. Required in hdf-system documents, optional in
    hdf-results. Enables cross-document correlation, diffing, and data flow references.
    """
    description: Optional[str] = None
    """Description of this component's role or purpose."""

    external_ids: Optional[Dict[str, str]] = None
    """Map of external identifier scheme to value. Well-known schemes: aws (instance ID), azure
    (resource ID), cmdb (asset ID), emass (system ID), cve (CVE ID). Custom schemes are
    allowed.
    """
    input_overrides: Optional[List[InputOverride]] = None
    """System-specific overrides for baseline input values."""

    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for flexible grouping. Well-known keys: system, component,
    environment, region, team. Values must be strings.
    """
    owner: Optional[Identity] = None
    """Team or individual responsible for this component. Enables per-component ownership when
    different teams manage different parts of a system.
    """
    sbom: Any
    """Embedded CycloneDX or SPDX SBOM document representing this component's software
    inventory. The sbomFormat field determines which format constraints apply.
    """
    sbom_format: Optional[SbomFormat] = None
    """Format of the SBOM (embedded or referenced). Required when sbom or sbomRef is present."""

    sbom_ref: Optional[str] = None
    """URI reference to an external CycloneDX or SPDX SBOM document for this component. May be a
    relative path, absolute URI, or fragment identifier.
    """
    target_selector: Optional[Dict[str, str]] = None
    """Label selector to match targets belonging to this component during migration. Targets
    with matching labels are automatically included.
    """
    fqdn: Optional[str] = None
    """Fully qualified domain name."""

    ip_address: Optional[str] = None
    """IP address of the host."""

    mac_address: Optional[str] = None
    """MAC address in colon-separated hexadecimal format."""

    os_name: Optional[str] = None
    """Operating system name."""

    os_version: Optional[str] = None
    """Operating system version."""

    digest: Optional[str] = None
    """Image digest for immutable reference."""

    image_id: Optional[str] = None
    """Container image ID."""

    registry: Optional[str] = None
    """Container registry. Example: 'docker.io'."""

    repository: Optional[str] = None
    """Repository name. Example: 'library/nginx'."""

    tag: Optional[str] = None
    """Image tag. Example: '1.25'."""

    container_id: Optional[str] = None
    """Running container ID."""

    image: Optional[str] = None
    """Image the container was started from."""

    runtime: Optional[str] = None
    """Container runtime. Example: 'docker', 'containerd', 'cri-o'."""

    cluster_name: Optional[str] = None
    """Cluster name."""

    namespace: Optional[str] = None
    """Namespace within the cluster, if applicable."""

    platform_type: Optional[str] = None
    """Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'."""

    version: Optional[str] = None
    """Platform version.
    
    Application version.
    
    Package version.
    
    Database version.
    """
    account_id: Optional[str] = None
    """Cloud account identifier."""

    provider: Optional[CloudProvider] = None
    """Cloud provider."""

    region: Optional[str] = None
    """Cloud region, if applicable.
    
    Cloud region where the resource resides.
    """
    arn: Optional[str] = None
    """Amazon Resource Name (AWS only)."""

    resource_id: Optional[str] = None
    """Provider-specific resource identifier."""

    resource_type: Optional[str] = None
    """Type of cloud resource. Example: 'ec2:instance', 's3:bucket'."""

    branch: Optional[str] = None
    """Branch that was scanned."""

    commit: Optional[str] = None
    """Commit SHA that was scanned."""

    url: Optional[str] = None
    """Repository URL.
    
    Application URL (for DAST tools).
    """
    environment: Optional[str] = None
    """Environment. Example: 'production', 'staging', 'development'."""

    checksum: Optional[str] = None
    """Package checksum for verification."""

    package_manager: Optional[str] = None
    """Package manager. Example: 'npm', 'maven', 'pip', 'nuget'."""

    package_name: Optional[str] = None
    """Package name."""

    cidr: Optional[str] = None
    """Network CIDR block."""

    gateway: Optional[str] = None
    """Network gateway address."""

    engine: Optional[str] = None
    """Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'."""

    host: Optional[str] = None
    """Database host."""

    port: Optional[int] = None
    """Database port."""

    @staticmethod
    def from_dict(obj: Any) -> 'Component':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        type = BoundaryDescription(obj.get("type"))
        baseline_refs = from_union([lambda x: from_list(from_str, x), from_none], obj.get("baselineRefs"))
        component_id = from_union([lambda x: UUID(x), from_none], obj.get("componentId"))
        description = from_union([from_str, from_none], obj.get("description"))
        external_ids = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("externalIds"))
        input_overrides = from_union([lambda x: from_list(InputOverride.from_dict, x), from_none], obj.get("inputOverrides"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        owner = from_union([Identity.from_dict, from_none], obj.get("owner"))
        sbom = obj.get("sbom")
        sbom_format = from_union([SbomFormat, from_none], obj.get("sbomFormat"))
        sbom_ref = from_union([from_str, from_none], obj.get("sbomRef"))
        target_selector = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("targetSelector"))
        fqdn = from_union([from_str, from_none], obj.get("fqdn"))
        ip_address = from_union([from_str, from_none], obj.get("ipAddress"))
        mac_address = from_union([from_str, from_none], obj.get("macAddress"))
        os_name = from_union([from_str, from_none], obj.get("osName"))
        os_version = from_union([from_str, from_none], obj.get("osVersion"))
        digest = from_union([from_str, from_none], obj.get("digest"))
        image_id = from_union([from_str, from_none], obj.get("imageId"))
        registry = from_union([from_str, from_none], obj.get("registry"))
        repository = from_union([from_str, from_none], obj.get("repository"))
        tag = from_union([from_str, from_none], obj.get("tag"))
        container_id = from_union([from_str, from_none], obj.get("containerId"))
        image = from_union([from_str, from_none], obj.get("image"))
        runtime = from_union([from_str, from_none], obj.get("runtime"))
        cluster_name = from_union([from_str, from_none], obj.get("clusterName"))
        namespace = from_union([from_str, from_none], obj.get("namespace"))
        platform_type = from_union([from_str, from_none], obj.get("platformType"))
        version = from_union([from_str, from_none], obj.get("version"))
        account_id = from_union([from_str, from_none], obj.get("accountId"))
        provider = from_union([from_none, CloudProvider], obj.get("provider"))
        region = from_union([from_str, from_none], obj.get("region"))
        arn = from_union([from_str, from_none], obj.get("arn"))
        resource_id = from_union([from_str, from_none], obj.get("resourceId"))
        resource_type = from_union([from_str, from_none], obj.get("resourceType"))
        branch = from_union([from_str, from_none], obj.get("branch"))
        commit = from_union([from_str, from_none], obj.get("commit"))
        url = from_union([from_str, from_none], obj.get("url"))
        environment = from_union([from_str, from_none], obj.get("environment"))
        checksum = from_union([from_str, from_none], obj.get("checksum"))
        package_manager = from_union([from_str, from_none], obj.get("packageManager"))
        package_name = from_union([from_str, from_none], obj.get("packageName"))
        cidr = from_union([from_str, from_none], obj.get("cidr"))
        gateway = from_union([from_str, from_none], obj.get("gateway"))
        engine = from_union([from_str, from_none], obj.get("engine"))
        host = from_union([from_str, from_none], obj.get("host"))
        port = from_union([from_int, from_none], obj.get("port"))
        return Component(name, type, baseline_refs, component_id, description, external_ids, input_overrides, labels, owner, sbom, sbom_format, sbom_ref, target_selector, fqdn, ip_address, mac_address, os_name, os_version, digest, image_id, registry, repository, tag, container_id, image, runtime, cluster_name, namespace, platform_type, version, account_id, provider, region, arn, resource_id, resource_type, branch, commit, url, environment, checksum, package_manager, package_name, cidr, gateway, engine, host, port)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["type"] = to_enum(BoundaryDescription, self.type)
        if self.baseline_refs is not None:
            result["baselineRefs"] = from_union([lambda x: from_list(from_str, x), from_none], self.baseline_refs)
        if self.component_id is not None:
            result["componentId"] = from_union([lambda x: str(x), from_none], self.component_id)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.external_ids is not None:
            result["externalIds"] = from_union([lambda x: from_dict(from_str, x), from_none], self.external_ids)
        if self.input_overrides is not None:
            result["inputOverrides"] = from_union([lambda x: from_list(lambda x: to_class(InputOverride, x), x), from_none], self.input_overrides)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.owner is not None:
            result["owner"] = from_union([lambda x: to_class(Identity, x), from_none], self.owner)
        if self.sbom is not None:
            result["sbom"] = self.sbom
        if self.sbom_format is not None:
            result["sbomFormat"] = from_union([lambda x: to_enum(SbomFormat, x), from_none], self.sbom_format)
        if self.sbom_ref is not None:
            result["sbomRef"] = from_union([from_str, from_none], self.sbom_ref)
        if self.target_selector is not None:
            result["targetSelector"] = from_union([lambda x: from_dict(from_str, x), from_none], self.target_selector)
        if self.fqdn is not None:
            result["fqdn"] = from_union([from_str, from_none], self.fqdn)
        if self.ip_address is not None:
            result["ipAddress"] = from_union([from_str, from_none], self.ip_address)
        if self.mac_address is not None:
            result["macAddress"] = from_union([from_str, from_none], self.mac_address)
        if self.os_name is not None:
            result["osName"] = from_union([from_str, from_none], self.os_name)
        if self.os_version is not None:
            result["osVersion"] = from_union([from_str, from_none], self.os_version)
        if self.digest is not None:
            result["digest"] = from_union([from_str, from_none], self.digest)
        if self.image_id is not None:
            result["imageId"] = from_union([from_str, from_none], self.image_id)
        if self.registry is not None:
            result["registry"] = from_union([from_str, from_none], self.registry)
        if self.repository is not None:
            result["repository"] = from_union([from_str, from_none], self.repository)
        if self.tag is not None:
            result["tag"] = from_union([from_str, from_none], self.tag)
        if self.container_id is not None:
            result["containerId"] = from_union([from_str, from_none], self.container_id)
        if self.image is not None:
            result["image"] = from_union([from_str, from_none], self.image)
        if self.runtime is not None:
            result["runtime"] = from_union([from_str, from_none], self.runtime)
        if self.cluster_name is not None:
            result["clusterName"] = from_union([from_str, from_none], self.cluster_name)
        if self.namespace is not None:
            result["namespace"] = from_union([from_str, from_none], self.namespace)
        if self.platform_type is not None:
            result["platformType"] = from_union([from_str, from_none], self.platform_type)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        if self.account_id is not None:
            result["accountId"] = from_union([from_str, from_none], self.account_id)
        if self.provider is not None:
            result["provider"] = from_union([from_none, lambda x: to_enum(CloudProvider, x)], self.provider)
        if self.region is not None:
            result["region"] = from_union([from_str, from_none], self.region)
        if self.arn is not None:
            result["arn"] = from_union([from_str, from_none], self.arn)
        if self.resource_id is not None:
            result["resourceId"] = from_union([from_str, from_none], self.resource_id)
        if self.resource_type is not None:
            result["resourceType"] = from_union([from_str, from_none], self.resource_type)
        if self.branch is not None:
            result["branch"] = from_union([from_str, from_none], self.branch)
        if self.commit is not None:
            result["commit"] = from_union([from_str, from_none], self.commit)
        if self.url is not None:
            result["url"] = from_union([from_str, from_none], self.url)
        if self.environment is not None:
            result["environment"] = from_union([from_str, from_none], self.environment)
        if self.checksum is not None:
            result["checksum"] = from_union([from_str, from_none], self.checksum)
        if self.package_manager is not None:
            result["packageManager"] = from_union([from_str, from_none], self.package_manager)
        if self.package_name is not None:
            result["packageName"] = from_union([from_str, from_none], self.package_name)
        if self.cidr is not None:
            result["cidr"] = from_union([from_str, from_none], self.cidr)
        if self.gateway is not None:
            result["gateway"] = from_union([from_str, from_none], self.gateway)
        if self.engine is not None:
            result["engine"] = from_union([from_str, from_none], self.engine)
        if self.host is not None:
            result["host"] = from_union([from_str, from_none], self.host)
        if self.port is not None:
            result["port"] = from_union([from_int, from_none], self.port)
        return result


class Designation(Enum):
    """NIST SP 800-53 control designation. 'common': fully provided by another component or
    system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
    shared responsibility between provider and inheritor.
    """
    COMMON = "common"
    HYBRID = "hybrid"
    SYSTEM_SPECIFIC = "system-specific"


@dataclass
class ControlDesignation:
    """Declares a control's designation within a system — whether it is common (provided by
    another component or system), system-specific (implemented locally), or hybrid (shared
    responsibility). Maps to NIST SP 800-53 Appendix C control designations and OSCAL SSP
    by-component provided/inherited semantics.
    """
    control_id: str
    """The control identifier (e.g., 'SC-7', 'AC-2 (1)'). Must match a NIST tag in a baseline
    requirement's tags.
    """
    description: str
    """Justification for this designation — who provides the control, why it's inherited, and
    any relevant authorization references.
    """
    designation: Designation
    """NIST SP 800-53 control designation. 'common': fully provided by another component or
    system. 'system-specific': implemented by the inheriting component(s) only. 'hybrid':
    shared responsibility between provider and inheritor.
    """
    inherited_by: Optional[List[UUID]] = None
    """componentIds that inherit this control. If omitted, all components in the system inherit
    it.
    """
    provided_by: Optional[UUID] = None
    """componentId of a local component that provides this control. Omit when the provider is an
    external system.
    """
    system_ref: Optional[str] = None
    """Reference to another hdf-system document whose component provides this control. Use when
    the provider is in a different system. Omit when the provider is local.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'ControlDesignation':
        assert isinstance(obj, dict)
        control_id = from_str(obj.get("controlId"))
        description = from_str(obj.get("description"))
        designation = Designation(obj.get("designation"))
        inherited_by = from_union([lambda x: from_list(lambda x: UUID(x), x), from_none], obj.get("inheritedBy"))
        provided_by = from_union([lambda x: UUID(x), from_none], obj.get("providedBy"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        return ControlDesignation(control_id, description, designation, inherited_by, provided_by, system_ref)

    def to_dict(self) -> dict:
        result: dict = {}
        result["controlId"] = from_str(self.control_id)
        result["description"] = from_str(self.description)
        result["designation"] = to_enum(Designation, self.designation)
        if self.inherited_by is not None:
            result["inheritedBy"] = from_union([lambda x: from_list(lambda x: str(x), x), from_none], self.inherited_by)
        if self.provided_by is not None:
            result["providedBy"] = from_union([lambda x: str(x), from_none], self.provided_by)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        return result


class Direction(Enum):
    """Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
    means data flows in both directions (e.g., request/response).
    """
    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"


@dataclass
class DataFlow:
    """A data flow between two endpoints. The 'from' endpoint is always a local component; the
    'to' endpoint can be local, cross-system, or external. Use 'direction' to indicate
    whether data flows one-way or both ways.
    """
    data_flow_from: UUID
    """UUID of the local component that is one end of this data flow. Always references a
    component in the current system document.
    """
    to: Any
    """The other end of this data flow. Can be a local component (UUID), a cross-system
    component reference, or an external endpoint.
    """
    authentication: Optional[str] = None
    """Authentication mechanism used for this connection. Examples: 'mTLS', 'OAuth2', 'API key',
    'SAML', 'Kerberos'.
    """
    description: Optional[str] = None
    """Human-readable description of this data flow's purpose and the data exchanged."""

    direction: Optional[Direction] = None
    """Data flow direction. 'unidirectional' means data flows from→to only. 'bidirectional'
    means data flows in both directions (e.g., request/response).
    """
    port: Optional[int] = None
    """Network port number."""

    protocol: Optional[str] = None
    """Communication protocol. Examples: 'http', 'https', 'grpc', 'ssh', 'jdbc', 'k8s-api',
    'socket', 'sftp'.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'DataFlow':
        assert isinstance(obj, dict)
        data_flow_from = UUID(obj.get("from"))
        to = obj.get("to")
        authentication = from_union([from_str, from_none], obj.get("authentication"))
        description = from_union([from_str, from_none], obj.get("description"))
        direction = from_union([Direction, from_none], obj.get("direction"))
        port = from_union([from_int, from_none], obj.get("port"))
        protocol = from_union([from_str, from_none], obj.get("protocol"))
        return DataFlow(data_flow_from, to, authentication, description, direction, port, protocol)

    def to_dict(self) -> dict:
        result: dict = {}
        result["from"] = str(self.data_flow_from)
        result["to"] = self.to
        if self.authentication is not None:
            result["authentication"] = from_union([from_str, from_none], self.authentication)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.direction is not None:
            result["direction"] = from_union([lambda x: to_enum(Direction, x), from_none], self.direction)
        if self.port is not None:
            result["port"] = from_union([from_int, from_none], self.port)
        if self.protocol is not None:
            result["protocol"] = from_union([from_str, from_none], self.protocol)
        return result


@dataclass
class Generator:
    """Information about the tool that generated this system document.
    
    Information about the tool that generated this HDF file.
    """
    name: str
    """The name of the software that produced this HDF file. Example: 'gosec-to-hdf'."""

    version: str
    """The version of the tool. Example: '5.22.3'."""

    @staticmethod
    def from_dict(obj: Any) -> 'Generator':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        version = from_str(obj.get("version"))
        return Generator(name, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["version"] = from_str(self.version)
        return result


class HashAlgorithm(Enum):
    """The hash algorithm used for the checksum.
    
    Supported cryptographic hash algorithms for checksums and integrity verification.
    """
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass
class Integrity:
    """Cryptographic integrity information for verifying this system document has not been
    tampered with.
    
    Cryptographic integrity information for verifying the HDF file has not been tampered
    with. If algorithm is provided, checksum must also be provided, and vice versa.
    """
    algorithm: Optional[HashAlgorithm] = None
    """The hash algorithm used for the checksum."""

    checksum: Optional[str] = None
    """The checksum value."""

    signature: Optional[str] = None
    """Optional cryptographic signature."""

    signed_by: Optional[str] = None
    """Identifier of who signed this file."""

    @staticmethod
    def from_dict(obj: Any) -> 'Integrity':
        assert isinstance(obj, dict)
        algorithm = from_union([HashAlgorithm, from_none], obj.get("algorithm"))
        checksum = from_union([from_str, from_none], obj.get("checksum"))
        signature = from_union([from_str, from_none], obj.get("signature"))
        signed_by = from_union([from_str, from_none], obj.get("signedBy"))
        return Integrity(algorithm, checksum, signature, signed_by)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.algorithm is not None:
            result["algorithm"] = from_union([lambda x: to_enum(HashAlgorithm, x), from_none], self.algorithm)
        if self.checksum is not None:
            result["checksum"] = from_union([from_str, from_none], self.checksum)
        if self.signature is not None:
            result["signature"] = from_union([from_str, from_none], self.signature)
        if self.signed_by is not None:
            result["signedBy"] = from_union([from_str, from_none], self.signed_by)
        return result


@dataclass
class HdfSystem:
    """Describes a system's authorization boundary, components, and interconnections. Maps to
    OSCAL SSP system-characteristics and FedRAMP system inventory.
    """
    components: List[Component]
    """System components within the authorization boundary. Uses the full polymorphic Component
    type with stable identity (componentId), external references, and SBOM support.
    """
    name: str
    """Human-readable system name. Example: 'Enterprise Portal Production'."""

    authorization_date: Optional[datetime] = None
    """Date the current authorization status was granted. ISO 8601 format."""

    authorization_status: Optional[AuthorizationStatus] = None
    """Current Authorization to Operate (ATO) status."""

    boundary_description: Optional[str] = None
    """Description of the system's authorization boundary. Example: network CIDR blocks, cloud
    VPC IDs, physical locations.
    """
    categorization_level: Optional[CategorizationLevel] = None
    """FIPS 199 security categorization (impact level)."""

    control_designations: Optional[List[ControlDesignation]] = None
    """Declares which controls are common, hybrid, or system-specific, and which component
    provides them. Maps to NIST SP 800-53 control designations and OSCAL
    leveraged-authorizations.
    """
    data_flows: Optional[List[DataFlow]] = None
    """Inter-component data flows describing how components communicate. Supports local,
    cross-system, and external flows. Replaces the interconnections[] field.
    """
    description: Optional[str] = None
    """Description of the system's purpose and mission."""

    generator: Optional[Generator] = None
    """Information about the tool that generated this system document."""

    identifier: Optional[str] = None
    """System identifier from an authoritative source. Example: eMASS system ID, FedRAMP package
    ID.
    """
    identifier_scheme: Optional[str] = None
    """URI identifying the scheme of the system identifier. Example: 'https://emass.mil',
    'https://fedramp.gov'.
    """
    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this system document has not been
    tampered with.
    """
    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for grouping and querying systems."""

    owner: Optional[Identity] = None
    """Team or individual responsible for this system's authorization and compliance. Maps to
    OSCAL responsible-party with role 'system-owner'.
    """
    system_id: Optional[UUID] = None
    """Stable UUID (RFC 4122) for this system. Enables cross-document correlation independent of
    file location. Optional in casual use, expected in production documents.
    """
    version: Optional[str] = None
    """Version of this system document."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfSystem':
        assert isinstance(obj, dict)
        components = from_list(Component.from_dict, obj.get("components"))
        name = from_str(obj.get("name"))
        authorization_date = from_union([from_datetime, from_none], obj.get("authorizationDate"))
        authorization_status = from_union([AuthorizationStatus, from_none], obj.get("authorizationStatus"))
        boundary_description = from_union([from_str, from_none], obj.get("boundaryDescription"))
        categorization_level = from_union([CategorizationLevel, from_none], obj.get("categorizationLevel"))
        control_designations = from_union([lambda x: from_list(ControlDesignation.from_dict, x), from_none], obj.get("controlDesignations"))
        data_flows = from_union([lambda x: from_list(DataFlow.from_dict, x), from_none], obj.get("dataFlows"))
        description = from_union([from_str, from_none], obj.get("description"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        identifier = from_union([from_str, from_none], obj.get("identifier"))
        identifier_scheme = from_union([from_str, from_none], obj.get("identifierScheme"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        owner = from_union([Identity.from_dict, from_none], obj.get("owner"))
        system_id = from_union([lambda x: UUID(x), from_none], obj.get("systemId"))
        version = from_union([from_str, from_none], obj.get("version"))
        return HdfSystem(components, name, authorization_date, authorization_status, boundary_description, categorization_level, control_designations, data_flows, description, generator, identifier, identifier_scheme, integrity, labels, owner, system_id, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["components"] = from_list(lambda x: to_class(Component, x), self.components)
        result["name"] = from_str(self.name)
        if self.authorization_date is not None:
            result["authorizationDate"] = from_union([lambda x: x.isoformat(), from_none], self.authorization_date)
        if self.authorization_status is not None:
            result["authorizationStatus"] = from_union([lambda x: to_enum(AuthorizationStatus, x), from_none], self.authorization_status)
        if self.boundary_description is not None:
            result["boundaryDescription"] = from_union([from_str, from_none], self.boundary_description)
        if self.categorization_level is not None:
            result["categorizationLevel"] = from_union([lambda x: to_enum(CategorizationLevel, x), from_none], self.categorization_level)
        if self.control_designations is not None:
            result["controlDesignations"] = from_union([lambda x: from_list(lambda x: to_class(ControlDesignation, x), x), from_none], self.control_designations)
        if self.data_flows is not None:
            result["dataFlows"] = from_union([lambda x: from_list(lambda x: to_class(DataFlow, x), x), from_none], self.data_flows)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.identifier is not None:
            result["identifier"] = from_union([from_str, from_none], self.identifier)
        if self.identifier_scheme is not None:
            result["identifierScheme"] = from_union([from_str, from_none], self.identifier_scheme)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.owner is not None:
            result["owner"] = from_union([lambda x: to_class(Identity, x), from_none], self.owner)
        if self.system_id is not None:
            result["systemId"] = from_union([lambda x: str(x), from_none], self.system_id)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


def hdf_system_from_dict(s: Any) -> HdfSystem:
    return HdfSystem.from_dict(s)


def hdf_system_to_dict(x: HdfSystem) -> Any:
    return to_class(HdfSystem, x)
