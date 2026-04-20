from dataclasses import dataclass
from typing import Optional, Any, List, Dict, Union, TypeVar, Callable, Type, cast
from enum import Enum
from datetime import datetime
from uuid import UUID
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


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def to_float(x: Any) -> float:
    assert isinstance(x, (int, float))
    return x


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


@dataclass
class Dependency:
    """A dependency for a baseline. Can include relative paths or URLs for where to find the
    dependency.
    """
    branch: Optional[str] = None
    """The branch name for a git repo."""

    compliance: Optional[str] = None
    """The 'user/profilename' attribute for an Automate server."""

    git: Optional[str] = None
    """The location of the git repo. Example:
    'https://github.com/my-org/ubuntu-22.04-stig-baseline.git'.
    """
    name: Optional[str] = None
    """The name or assigned alias."""

    path: Optional[str] = None
    """The relative path if the dependency is locally available."""

    status: Optional[str] = None
    """The status. Should be: 'loaded', 'failed', or 'skipped'."""

    status_message: Optional[str] = None
    """The reason for the status if it is 'failed' or 'skipped'."""

    supermarket: Optional[str] = None
    """The 'user/profilename' attribute for a Supermarket server."""

    url: Optional[str] = None
    """The address of the dependency."""

    @staticmethod
    def from_dict(obj: Any) -> 'Dependency':
        assert isinstance(obj, dict)
        branch = from_union([from_str, from_none], obj.get("branch"))
        compliance = from_union([from_str, from_none], obj.get("compliance"))
        git = from_union([from_str, from_none], obj.get("git"))
        name = from_union([from_str, from_none], obj.get("name"))
        path = from_union([from_str, from_none], obj.get("path"))
        status = from_union([from_str, from_none], obj.get("status"))
        status_message = from_union([from_str, from_none], obj.get("statusMessage"))
        supermarket = from_union([from_str, from_none], obj.get("supermarket"))
        url = from_union([from_str, from_none], obj.get("url"))
        return Dependency(branch, compliance, git, name, path, status, status_message, supermarket, url)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.branch is not None:
            result["branch"] = from_union([from_str, from_none], self.branch)
        if self.compliance is not None:
            result["compliance"] = from_union([from_str, from_none], self.compliance)
        if self.git is not None:
            result["git"] = from_union([from_str, from_none], self.git)
        if self.name is not None:
            result["name"] = from_union([from_str, from_none], self.name)
        if self.path is not None:
            result["path"] = from_union([from_str, from_none], self.path)
        if self.status is not None:
            result["status"] = from_union([from_str, from_none], self.status)
        if self.status_message is not None:
            result["statusMessage"] = from_union([from_str, from_none], self.status_message)
        if self.supermarket is not None:
            result["supermarket"] = from_union([from_str, from_none], self.supermarket)
        if self.url is not None:
            result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class RequirementGroup:
    """Describes a group of requirements, such as those defined in a single file."""

    id: str
    """The unique identifier for the group. Example: the relative path to the file specifying
    the requirements.
    """
    requirements: List[str]
    """The set of requirements as specified by their ids in this group. Example: 'SV-238196'."""

    title: Optional[str] = None
    """The title of the group - should be human readable."""

    @staticmethod
    def from_dict(obj: Any) -> 'RequirementGroup':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        requirements = from_list(from_str, obj.get("requirements"))
        title = from_union([from_str, from_none], obj.get("title"))
        return RequirementGroup(id, requirements, title)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["requirements"] = from_list(from_str, self.requirements)
        if self.title is not None:
            result["title"] = from_union([from_str, from_none], self.title)
        return result


@dataclass
class InputConstraints:
    """Validation constraints for the input value.
    
    Validation constraints for an input value.
    """
    allowed_values: Optional[List[Any]] = None
    """Enumeration of permitted values."""

    max: Optional[float] = None
    """Maximum allowed value (for Numeric inputs)."""

    min: Optional[float] = None
    """Minimum allowed value (for Numeric inputs)."""

    pattern: Optional[str] = None
    """Regular expression pattern the value must match (for String inputs)."""

    @staticmethod
    def from_dict(obj: Any) -> 'InputConstraints':
        assert isinstance(obj, dict)
        allowed_values = from_union([lambda x: from_list(lambda x: x, x), from_none], obj.get("allowedValues"))
        max = from_union([from_float, from_none], obj.get("max"))
        min = from_union([from_float, from_none], obj.get("min"))
        pattern = from_union([from_str, from_none], obj.get("pattern"))
        return InputConstraints(allowed_values, max, min, pattern)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.allowed_values is not None:
            result["allowedValues"] = from_union([lambda x: from_list(lambda x: x, x), from_none], self.allowed_values)
        if self.max is not None:
            result["max"] = from_union([to_float, from_none], self.max)
        if self.min is not None:
            result["min"] = from_union([to_float, from_none], self.min)
        if self.pattern is not None:
            result["pattern"] = from_union([from_str, from_none], self.pattern)
        return result


class ComparisonOperator(Enum):
    """The comparison operator used when evaluating this input against observed values.
    
    Comparison operator for evaluating the input value against observed values. Numeric:
    eq/ne/lt/le/gt/ge. String: eq/ne/contains/matches. Collection: in/notIn.
    """
    CONTAINS = "contains"
    EQ = "eq"
    GE = "ge"
    GT = "gt"
    IN = "in"
    LE = "le"
    LT = "lt"
    MATCHES = "matches"
    NE = "ne"
    NOT_IN = "notIn"


class InputType(Enum):
    """The data type of this input.
    
    The data type of the input value. Aligns with InSpec input types.
    """
    ARRAY = "Array"
    BOOLEAN = "Boolean"
    HASH = "Hash"
    NUMERIC = "Numeric"
    REGEXP = "Regexp"
    STRING = "String"


@dataclass
class Input:
    """A typed input parameter that bridges governance requirements and scanner automation.
    Inputs carry expected configuration values with type information, comparison operators,
    and validation constraints, enabling traceability from policy through to scan results.
    """
    name: str
    """The input name. Must be unique within a baseline or results document. Example:
    'max_concurrent_sessions'.
    """
    constraints: Optional[InputConstraints] = None
    """Validation constraints for the input value."""

    description: Optional[str] = None
    """Human-readable description of what this input controls."""

    operator: Optional[ComparisonOperator] = None
    """The comparison operator used when evaluating this input against observed values."""

    required: Optional[bool] = None
    """Whether this input must be provided. Defaults to false if omitted."""

    sensitive: Optional[bool] = None
    """Whether this input contains sensitive data (passwords, keys). Sensitive values should be
    redacted in output. Defaults to false if omitted.
    """
    type: Optional[InputType] = None
    """The data type of this input."""

    value: Any
    """The input value. Type should match the declared type field. Accepts any JSON value."""

    @staticmethod
    def from_dict(obj: Any) -> 'Input':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        constraints = from_union([InputConstraints.from_dict, from_none], obj.get("constraints"))
        description = from_union([from_str, from_none], obj.get("description"))
        operator = from_union([ComparisonOperator, from_none], obj.get("operator"))
        required = from_union([from_bool, from_none], obj.get("required"))
        sensitive = from_union([from_bool, from_none], obj.get("sensitive"))
        type = from_union([InputType, from_none], obj.get("type"))
        value = obj.get("value")
        return Input(name, constraints, description, operator, required, sensitive, type, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        if self.constraints is not None:
            result["constraints"] = from_union([lambda x: to_class(InputConstraints, x), from_none], self.constraints)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.operator is not None:
            result["operator"] = from_union([lambda x: to_enum(ComparisonOperator, x), from_none], self.operator)
        if self.required is not None:
            result["required"] = from_union([from_bool, from_none], self.required)
        if self.sensitive is not None:
            result["sensitive"] = from_union([from_bool, from_none], self.sensitive)
        if self.type is not None:
            result["type"] = from_union([lambda x: to_enum(InputType, x), from_none], self.type)
        if self.value is not None:
            result["value"] = self.value
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
    """Cryptographic integrity information for verifying this baseline has not been tampered
    with.
    
    Cryptographic integrity information for verifying the HDF file has not been tampered
    with. If algorithm is provided, checksum must also be provided, and vice versa.
    
    Cryptographic integrity information for verifying this file.
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
class Checksum:
    """SHA-256 checksum of the original baseline definition file (before execution). This is an
    immutable reference to the baseline as defined, used to detect tampering with baseline
    requirements or metadata.
    
    Cryptographic checksum for baseline integrity verification.
    
    SHA-256 checksum of the previous amendment in chronological order. Creates a
    tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
    on a requirement.
    
    SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).
    Used to detect tampering with test results. Compare with currentChecksum to verify
    amendment integrity.
    
    Optional cryptographic checksum for verifying the integrity of remediation resources
    fetched from the URI. Recommended for security when referencing external automation
    scripts.
    """
    algorithm: HashAlgorithm
    """The hash algorithm used for the checksum."""

    value: str
    """The checksum value."""

    @staticmethod
    def from_dict(obj: Any) -> 'Checksum':
        assert isinstance(obj, dict)
        algorithm = HashAlgorithm(obj.get("algorithm"))
        value = from_str(obj.get("value"))
        return Checksum(algorithm, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["algorithm"] = to_enum(HashAlgorithm, self.algorithm)
        result["value"] = from_str(self.value)
        return result


@dataclass
class Description:
    data: str
    """The description text content."""

    label: str
    """Description category. The 'default' label is required for the primary description. Common
    labels: 'default', 'check', 'fix', 'rationale'. Tools may use custom labels.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'Description':
        assert isinstance(obj, dict)
        data = from_str(obj.get("data"))
        label = from_str(obj.get("label"))
        return Description(data, label)

    def to_dict(self) -> dict:
        result: dict = {}
        result["data"] = from_str(self.data)
        result["label"] = from_str(self.label)
        return result


class OverrideType(Enum):
    """The type of the most recent non-expired override or POAM governing this requirement.
    Indicates why the requirement is in its current state (e.g., waiver, falsePositive,
    riskAdjustment) or what remediation is being tracked (poam). Absent when no overrides or
    POAMs apply.
    
    The type of amendment, aligned with FedRAMP deviation request categories. 'waiver': risk
    accepted by Authorizing Official. 'attestation': manually verified by assessor. 'poam':
    remediation tracked (no status change). 'inherited': control provided by another
    component or system. 'falsePositive': scanner incorrectly identified a finding — for
    compliance scans (STIG, CIS), the check actually passes, so status is typically set to
    'passed'; for vulnerability scans (CVE, SCA), the flagged vulnerability does not apply to
    this system, so status is typically set to 'notApplicable'. The disposition field on the
    requirement distinguishes false positives from genuinely not-applicable findings.
    'riskAdjustment': impact score adjusted based on environmental context (FedRAMP Risk
    Adjustment); does not change pass/fail status, only impact via the impact field.
    'operationalRequirement': deviation required by operational constraints (FedRAMP
    Operational Requirement); the finding cannot be remediated because the system requires
    the affected functionality. Remains an open risk. Migration note: 'exception' was removed
    in v3.1.0 — use 'waiver' with status 'notApplicable' instead.
    
    The type of override applied to this requirement.
    """
    ATTESTATION = "attestation"
    FALSE_POSITIVE = "falsePositive"
    INHERITED = "inherited"
    OPERATIONAL_REQUIREMENT = "operationalRequirement"
    POAM = "poam"
    RISK_ADJUSTMENT = "riskAdjustment"
    WAIVER = "waiver"


class ResultStatus(Enum):
    """The current effective compliance status of this requirement after applying the most
    recent non-expired override with a status field, or computed from results (worst-wins) if
    no status-bearing overrides exist.
    
    The status of an individual test result. 'notApplicable' indicates the requirement does
    not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
    requires manual verification).
    
    The status of this test within the requirement. Example: 'failed'.
    
    The new status this override sets for the requirement. Optional when only impact is being
    overridden.
    """
    ERROR = "error"
    FAILED = "failed"
    NOT_APPLICABLE = "notApplicable"
    NOT_REVIEWED = "notReviewed"
    PASSED = "passed"


class OperatorType(Enum):
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
    """Identity of who or what captured this evidence.
    
    Represents an identity that performed an action, such as capturing evidence or applying
    an override.
    
    Identity of who created this POA&M. For simple cases, use type 'simple' with just an
    identifier.
    
    Identity of who completed this milestone.
    
    The identity that created this signature.
    
    Identity of who applied this override. For simple cases, use type 'simple' with just an
    identifier.
    
    Identity of the person or system that approved this override.
    
    Team or individual responsible for this component. Enables per-component ownership when
    different teams manage different parts of a system.
    
    The identity of the person or system responsible for executing the test. This could be a
    human auditor manually completing a checklist, an automated CI/CD system, or a security
    tool. Optional field to support both automated and manual HDF generation.
    """
    identifier: str
    """The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'."""

    type: OperatorType
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
        type = OperatorType(obj.get("type"))
        description = from_union([from_str, from_none], obj.get("description"))
        return Identity(identifier, type, description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["identifier"] = from_str(self.identifier)
        result["type"] = to_enum(OperatorType, self.type)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        return result


class EvidenceType(Enum):
    """The type of evidence being provided."""

    CODE = "code"
    FILE = "file"
    LOG = "log"
    OTHER = "other"
    SCREENSHOT = "screenshot"
    URL = "url"


@dataclass
class Evidence:
    """Supporting evidence for a finding or override, such as screenshots, code samples, log
    excerpts, or URLs.
    """
    data: str
    """The evidence content. For screenshots/files: base64-encoded data or URL. For code/logs:
    the raw text. For URLs: the URL string.
    """
    type: EvidenceType
    """The type of evidence being provided."""

    captured_at: Optional[datetime] = None
    """Timestamp when this evidence was captured. ISO 8601 format."""

    captured_by: Optional[Identity] = None
    """Identity of who or what captured this evidence."""

    description: Optional[str] = None
    """Human-readable description of what this evidence shows."""

    encoding: Optional[str] = None
    """Encoding used for the data. Example: 'base64', 'utf-8'."""

    mime_type: Optional[str] = None
    """MIME type of the evidence. Example: 'image/png', 'text/plain', 'application/json'."""

    size: Optional[float] = None
    """Size of the evidence data in bytes."""

    @staticmethod
    def from_dict(obj: Any) -> 'Evidence':
        assert isinstance(obj, dict)
        data = from_str(obj.get("data"))
        type = EvidenceType(obj.get("type"))
        captured_at = from_union([from_datetime, from_none], obj.get("capturedAt"))
        captured_by = from_union([Identity.from_dict, from_none], obj.get("capturedBy"))
        description = from_union([from_str, from_none], obj.get("description"))
        encoding = from_union([from_str, from_none], obj.get("encoding"))
        mime_type = from_union([from_str, from_none], obj.get("mimeType"))
        size = from_union([from_float, from_none], obj.get("size"))
        return Evidence(data, type, captured_at, captured_by, description, encoding, mime_type, size)

    def to_dict(self) -> dict:
        result: dict = {}
        result["data"] = from_str(self.data)
        result["type"] = to_enum(EvidenceType, self.type)
        if self.captured_at is not None:
            result["capturedAt"] = from_union([lambda x: x.isoformat(), from_none], self.captured_at)
        if self.captured_by is not None:
            result["capturedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.captured_by)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.encoding is not None:
            result["encoding"] = from_union([from_str, from_none], self.encoding)
        if self.mime_type is not None:
            result["mimeType"] = from_union([from_str, from_none], self.mime_type)
        if self.size is not None:
            result["size"] = from_union([to_float, from_none], self.size)
        return result


class Status(Enum):
    """Current status of this milestone."""

    COMPLETED = "completed"
    IN_PROGRESS = "inProgress"
    PENDING = "pending"


@dataclass
class Milestone:
    """A milestone or task within a POA&M remediation plan."""

    description: str
    """Description of this milestone or task."""

    estimated_completion: datetime
    """Estimated completion date. ISO 8601 format."""

    status: Status
    """Current status of this milestone."""

    completed_at: Optional[datetime] = None
    """Actual completion timestamp. ISO 8601 format."""

    completed_by: Optional[Identity] = None
    """Identity of who completed this milestone."""

    @staticmethod
    def from_dict(obj: Any) -> 'Milestone':
        assert isinstance(obj, dict)
        description = from_str(obj.get("description"))
        estimated_completion = from_datetime(obj.get("estimatedCompletion"))
        status = Status(obj.get("status"))
        completed_at = from_union([from_datetime, from_none], obj.get("completedAt"))
        completed_by = from_union([Identity.from_dict, from_none], obj.get("completedBy"))
        return Milestone(description, estimated_completion, status, completed_at, completed_by)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_str(self.description)
        result["estimatedCompletion"] = self.estimated_completion.isoformat()
        result["status"] = to_enum(Status, self.status)
        if self.completed_at is not None:
            result["completedAt"] = from_union([lambda x: x.isoformat(), from_none], self.completed_at)
        if self.completed_by is not None:
            result["completedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.completed_by)
        return result


@dataclass
class VerificationMethod:
    """The verification method containing the public key for signature verification.
    
    Verification method containing the public key needed to verify a digital signature.
    Supports multiple key formats including JWK (for RSA, EC), PEM, and Base58.
    """
    controller: str
    """The entity that controls this verification method. Can be a DID, URI, or other identifier."""

    type: str
    """The type of verification method. Example: 'JsonWebKey2020', 'RsaVerificationKey2018',
    'Ed25519VerificationKey2020'.
    """
    public_key_base58: Optional[str] = None
    """Public key in Base58 format, commonly used with Ed25519 keys."""

    public_key_jwk: Optional[Dict[str, Any]] = None
    """Public key in JSON Web Key format."""

    public_key_pem: Optional[str] = None
    """Public key in PEM format. Example: '-----BEGIN PUBLIC KEY-----...-----END PUBLIC
    KEY-----'.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'VerificationMethod':
        assert isinstance(obj, dict)
        controller = from_str(obj.get("controller"))
        type = from_str(obj.get("type"))
        public_key_base58 = from_union([from_str, from_none], obj.get("publicKeyBase58"))
        public_key_jwk = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("publicKeyJwk"))
        public_key_pem = from_union([from_str, from_none], obj.get("publicKeyPem"))
        return VerificationMethod(controller, type, public_key_base58, public_key_jwk, public_key_pem)

    def to_dict(self) -> dict:
        result: dict = {}
        result["controller"] = from_str(self.controller)
        result["type"] = from_str(self.type)
        if self.public_key_base58 is not None:
            result["publicKeyBase58"] = from_union([from_str, from_none], self.public_key_base58)
        if self.public_key_jwk is not None:
            result["publicKeyJwk"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.public_key_jwk)
        if self.public_key_pem is not None:
            result["publicKeyPem"] = from_union([from_str, from_none], self.public_key_pem)
        return result


@dataclass
class Signature:
    """Optional digital signature for enhanced trust and non-repudiation.
    
    A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
    security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
    signing methods via JWK, PEM, or Base58 key formats.
    
    Optional digital signature for enhanced trust and non-repudiation. Supports hardware
    security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing
    methods.
    """
    created: datetime
    """When the signature was created. ISO 8601 format."""

    creator: Identity
    """The identity that created this signature."""

    proof_purpose: str
    """The purpose of this signature. Example: 'attestation', 'authentication',
    'assertionMethod'.
    """
    signature_value: str
    """The base64-encoded or base58-encoded signature value."""

    type: str
    """The signature suite type. Example: 'JsonWebSignature2020', 'RsaSignature2018',
    'Ed25519Signature2020'.
    """
    verification_method: VerificationMethod
    """The verification method containing the public key for signature verification."""

    challenge: Optional[str] = None
    """Challenge value from the verifier, used in challenge-response authentication."""

    domain: Optional[str] = None
    """Domain restriction for the signature, prevents cross-domain replay attacks."""

    nonce: Optional[str] = None
    """Random value to prevent replay attacks."""

    @staticmethod
    def from_dict(obj: Any) -> 'Signature':
        assert isinstance(obj, dict)
        created = from_datetime(obj.get("created"))
        creator = Identity.from_dict(obj.get("creator"))
        proof_purpose = from_str(obj.get("proofPurpose"))
        signature_value = from_str(obj.get("signatureValue"))
        type = from_str(obj.get("type"))
        verification_method = VerificationMethod.from_dict(obj.get("verificationMethod"))
        challenge = from_union([from_str, from_none], obj.get("challenge"))
        domain = from_union([from_str, from_none], obj.get("domain"))
        nonce = from_union([from_str, from_none], obj.get("nonce"))
        return Signature(created, creator, proof_purpose, signature_value, type, verification_method, challenge, domain, nonce)

    def to_dict(self) -> dict:
        result: dict = {}
        result["created"] = self.created.isoformat()
        result["creator"] = to_class(Identity, self.creator)
        result["proofPurpose"] = from_str(self.proof_purpose)
        result["signatureValue"] = from_str(self.signature_value)
        result["type"] = from_str(self.type)
        result["verificationMethod"] = to_class(VerificationMethod, self.verification_method)
        if self.challenge is not None:
            result["challenge"] = from_union([from_str, from_none], self.challenge)
        if self.domain is not None:
            result["domain"] = from_union([from_str, from_none], self.domain)
        if self.nonce is not None:
            result["nonce"] = from_union([from_str, from_none], self.nonce)
        return result


class PoamType(Enum):
    """The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
    compensating controls. 'riskAcceptance' documents decision to accept risk.
    'vendorDependency' tracks a fix that depends on a vendor releasing a patch or update.
    """
    MITIGATION = "mitigation"
    REMEDIATION = "remediation"
    RISK_ACCEPTANCE = "riskAcceptance"
    VENDOR_DEPENDENCY = "vendorDependency"


@dataclass
class Poam:
    """Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
    POAMs do NOT change the effectiveStatus - the requirement remains in its current state
    while the POA&M tracks remediation efforts.
    """
    applied_at: datetime
    """Timestamp when this POA&M was created. ISO 8601 format."""

    applied_by: Identity
    """Identity of who created this POA&M. For simple cases, use type 'simple' with just an
    identifier.
    """
    explanation: str
    """Detailed explanation of the plan, including what actions will be taken."""

    type: PoamType
    """The type of POA&M. 'remediation' fixes root cause. 'mitigation' reduces risk via
    compensating controls. 'riskAcceptance' documents decision to accept risk.
    'vendorDependency' tracks a fix that depends on a vendor releasing a patch or update.
    """
    evidence: Optional[List[Evidence]] = None
    """Supporting evidence for this POA&M, such as documentation of compensating controls or
    mitigation implementation.
    """
    expires_at: Optional[datetime] = None
    """Optional expiration date for this POA&M requiring review/renewal. ISO 8601 format."""

    milestones: Optional[List[Milestone]] = None
    """Optional array of milestones tracking progress toward completion."""

    previous_checksum: Optional[Checksum] = None
    """SHA-256 checksum of the previous amendment in chronological order. Creates a
    tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
    on a requirement.
    """
    signature: Optional[Signature] = None
    """Optional digital signature for enhanced trust and non-repudiation."""

    @staticmethod
    def from_dict(obj: Any) -> 'Poam':
        assert isinstance(obj, dict)
        applied_at = from_datetime(obj.get("appliedAt"))
        applied_by = Identity.from_dict(obj.get("appliedBy"))
        explanation = from_str(obj.get("explanation"))
        type = PoamType(obj.get("type"))
        evidence = from_union([lambda x: from_list(Evidence.from_dict, x), from_none], obj.get("evidence"))
        expires_at = from_union([from_datetime, from_none], obj.get("expiresAt"))
        milestones = from_union([lambda x: from_list(Milestone.from_dict, x), from_none], obj.get("milestones"))
        previous_checksum = from_union([Checksum.from_dict, from_none], obj.get("previousChecksum"))
        signature = from_union([Signature.from_dict, from_none], obj.get("signature"))
        return Poam(applied_at, applied_by, explanation, type, evidence, expires_at, milestones, previous_checksum, signature)

    def to_dict(self) -> dict:
        result: dict = {}
        result["appliedAt"] = self.applied_at.isoformat()
        result["appliedBy"] = to_class(Identity, self.applied_by)
        result["explanation"] = from_str(self.explanation)
        result["type"] = to_enum(PoamType, self.type)
        if self.evidence is not None:
            result["evidence"] = from_union([lambda x: from_list(lambda x: to_class(Evidence, x), x), from_none], self.evidence)
        if self.expires_at is not None:
            result["expiresAt"] = from_union([lambda x: x.isoformat(), from_none], self.expires_at)
        if self.milestones is not None:
            result["milestones"] = from_union([lambda x: from_list(lambda x: to_class(Milestone, x), x), from_none], self.milestones)
        if self.previous_checksum is not None:
            result["previousChecksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.previous_checksum)
        if self.signature is not None:
            result["signature"] = from_union([lambda x: to_class(Signature, x), from_none], self.signature)
        return result


@dataclass
class Reference:
    """A reference to an external document.
    
    A reference using the 'ref' field.
    
    A URL pointing at the reference.
    
    A URI pointing at the reference.
    """
    ref: Optional[Union[List[Dict[str, Any]], str]] = None
    url: Optional[str] = None
    uri: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Reference':
        assert isinstance(obj, dict)
        ref = from_union([lambda x: from_list(lambda x: from_dict(lambda x: x, x), x), from_str, from_none], obj.get("ref"))
        url = from_union([from_str, from_none], obj.get("url"))
        uri = from_union([from_str, from_none], obj.get("uri"))
        return Reference(ref, url, uri)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.ref is not None:
            result["ref"] = from_union([lambda x: from_list(lambda x: from_dict(lambda x: x, x), x), from_str, from_none], self.ref)
        if self.url is not None:
            result["url"] = from_union([from_str, from_none], self.url)
        if self.uri is not None:
            result["uri"] = from_union([from_str, from_none], self.uri)
        return result


@dataclass
class RequirementResult:
    """A test within a requirement and its results and findings such as how long it took to run."""

    code_desc: str
    """A description of this test. Example: 'limits.conf * is expected to include ["hard",
    "maxlogins", "10"]'.
    """
    start_time: datetime
    """The time at which the test started."""

    status: ResultStatus
    """The status of this test within the requirement. Example: 'failed'."""

    backtrace: Optional[List[str]] = None
    """The stacktrace/backtrace of the exception if one occurred."""

    exception: Optional[str] = None
    """The type of exception if an exception was thrown."""

    message: Optional[str] = None
    """An explanation of the test result. Typically provided for failed tests, errors, or to
    explain why a test was not applicable or not reviewed.
    """
    resource: Optional[str] = None
    """The resource used in the test. Example: 'file', 'command', 'service'."""

    resource_id: Optional[str] = None
    """The unique identifier of the resource. Example: '/etc/passwd'."""

    run_time: Optional[float] = None
    """The execution time in seconds for the test."""

    @staticmethod
    def from_dict(obj: Any) -> 'RequirementResult':
        assert isinstance(obj, dict)
        code_desc = from_str(obj.get("codeDesc"))
        start_time = from_datetime(obj.get("startTime"))
        status = ResultStatus(obj.get("status"))
        backtrace = from_union([lambda x: from_list(from_str, x), from_none], obj.get("backtrace"))
        exception = from_union([from_str, from_none], obj.get("exception"))
        message = from_union([from_str, from_none], obj.get("message"))
        resource = from_union([from_str, from_none], obj.get("resource"))
        resource_id = from_union([from_str, from_none], obj.get("resourceId"))
        run_time = from_union([from_float, from_none], obj.get("runTime"))
        return RequirementResult(code_desc, start_time, status, backtrace, exception, message, resource, resource_id, run_time)

    def to_dict(self) -> dict:
        result: dict = {}
        result["codeDesc"] = from_str(self.code_desc)
        result["startTime"] = self.start_time.isoformat()
        result["status"] = to_enum(ResultStatus, self.status)
        if self.backtrace is not None:
            result["backtrace"] = from_union([lambda x: from_list(from_str, x), from_none], self.backtrace)
        if self.exception is not None:
            result["exception"] = from_union([from_str, from_none], self.exception)
        if self.message is not None:
            result["message"] = from_union([from_str, from_none], self.message)
        if self.resource is not None:
            result["resource"] = from_union([from_str, from_none], self.resource)
        if self.resource_id is not None:
            result["resourceId"] = from_union([from_str, from_none], self.resource_id)
        if self.run_time is not None:
            result["runTime"] = from_union([to_float, from_none], self.run_time)
        return result


class Severity(Enum):
    """Explicit severity rating. Typically derived from impact score but provided explicitly for
    clarity.
    
    Severity rating for a requirement. Typically derived from the numeric impact score.
    """
    CRITICAL = "critical"
    HIGH = "high"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"


@dataclass
class SourceLocation:
    """The explicit location of the requirement within the source code.
    
    The explicit location of a requirement within source code.
    """
    line: Optional[float] = None
    """The line on which this requirement is located."""

    ref: Optional[str] = None
    """Path to the file that this requirement originates from."""

    @staticmethod
    def from_dict(obj: Any) -> 'SourceLocation':
        assert isinstance(obj, dict)
        line = from_union([from_float, from_none], obj.get("line"))
        ref = from_union([from_str, from_none], obj.get("ref"))
        return SourceLocation(line, ref)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.line is not None:
            result["line"] = from_union([to_float, from_none], self.line)
        if self.ref is not None:
            result["ref"] = from_union([from_str, from_none], self.ref)
        return result


@dataclass
class ImpactOverride:
    """Override to the requirement's impact score. At least one of status or impact must be
    set.
    
    An override to the requirement's impact score. The prior impact is the original result
    value or the preceding override in the chain.
    """
    value: float
    """The overridden impact score (0.0–1.0)."""

    @staticmethod
    def from_dict(obj: Any) -> 'ImpactOverride':
        assert isinstance(obj, dict)
        value = from_float(obj.get("value"))
        return ImpactOverride(value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["value"] = to_float(self.value)
        return result


@dataclass
class StatusOverride:
    """An intentional change to a requirement's compliance status and/or impact score. At least
    one of status or impact must be set. Overrides change the effectiveStatus or impact of
    the requirement. All overrides must have an expiration date to enforce periodic review.
    """
    applied_at: datetime
    """Timestamp when this override was applied. ISO 8601 format."""

    applied_by: Identity
    """Identity of who applied this override. For simple cases, use type 'simple' with just an
    identifier.
    """
    expires_at: datetime
    """Timestamp when this override expires and must be reviewed/renewed. REQUIRED - no
    permanent overrides allowed. ISO 8601 format.
    """
    reason: str
    """Explanation for why this override was applied."""

    type: OverrideType
    """The type of override applied to this requirement."""

    evidence: Optional[List[Evidence]] = None
    """Supporting evidence for this override, such as screenshots demonstrating manual
    verification for attestations.
    """
    impact: Optional[ImpactOverride] = None
    """Override to the requirement's impact score. At least one of status or impact must be set."""

    previous_checksum: Optional[Checksum] = None
    """SHA-256 checksum of the previous amendment in chronological order. Creates a
    tamper-evident chain of amendments (similar to blockchain). Null for the first amendment
    on a requirement.
    """
    signature: Optional[Signature] = None
    """Optional digital signature for enhanced trust and non-repudiation. Supports hardware
    security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other signing
    methods.
    """
    status: Optional[ResultStatus] = None
    """The new status this override sets for the requirement. Optional when only impact is being
    overridden.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'StatusOverride':
        assert isinstance(obj, dict)
        applied_at = from_datetime(obj.get("appliedAt"))
        applied_by = Identity.from_dict(obj.get("appliedBy"))
        expires_at = from_datetime(obj.get("expiresAt"))
        reason = from_str(obj.get("reason"))
        type = OverrideType(obj.get("type"))
        evidence = from_union([lambda x: from_list(Evidence.from_dict, x), from_none], obj.get("evidence"))
        impact = from_union([ImpactOverride.from_dict, from_none], obj.get("impact"))
        previous_checksum = from_union([Checksum.from_dict, from_none], obj.get("previousChecksum"))
        signature = from_union([Signature.from_dict, from_none], obj.get("signature"))
        status = from_union([ResultStatus, from_none], obj.get("status"))
        return StatusOverride(applied_at, applied_by, expires_at, reason, type, evidence, impact, previous_checksum, signature, status)

    def to_dict(self) -> dict:
        result: dict = {}
        result["appliedAt"] = self.applied_at.isoformat()
        result["appliedBy"] = to_class(Identity, self.applied_by)
        result["expiresAt"] = self.expires_at.isoformat()
        result["reason"] = from_str(self.reason)
        result["type"] = to_enum(OverrideType, self.type)
        if self.evidence is not None:
            result["evidence"] = from_union([lambda x: from_list(lambda x: to_class(Evidence, x), x), from_none], self.evidence)
        if self.impact is not None:
            result["impact"] = from_union([lambda x: to_class(ImpactOverride, x), from_none], self.impact)
        if self.previous_checksum is not None:
            result["previousChecksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.previous_checksum)
        if self.signature is not None:
            result["signature"] = from_union([lambda x: to_class(Signature, x), from_none], self.signature)
        if self.status is not None:
            result["status"] = from_union([lambda x: to_enum(ResultStatus, x), from_none], self.status)
        return result


@dataclass
class EvaluatedRequirement:
    """A requirement that has been evaluated, including any findings.
    
    Core requirement fields shared between baseline requirements and evaluated requirements.
    Contains the fundamental requirement definition without assessment results.
    """
    descriptions: List[Description]
    """Array of labeled descriptions. At least one description with label 'default' must be
    present. Convention: place default description first. Common labels: 'default', 'check',
    'fix', 'rationale'.
    """
    results: List[RequirementResult]
    """The set of all tests within the requirement and their results."""

    id: str
    """The requirement identifier. Example: 'SV-238196'."""

    impact: float
    """The impactfulness or severity (0.0 to 1.0)."""

    tags: Dict[str, Any]
    """A set of tags - usually metadata like CCI, STIG ID, severity."""

    disposition: Optional[OverrideType] = None
    """The type of the most recent non-expired override or POAM governing this requirement.
    Indicates why the requirement is in its current state (e.g., waiver, falsePositive,
    riskAdjustment) or what remediation is being tracked (poam). Absent when no overrides or
    POAMs apply.
    """
    effective_impact: Optional[float] = None
    """The current effective impact score (0.0–1.0) after applying the most recent non-expired
    override with an impact field. Absent when no impact overrides apply; consumers should
    use the requirement's impact field in that case.
    """
    effective_status: Optional[ResultStatus] = None
    """The current effective compliance status of this requirement after applying the most
    recent non-expired override with a status field, or computed from results (worst-wins) if
    no status-bearing overrides exist.
    """
    evidence: Optional[List[Evidence]] = None
    """Supporting evidence for this requirement's findings, such as screenshots, code samples,
    or log excerpts.
    """
    poams: Optional[List[Poam]] = None
    """Plan of Action and Milestones for tracking remediation, mitigation, or risk acceptance.
    POAMs do NOT change effectiveStatus - they track the work being done to address a
    failure. Separate from statusOverrides which DO change status.
    """
    severity: Optional[Severity] = None
    """Explicit severity rating. Typically derived from impact score but provided explicitly for
    clarity.
    """
    source_location: Optional[SourceLocation] = None
    """The explicit location of the requirement within the source code."""

    status_overrides: Optional[List[StatusOverride]] = None
    """Chronological history of all overrides applied to this requirement. Overrides are
    intentional changes to the compliance status and/or impact score (waivers, attestations,
    false positives, risk adjustments). Most recent override should be first in array.
    Preserves full audit trail.
    """
    code: Optional[str] = None
    """The raw source code of the requirement. Set to null for manual-only requirements or
    requirements not yet implemented. Note that if this is an overlay, it does not include
    the underlying source code.
    """
    refs: Optional[List[Reference]] = None
    """The set of references to external documents."""

    title: Optional[str] = None
    """The title - is nullable."""

    @staticmethod
    def from_dict(obj: Any) -> 'EvaluatedRequirement':
        assert isinstance(obj, dict)
        descriptions = from_list(Description.from_dict, obj.get("descriptions"))
        results = from_list(RequirementResult.from_dict, obj.get("results"))
        id = from_str(obj.get("id"))
        impact = from_float(obj.get("impact"))
        tags = from_dict(lambda x: x, obj.get("tags"))
        disposition = from_union([OverrideType, from_none], obj.get("disposition"))
        effective_impact = from_union([from_float, from_none], obj.get("effectiveImpact"))
        effective_status = from_union([ResultStatus, from_none], obj.get("effectiveStatus"))
        evidence = from_union([lambda x: from_list(Evidence.from_dict, x), from_none], obj.get("evidence"))
        poams = from_union([lambda x: from_list(Poam.from_dict, x), from_none], obj.get("poams"))
        severity = from_union([Severity, from_none], obj.get("severity"))
        source_location = from_union([SourceLocation.from_dict, from_none], obj.get("sourceLocation"))
        status_overrides = from_union([lambda x: from_list(StatusOverride.from_dict, x), from_none], obj.get("statusOverrides"))
        code = from_union([from_str, from_none], obj.get("code"))
        refs = from_union([lambda x: from_list(Reference.from_dict, x), from_none], obj.get("refs"))
        title = from_union([from_str, from_none], obj.get("title"))
        return EvaluatedRequirement(descriptions, results, id, impact, tags, disposition, effective_impact, effective_status, evidence, poams, severity, source_location, status_overrides, code, refs, title)

    def to_dict(self) -> dict:
        result: dict = {}
        result["descriptions"] = from_list(lambda x: to_class(Description, x), self.descriptions)
        result["results"] = from_list(lambda x: to_class(RequirementResult, x), self.results)
        result["id"] = from_str(self.id)
        result["impact"] = to_float(self.impact)
        result["tags"] = from_dict(lambda x: x, self.tags)
        if self.disposition is not None:
            result["disposition"] = from_union([lambda x: to_enum(OverrideType, x), from_none], self.disposition)
        if self.effective_impact is not None:
            result["effectiveImpact"] = from_union([to_float, from_none], self.effective_impact)
        if self.effective_status is not None:
            result["effectiveStatus"] = from_union([lambda x: to_enum(ResultStatus, x), from_none], self.effective_status)
        if self.evidence is not None:
            result["evidence"] = from_union([lambda x: from_list(lambda x: to_class(Evidence, x), x), from_none], self.evidence)
        if self.poams is not None:
            result["poams"] = from_union([lambda x: from_list(lambda x: to_class(Poam, x), x), from_none], self.poams)
        if self.severity is not None:
            result["severity"] = from_union([lambda x: to_enum(Severity, x), from_none], self.severity)
        if self.source_location is not None:
            result["sourceLocation"] = from_union([lambda x: to_class(SourceLocation, x), from_none], self.source_location)
        if self.status_overrides is not None:
            result["statusOverrides"] = from_union([lambda x: from_list(lambda x: to_class(StatusOverride, x), x), from_none], self.status_overrides)
        if self.code is not None:
            result["code"] = from_union([from_str, from_none], self.code)
        if self.refs is not None:
            result["refs"] = from_union([lambda x: from_list(lambda x: to_class(Reference, x), x), from_none], self.refs)
        if self.title is not None:
            result["title"] = from_union([from_str, from_none], self.title)
        return result


@dataclass
class SupportedPlatform:
    """A supported platform target. Example: the platform name being 'ubuntu'."""

    platform: Optional[str] = None
    """The location of the platform. Can be: 'os', 'aws', 'azure', or 'gcp'."""

    platform_family: Optional[str] = None
    """The platform family. Example: 'redhat'."""

    platform_name: Optional[str] = None
    """The platform name - can include wildcards. Example: 'debian'."""

    release: Optional[str] = None
    """The release of the platform. Example: '20.04' for 'ubuntu'."""

    @staticmethod
    def from_dict(obj: Any) -> 'SupportedPlatform':
        assert isinstance(obj, dict)
        platform = from_union([from_str, from_none], obj.get("platform"))
        platform_family = from_union([from_str, from_none], obj.get("platformFamily"))
        platform_name = from_union([from_str, from_none], obj.get("platformName"))
        release = from_union([from_str, from_none], obj.get("release"))
        return SupportedPlatform(platform, platform_family, platform_name, release)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.platform is not None:
            result["platform"] = from_union([from_str, from_none], self.platform)
        if self.platform_family is not None:
            result["platformFamily"] = from_union([from_str, from_none], self.platform_family)
        if self.platform_name is not None:
            result["platformName"] = from_union([from_str, from_none], self.platform_name)
        if self.release is not None:
            result["release"] = from_union([from_str, from_none], self.release)
        return result


@dataclass
class EvaluatedBaseline:
    """Information on a baseline that was evaluated, including any findings.
    
    Shared metadata fields for baselines. Used in both standalone baseline documents and
    evaluated baseline results.
    """
    requirements: List[EvaluatedRequirement]
    """The set of requirements including any findings. A baseline must have at least one
    requirement.
    """
    name: str
    """The name - must be unique."""

    depends: Optional[List[Dependency]] = None
    """The set of dependencies this baseline depends on."""

    description: Optional[str] = None
    """The description - should be more detailed than the summary."""

    extensions: Optional[Dict[str, Any]] = None
    """Reserved for tool-specific baseline metadata not defined in the HDF standard."""

    groups: Optional[List[RequirementGroup]] = None
    """A set of descriptions for the requirement groups."""

    inputs: Optional[List[Input]] = None
    """Typed inputs used to parameterize this baseline at execution time. See the Input
    primitive for the full schema.
    """
    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this baseline has not been tampered
    with.
    """
    original_checksum: Optional[Checksum] = None
    """SHA-256 checksum of the original baseline definition file (before execution). This is an
    immutable reference to the baseline as defined, used to detect tampering with baseline
    requirements or metadata.
    """
    parent_baseline: Optional[str] = None
    """The name of the parent baseline if this is a dependency of another."""

    results_checksum: Optional[Checksum] = None
    """SHA-256 checksum of the raw results before any amendments (statusOverrides or POAMs).
    Used to detect tampering with test results. Compare with currentChecksum to verify
    amendment integrity.
    """
    status_message: Optional[str] = None
    """An explanation of the baseline status. Example: why it was skipped, failed to load, or
    any other status details.
    """
    copyright: Optional[str] = None
    """The copyright holder(s)."""

    copyright_email: Optional[str] = None
    """The email address or other contact information of the copyright holder(s)."""

    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for flexible grouping. Well-known keys: system, component,
    environment, region, team. Values must be strings.
    """
    license: Optional[str] = None
    """The copyright license. Example: 'Apache-2.0'."""

    maintainer: Optional[str] = None
    """The maintainer(s)."""

    status: Optional[str] = None
    """The status. Example: 'loaded'."""

    summary: Optional[str] = None
    """The summary. Example: the Security Technical Implementation Guide (STIG) header."""

    supports: Optional[List[SupportedPlatform]] = None
    """The set of supported platform targets."""

    title: Optional[str] = None
    """The title - should be human readable."""

    version: Optional[str] = None
    """The version of the baseline."""

    @staticmethod
    def from_dict(obj: Any) -> 'EvaluatedBaseline':
        assert isinstance(obj, dict)
        requirements = from_list(EvaluatedRequirement.from_dict, obj.get("requirements"))
        name = from_str(obj.get("name"))
        depends = from_union([lambda x: from_list(Dependency.from_dict, x), from_none], obj.get("depends"))
        description = from_union([from_str, from_none], obj.get("description"))
        extensions = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("extensions"))
        groups = from_union([lambda x: from_list(RequirementGroup.from_dict, x), from_none], obj.get("groups"))
        inputs = from_union([lambda x: from_list(Input.from_dict, x), from_none], obj.get("inputs"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        original_checksum = from_union([Checksum.from_dict, from_none], obj.get("originalChecksum"))
        parent_baseline = from_union([from_str, from_none], obj.get("parentBaseline"))
        results_checksum = from_union([Checksum.from_dict, from_none], obj.get("resultsChecksum"))
        status_message = from_union([from_str, from_none], obj.get("statusMessage"))
        copyright = from_union([from_str, from_none], obj.get("copyright"))
        copyright_email = from_union([from_str, from_none], obj.get("copyrightEmail"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        license = from_union([from_str, from_none], obj.get("license"))
        maintainer = from_union([from_str, from_none], obj.get("maintainer"))
        status = from_union([from_str, from_none], obj.get("status"))
        summary = from_union([from_str, from_none], obj.get("summary"))
        supports = from_union([lambda x: from_list(SupportedPlatform.from_dict, x), from_none], obj.get("supports"))
        title = from_union([from_str, from_none], obj.get("title"))
        version = from_union([from_str, from_none], obj.get("version"))
        return EvaluatedBaseline(requirements, name, depends, description, extensions, groups, inputs, integrity, original_checksum, parent_baseline, results_checksum, status_message, copyright, copyright_email, labels, license, maintainer, status, summary, supports, title, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["requirements"] = from_list(lambda x: to_class(EvaluatedRequirement, x), self.requirements)
        result["name"] = from_str(self.name)
        if self.depends is not None:
            result["depends"] = from_union([lambda x: from_list(lambda x: to_class(Dependency, x), x), from_none], self.depends)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.extensions is not None:
            result["extensions"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.extensions)
        if self.groups is not None:
            result["groups"] = from_union([lambda x: from_list(lambda x: to_class(RequirementGroup, x), x), from_none], self.groups)
        if self.inputs is not None:
            result["inputs"] = from_union([lambda x: from_list(lambda x: to_class(Input, x), x), from_none], self.inputs)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.original_checksum is not None:
            result["originalChecksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.original_checksum)
        if self.parent_baseline is not None:
            result["parentBaseline"] = from_union([from_str, from_none], self.parent_baseline)
        if self.results_checksum is not None:
            result["resultsChecksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.results_checksum)
        if self.status_message is not None:
            result["statusMessage"] = from_union([from_str, from_none], self.status_message)
        if self.copyright is not None:
            result["copyright"] = from_union([from_str, from_none], self.copyright)
        if self.copyright_email is not None:
            result["copyrightEmail"] = from_union([from_str, from_none], self.copyright_email)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.license is not None:
            result["license"] = from_union([from_str, from_none], self.license)
        if self.maintainer is not None:
            result["maintainer"] = from_union([from_str, from_none], self.maintainer)
        if self.status is not None:
            result["status"] = from_union([from_str, from_none], self.status)
        if self.summary is not None:
            result["summary"] = from_union([from_str, from_none], self.summary)
        if self.supports is not None:
            result["supports"] = from_union([lambda x: from_list(lambda x: to_class(SupportedPlatform, x), x), from_none], self.supports)
        if self.title is not None:
            result["title"] = from_union([from_str, from_none], self.title)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
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


class Copyright(Enum):
    """A human readable/meaningful reference. Example: a book title.
    
    IP address of the host.
    """
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

    type: Copyright
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
        type = Copyright(obj.get("type"))
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
        result["type"] = to_enum(Copyright, self.type)
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


@dataclass
class Generator:
    """Information about the tool that generated this file.
    
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


@dataclass
class Remediation:
    """Optional reference to automated remediation resources (Ansible playbooks, Terraform
    scripts, etc.) for fixing failing requirements found in this assessment.
    
    Reference to automated remediation resources for implementing security controls. Points
    to external automation content like Ansible playbooks, Terraform scripts, or
    vendor-provided remediation tools.
    """
    uri: str
    """URI pointing to automated remediation resources (Ansible playbooks, Terraform scripts,
    etc.). Examples: GitHub repository, DISA STIG Supplemental Automation Content,
    vendor-provided scripts.
    """
    checksum: Optional[Checksum] = None
    """Optional cryptographic checksum for verifying the integrity of remediation resources
    fetched from the URI. Recommended for security when referencing external automation
    scripts.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'Remediation':
        assert isinstance(obj, dict)
        uri = from_str(obj.get("uri"))
        checksum = from_union([Checksum.from_dict, from_none], obj.get("checksum"))
        return Remediation(uri, checksum)

    def to_dict(self) -> dict:
        result: dict = {}
        result["uri"] = from_str(self.uri)
        if self.checksum is not None:
            result["checksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.checksum)
        return result


@dataclass
class Runner:
    """Information about the test execution environment where the security tool was run.
    Distinct from targets (what is being tested).
    
    Information about the test execution environment. This is distinct from the target being
    scanned - the runner is where the security tool executes, while targets are what is being
    assessed.
    """
    name: str
    """The name of the runner environment. Examples: 'ubuntu', 'macos', 'windows', 'docker',
    'kubernetes-pod', 'manual'.
    """
    architecture: Optional[str] = None
    """The CPU architecture of the runner system. Example: 'x86_64', 'arm64', 'aarch64'."""

    container_id: Optional[str] = None
    """The container instance identifier. Example: 'a1b2c3d4e5f6', 'security-scan-job-xyz123'.
    Can be a Docker container ID, Kubernetes pod name, or other container runtime identifier.
    """
    container_image: Optional[str] = None
    """The container image used for the test execution. Example: 'inspec/inspec:latest',
    'ghcr.io/my-org/scanner:v2.1.0'. Useful for CI/CD pipelines where tests run in containers.
    """
    hostname: Optional[str] = None
    """The hostname of the runner system. Example: 'ci-runner-01', 'jenkins-agent-03',
    'k8s-node-worker-03'.
    """
    operator: Optional[Identity] = None
    """The identity of the person or system responsible for executing the test. This could be a
    human auditor manually completing a checklist, an automated CI/CD system, or a security
    tool. Optional field to support both automated and manual HDF generation.
    """
    release: Optional[str] = None
    """The version/release of the operating system or runtime. Example: '20.04', '13.2', '11'."""

    @staticmethod
    def from_dict(obj: Any) -> 'Runner':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        architecture = from_union([from_str, from_none], obj.get("architecture"))
        container_id = from_union([from_str, from_none], obj.get("containerId"))
        container_image = from_union([from_str, from_none], obj.get("containerImage"))
        hostname = from_union([from_str, from_none], obj.get("hostname"))
        operator = from_union([Identity.from_dict, from_none], obj.get("operator"))
        release = from_union([from_str, from_none], obj.get("release"))
        return Runner(name, architecture, container_id, container_image, hostname, operator, release)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        if self.architecture is not None:
            result["architecture"] = from_union([from_str, from_none], self.architecture)
        if self.container_id is not None:
            result["containerId"] = from_union([from_str, from_none], self.container_id)
        if self.container_image is not None:
            result["containerImage"] = from_union([from_str, from_none], self.container_image)
        if self.hostname is not None:
            result["hostname"] = from_union([from_str, from_none], self.hostname)
        if self.operator is not None:
            result["operator"] = from_union([lambda x: to_class(Identity, x), from_none], self.operator)
        if self.release is not None:
            result["release"] = from_union([from_str, from_none], self.release)
        return result


@dataclass
class StatisticBlock:
    """Statistics for requirements that encountered an error during assessment.
    
    Statistics for a given item, such as the total count.
    
    Statistics for requirements that failed.
    
    Statistics for requirements that are not applicable to the target.
    
    Statistics for requirements that were not reviewed (manual check required).
    
    Statistics for requirements that passed.
    """
    total: int
    """The total count. Example: the total number of requirements in a given category for a run."""

    @staticmethod
    def from_dict(obj: Any) -> 'StatisticBlock':
        assert isinstance(obj, dict)
        total = from_int(obj.get("total"))
        return StatisticBlock(total)

    def to_dict(self) -> dict:
        result: dict = {}
        result["total"] = from_int(self.total)
        return result


@dataclass
class StatisticHash:
    """Breakdowns of requirement statistics by result status.
    
    Statistics for requirement results, grouped by status.
    """
    error: Optional[StatisticBlock] = None
    """Statistics for requirements that encountered an error during assessment."""

    failed: Optional[StatisticBlock] = None
    """Statistics for requirements that failed."""

    not_applicable: Optional[StatisticBlock] = None
    """Statistics for requirements that are not applicable to the target."""

    not_reviewed: Optional[StatisticBlock] = None
    """Statistics for requirements that were not reviewed (manual check required)."""

    passed: Optional[StatisticBlock] = None
    """Statistics for requirements that passed."""

    @staticmethod
    def from_dict(obj: Any) -> 'StatisticHash':
        assert isinstance(obj, dict)
        error = from_union([StatisticBlock.from_dict, from_none], obj.get("error"))
        failed = from_union([StatisticBlock.from_dict, from_none], obj.get("failed"))
        not_applicable = from_union([StatisticBlock.from_dict, from_none], obj.get("notApplicable"))
        not_reviewed = from_union([StatisticBlock.from_dict, from_none], obj.get("notReviewed"))
        passed = from_union([StatisticBlock.from_dict, from_none], obj.get("passed"))
        return StatisticHash(error, failed, not_applicable, not_reviewed, passed)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.error is not None:
            result["error"] = from_union([lambda x: to_class(StatisticBlock, x), from_none], self.error)
        if self.failed is not None:
            result["failed"] = from_union([lambda x: to_class(StatisticBlock, x), from_none], self.failed)
        if self.not_applicable is not None:
            result["notApplicable"] = from_union([lambda x: to_class(StatisticBlock, x), from_none], self.not_applicable)
        if self.not_reviewed is not None:
            result["notReviewed"] = from_union([lambda x: to_class(StatisticBlock, x), from_none], self.not_reviewed)
        if self.passed is not None:
            result["passed"] = from_union([lambda x: to_class(StatisticBlock, x), from_none], self.passed)
        return result


@dataclass
class Statistics:
    """Statistics for the assessment run, including duration and result counts.
    
    Statistics for the assessment run(s) such as duration and result counts.
    """
    duration: Optional[float] = None
    """How long (in seconds) this assessment run took."""

    requirements: Optional[StatisticHash] = None
    """Breakdowns of requirement statistics by result status."""

    @staticmethod
    def from_dict(obj: Any) -> 'Statistics':
        assert isinstance(obj, dict)
        duration = from_union([from_float, from_none], obj.get("duration"))
        requirements = from_union([StatisticHash.from_dict, from_none], obj.get("requirements"))
        return Statistics(duration, requirements)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.duration is not None:
            result["duration"] = from_union([to_float, from_none], self.duration)
        if self.requirements is not None:
            result["requirements"] = from_union([lambda x: to_class(StatisticHash, x), from_none], self.requirements)
        return result


@dataclass
class Tool:
    """The security tool that produced the assessment data in this file.
    
    The security tool that produced the assessment data represented in this HDF file. Aligns
    with SARIF, OSCAL, and CycloneDX terminology.
    """
    format: Optional[str] = None
    """The file format, if it is a recognized named format shared by multiple tools. Examples:
    'SARIF', 'XCCDF'. Omit for tool-specific formats where the tool name already implies the
    format (Nessus XML, gosec JSON).
    """
    name: Optional[str] = None
    """The name of the security tool that produced the data. Examples: 'gosec', 'Semgrep',
    'OpenSCAP', 'AWS Config', 'Nessus'. Omit if the tool cannot be identified.
    """
    version: Optional[str] = None
    """Version of the source tool, if available in the tool's output. Example: '5.22.3'."""

    @staticmethod
    def from_dict(obj: Any) -> 'Tool':
        assert isinstance(obj, dict)
        format = from_union([from_str, from_none], obj.get("format"))
        name = from_union([from_str, from_none], obj.get("name"))
        version = from_union([from_str, from_none], obj.get("version"))
        return Tool(format, name, version)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.format is not None:
            result["format"] = from_union([from_str, from_none], self.format)
        if self.name is not None:
            result["name"] = from_union([from_str, from_none], self.name)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


@dataclass
class HdfResults:
    """The top level value containing all assessment results."""

    baselines: List[EvaluatedBaseline]
    """Information on the baselines that were evaluated, including findings."""

    components: Optional[List[Component]] = None
    """The components that were assessed. Each component describes a system element (host,
    container, cloud resource, application, etc.) with optional identity, SBOM, and external
    references.
    """
    extensions: Optional[Dict[str, Any]] = None
    """Reserved for tool-specific data not defined in the HDF standard. Use this to preserve
    original tool output, auxiliary data, or custom metadata.
    """
    generator: Optional[Generator] = None
    """Information about the tool that generated this file."""

    id: Optional[UUID] = None
    """Unique identifier for this assessment run."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this file."""

    plan_ref: Optional[str] = None
    """Reference to an hdf-plan document describing the assessment plan that produced these
    results. May be a relative path, absolute URI, or fragment identifier.
    """
    remediation: Optional[Remediation] = None
    """Optional reference to automated remediation resources (Ansible playbooks, Terraform
    scripts, etc.) for fixing failing requirements found in this assessment.
    """
    runner: Optional[Runner] = None
    """Information about the test execution environment where the security tool was run.
    Distinct from targets (what is being tested).
    """
    statistics: Optional[Statistics] = None
    """Statistics for the assessment run, including duration and result counts."""

    system_ref: Optional[str] = None
    """Reference to an hdf-system document describing the system under assessment. May be a
    relative path, absolute URI, or fragment identifier.
    """
    timestamp: Optional[datetime] = None
    """When this assessment was executed."""

    tool: Optional[Tool] = None
    """The security tool that produced the assessment data in this file."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfResults':
        assert isinstance(obj, dict)
        baselines = from_list(EvaluatedBaseline.from_dict, obj.get("baselines"))
        components = from_union([lambda x: from_list(Component.from_dict, x), from_none], obj.get("components"))
        extensions = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("extensions"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        id = from_union([lambda x: UUID(x), from_none], obj.get("id"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        plan_ref = from_union([from_str, from_none], obj.get("planRef"))
        remediation = from_union([Remediation.from_dict, from_none], obj.get("remediation"))
        runner = from_union([Runner.from_dict, from_none], obj.get("runner"))
        statistics = from_union([Statistics.from_dict, from_none], obj.get("statistics"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        timestamp = from_union([from_datetime, from_none], obj.get("timestamp"))
        tool = from_union([Tool.from_dict, from_none], obj.get("tool"))
        return HdfResults(baselines, components, extensions, generator, id, integrity, plan_ref, remediation, runner, statistics, system_ref, timestamp, tool)

    def to_dict(self) -> dict:
        result: dict = {}
        result["baselines"] = from_list(lambda x: to_class(EvaluatedBaseline, x), self.baselines)
        if self.components is not None:
            result["components"] = from_union([lambda x: from_list(lambda x: to_class(Component, x), x), from_none], self.components)
        if self.extensions is not None:
            result["extensions"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.extensions)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.id is not None:
            result["id"] = from_union([lambda x: str(x), from_none], self.id)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.plan_ref is not None:
            result["planRef"] = from_union([from_str, from_none], self.plan_ref)
        if self.remediation is not None:
            result["remediation"] = from_union([lambda x: to_class(Remediation, x), from_none], self.remediation)
        if self.runner is not None:
            result["runner"] = from_union([lambda x: to_class(Runner, x), from_none], self.runner)
        if self.statistics is not None:
            result["statistics"] = from_union([lambda x: to_class(Statistics, x), from_none], self.statistics)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        if self.timestamp is not None:
            result["timestamp"] = from_union([lambda x: x.isoformat(), from_none], self.timestamp)
        if self.tool is not None:
            result["tool"] = from_union([lambda x: to_class(Tool, x), from_none], self.tool)
        return result


def hdf_results_from_dict(s: Any) -> HdfResults:
    return HdfResults.from_dict(s)


def hdf_results_to_dict(x: HdfResults) -> Any:
    return to_class(HdfResults, x)
