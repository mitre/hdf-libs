from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, Dict, List, TypeVar, Type, cast, Callable
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


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def to_float(x: Any) -> float:
    assert isinstance(x, (int, float))
    return x


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


class AppliedByType(Enum):
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
    """Default identity of who created this amendments document. Individual overrides may
    specify their own appliedBy.
    
    Represents an identity that performed an action, such as capturing evidence or applying
    an override.
    
    Identity of the authorizing official who approved these amendments.
    
    Identity of who applied this amendment.
    
    Identity of who or what captured this evidence.
    
    Identity of who completed this milestone.
    
    The identity that created this signature.
    """
    identifier: str
    """The identifier value. Example: 'user@example.com', 'jdoe', 'automated-scanner-01'."""

    type: AppliedByType
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
        type = AppliedByType(obj.get("type"))
        description = from_union([from_str, from_none], obj.get("description"))
        return Identity(identifier, type, description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["identifier"] = from_str(self.identifier)
        result["type"] = to_enum(AppliedByType, self.type)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        return result


@dataclass
class Generator:
    """Information about the tool that generated this document.
    
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
    """Cryptographic integrity information for verifying this amendments document has not been
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
class Checksum:
    """Checksum of the prior amendment in the chain. Creates a tamper-evident linked list. Null
    for the first amendment.
    
    Cryptographic checksum for baseline integrity verification.
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
    """Digital signature for non-repudiation.
    
    A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
    security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
    signing methods via JWK, PEM, or Base58 key formats.
    
    Document-level digital signature covering all amendments.
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


class ResultStatus(Enum):
    """The new status this amendment sets. For POA&Ms, this is the current status (POA&Ms track
    work, they don't change status).
    
    The status of an individual test result. 'notApplicable' indicates the requirement does
    not apply to the target. 'notReviewed' indicates the requirement was not assessed (e.g.,
    requires manual verification).
    """
    ERROR = "error"
    FAILED = "failed"
    NOT_APPLICABLE = "notApplicable"
    NOT_REVIEWED = "notReviewed"
    PASSED = "passed"


class OverrideType(Enum):
    """The type of amendment.
    
    The type of amendment. 'waiver': risk accepted (AO). 'attestation': manually verified
    (assessor). 'exception': not applicable (system owner + AO). 'poam': remediation tracked
    (no status change). 'inherited': control provided by another component or system
    (overrides to notApplicable/passed).
    """
    ATTESTATION = "attestation"
    EXCEPTION = "exception"
    INHERITED = "inherited"
    POAM = "poam"
    WAIVER = "waiver"


@dataclass
class StandaloneOverride:
    """A standalone amendment that modifies a requirement's compliance status. Extends the
    inline Status_Override concept with requirementId and baselineRef for use outside of
    results documents.
    """
    applied_at: datetime
    """When this amendment was applied. ISO 8601 format."""

    applied_by: Identity
    """Identity of who applied this amendment."""

    expires_at: datetime
    """When this amendment expires and must be reviewed. No permanent amendments. ISO 8601
    format.
    """
    reason: str
    """Justification for this amendment."""

    requirement_id: str
    """The ID of the requirement being amended. Must match a requirement ID in the referenced
    baseline.
    """
    status: ResultStatus
    """The new status this amendment sets. For POA&Ms, this is the current status (POA&Ms track
    work, they don't change status).
    """
    type: OverrideType
    """The type of amendment."""

    baseline_ref: Optional[str] = None
    """Name of the baseline containing the requirement. Required when the system has multiple
    baselines with potentially overlapping requirement IDs.
    """
    component_ref: Optional[UUID] = None
    """componentId of the component this amendment is scoped to. When set, the amendment only
    applies to the specified component. When omitted, the amendment applies system-wide.
    """
    evidence: Optional[List[Evidence]] = None
    """Supporting evidence (screenshots, logs, URLs, documents)."""

    inherited_from: Optional[UUID] = None
    """componentId of the local component that provides this control. Set when the provider is
    in the same system. Omit for external or cross-system providers; the reason field
    explains the source. Primarily used with type 'inherited'.
    """
    milestones: Optional[List[Milestone]] = None
    """Remediation milestones (primarily for POA&M type amendments)."""

    previous_checksum: Optional[Checksum] = None
    """Checksum of the prior amendment in the chain. Creates a tamper-evident linked list. Null
    for the first amendment.
    """
    signature: Optional[Signature] = None
    """Digital signature for non-repudiation."""

    @staticmethod
    def from_dict(obj: Any) -> 'StandaloneOverride':
        assert isinstance(obj, dict)
        applied_at = from_datetime(obj.get("appliedAt"))
        applied_by = Identity.from_dict(obj.get("appliedBy"))
        expires_at = from_datetime(obj.get("expiresAt"))
        reason = from_str(obj.get("reason"))
        requirement_id = from_str(obj.get("requirementId"))
        status = ResultStatus(obj.get("status"))
        type = OverrideType(obj.get("type"))
        baseline_ref = from_union([from_str, from_none], obj.get("baselineRef"))
        component_ref = from_union([lambda x: UUID(x), from_none], obj.get("componentRef"))
        evidence = from_union([lambda x: from_list(Evidence.from_dict, x), from_none], obj.get("evidence"))
        inherited_from = from_union([lambda x: UUID(x), from_none], obj.get("inheritedFrom"))
        milestones = from_union([lambda x: from_list(Milestone.from_dict, x), from_none], obj.get("milestones"))
        previous_checksum = from_union([Checksum.from_dict, from_none], obj.get("previousChecksum"))
        signature = from_union([Signature.from_dict, from_none], obj.get("signature"))
        return StandaloneOverride(applied_at, applied_by, expires_at, reason, requirement_id, status, type, baseline_ref, component_ref, evidence, inherited_from, milestones, previous_checksum, signature)

    def to_dict(self) -> dict:
        result: dict = {}
        result["appliedAt"] = self.applied_at.isoformat()
        result["appliedBy"] = to_class(Identity, self.applied_by)
        result["expiresAt"] = self.expires_at.isoformat()
        result["reason"] = from_str(self.reason)
        result["requirementId"] = from_str(self.requirement_id)
        result["status"] = to_enum(ResultStatus, self.status)
        result["type"] = to_enum(OverrideType, self.type)
        if self.baseline_ref is not None:
            result["baselineRef"] = from_union([from_str, from_none], self.baseline_ref)
        if self.component_ref is not None:
            result["componentRef"] = from_union([lambda x: str(x), from_none], self.component_ref)
        if self.evidence is not None:
            result["evidence"] = from_union([lambda x: from_list(lambda x: to_class(Evidence, x), x), from_none], self.evidence)
        if self.inherited_from is not None:
            result["inheritedFrom"] = from_union([lambda x: str(x), from_none], self.inherited_from)
        if self.milestones is not None:
            result["milestones"] = from_union([lambda x: from_list(lambda x: to_class(Milestone, x), x), from_none], self.milestones)
        if self.previous_checksum is not None:
            result["previousChecksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.previous_checksum)
        if self.signature is not None:
            result["signature"] = from_union([lambda x: to_class(Signature, x), from_none], self.signature)
        return result


@dataclass
class HdfAmendments:
    """Waivers, attestations, exceptions, and POA&Ms that modify requirement compliance status.
    Amendments are standalone documents that can be applied to results via merge operations.
    """
    name: str
    """Human-readable name for this amendments document. Example: 'Portal Q1 2026 Waivers'."""

    overrides: List[StandaloneOverride]
    """The set of amendments (waivers, attestations, exceptions, POA&Ms)."""

    amendment_id: Optional[UUID] = None
    """Unique identifier for this amendments document. Useful for cross-referencing when
    multiple amendment documents target the same results.
    """
    applied_by: Optional[Identity] = None
    """Default identity of who created this amendments document. Individual overrides may
    specify their own appliedBy.
    """
    approved_by: Optional[Identity] = None
    """Identity of the authorizing official who approved these amendments."""

    description: Optional[str] = None
    """Description of the amendments' purpose and scope."""

    generator: Optional[Generator] = None
    """Information about the tool that generated this document."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this amendments document has not been
    tampered with.
    """
    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for grouping and querying amendments."""

    signature: Optional[Signature] = None
    """Document-level digital signature covering all amendments."""

    system_ref: Optional[str] = None
    """URI to the hdf-system document these amendments apply to."""

    version: Optional[str] = None
    """Version of this amendments document."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfAmendments':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        overrides = from_list(StandaloneOverride.from_dict, obj.get("overrides"))
        amendment_id = from_union([lambda x: UUID(x), from_none], obj.get("amendmentId"))
        applied_by = from_union([Identity.from_dict, from_none], obj.get("appliedBy"))
        approved_by = from_union([Identity.from_dict, from_none], obj.get("approvedBy"))
        description = from_union([from_str, from_none], obj.get("description"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        signature = from_union([Signature.from_dict, from_none], obj.get("signature"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        version = from_union([from_str, from_none], obj.get("version"))
        return HdfAmendments(name, overrides, amendment_id, applied_by, approved_by, description, generator, integrity, labels, signature, system_ref, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["overrides"] = from_list(lambda x: to_class(StandaloneOverride, x), self.overrides)
        if self.amendment_id is not None:
            result["amendmentId"] = from_union([lambda x: str(x), from_none], self.amendment_id)
        if self.applied_by is not None:
            result["appliedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.applied_by)
        if self.approved_by is not None:
            result["approvedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.approved_by)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.signature is not None:
            result["signature"] = from_union([lambda x: to_class(Signature, x), from_none], self.signature)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


def hdf_amendments_from_dict(s: Any) -> HdfAmendments:
    return HdfAmendments.from_dict(s)


def hdf_amendments_to_dict(x: HdfAmendments) -> Any:
    return to_class(HdfAmendments, x)
