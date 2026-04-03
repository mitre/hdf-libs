from dataclasses import dataclass
from typing import Optional, Any, Dict, List, TypeVar, Type, cast, Callable
from enum import Enum
from uuid import UUID
from datetime import datetime
import dateutil.parser


T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
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


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def to_float(x: Any) -> float:
    assert isinstance(x, (int, float))
    return x


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


@dataclass
class SBOMCoverage:
    """SBOM coverage across system components.
    
    SBOM coverage statistics for the system.
    """
    components_with_sbom: Optional[int] = None
    """Number of system components that have an associated SBOM."""

    total_components: Optional[int] = None
    """Total number of components in the system."""

    @staticmethod
    def from_dict(obj: Any) -> 'SBOMCoverage':
        assert isinstance(obj, dict)
        components_with_sbom = from_union([from_int, from_none], obj.get("componentsWithSbom"))
        total_components = from_union([from_int, from_none], obj.get("totalComponents"))
        return SBOMCoverage(components_with_sbom, total_components)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.components_with_sbom is not None:
            result["componentsWithSbom"] = from_union([from_int, from_none], self.components_with_sbom)
        if self.total_components is not None:
            result["totalComponents"] = from_union([from_int, from_none], self.total_components)
        return result


@dataclass
class CompletenessCheck:
    """Summary of assessment completeness and compliance status.
    
    Informational summary of assessment completeness. Not authoritative — tools should
    compute these from the referenced documents.
    """
    all_baselines_assessed: Optional[bool] = None
    """Whether all baselines referenced by system components have assessment results."""

    all_components_covered: Optional[bool] = None
    """Whether all system components have at least one matching target in the results."""

    compliance_percent: Optional[float] = None
    """Overall compliance percentage across all assessments."""

    expired_waivers: Optional[int] = None
    """Number of waivers/amendments that have expired."""

    sbom_coverage: Optional[SBOMCoverage] = None
    """SBOM coverage across system components."""

    unresolved_poams: Optional[int] = None
    """Number of POA&M items that are still open (not completed)."""

    @staticmethod
    def from_dict(obj: Any) -> 'CompletenessCheck':
        assert isinstance(obj, dict)
        all_baselines_assessed = from_union([from_bool, from_none], obj.get("allBaselinesAssessed"))
        all_components_covered = from_union([from_bool, from_none], obj.get("allComponentsCovered"))
        compliance_percent = from_union([from_float, from_none], obj.get("compliancePercent"))
        expired_waivers = from_union([from_int, from_none], obj.get("expiredWaivers"))
        sbom_coverage = from_union([SBOMCoverage.from_dict, from_none], obj.get("sbomCoverage"))
        unresolved_poams = from_union([from_int, from_none], obj.get("unresolvedPoams"))
        return CompletenessCheck(all_baselines_assessed, all_components_covered, compliance_percent, expired_waivers, sbom_coverage, unresolved_poams)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.all_baselines_assessed is not None:
            result["allBaselinesAssessed"] = from_union([from_bool, from_none], self.all_baselines_assessed)
        if self.all_components_covered is not None:
            result["allComponentsCovered"] = from_union([from_bool, from_none], self.all_components_covered)
        if self.compliance_percent is not None:
            result["compliancePercent"] = from_union([to_float, from_none], self.compliance_percent)
        if self.expired_waivers is not None:
            result["expiredWaivers"] = from_union([from_int, from_none], self.expired_waivers)
        if self.sbom_coverage is not None:
            result["sbomCoverage"] = from_union([lambda x: to_class(SBOMCoverage, x), from_none], self.sbom_coverage)
        if self.unresolved_poams is not None:
            result["unresolvedPoams"] = from_union([from_int, from_none], self.unresolved_poams)
        return result


class HashAlgorithm(Enum):
    """The hash algorithm used for the checksum.
    
    Supported cryptographic hash algorithms for checksums and integrity verification.
    """
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


@dataclass
class Checksum:
    """Cryptographic checksum for verifying the referenced document's integrity.
    
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


class ContentType(Enum):
    """The type of HDF document being referenced.
    
    The type of document referenced in the evidence package.
    """
    HDF_AMENDMENTS = "hdf-amendments"
    HDF_BASELINE = "hdf-baseline"
    HDF_COMPARISON = "hdf-comparison"
    HDF_PLAN = "hdf-plan"
    HDF_RESULTS = "hdf-results"
    HDF_SYSTEM = "hdf-system"
    SBOM = "sbom"


@dataclass
class ContentReference:
    """A reference to an HDF document or SBOM included in the evidence package."""

    type: ContentType
    """The type of HDF document being referenced."""

    uri: str
    """URI to the document. Can be a relative path or absolute URL."""

    checksum: Optional[Checksum] = None
    """Cryptographic checksum for verifying the referenced document's integrity."""

    component_ref: Optional[UUID] = None
    """componentId of the component this content entry relates to. Use to link SBOMs, results,
    or other documents to a specific system component.
    """
    description: Optional[str] = None
    """Optional description of this content entry."""

    @staticmethod
    def from_dict(obj: Any) -> 'ContentReference':
        assert isinstance(obj, dict)
        type = ContentType(obj.get("type"))
        uri = from_str(obj.get("uri"))
        checksum = from_union([Checksum.from_dict, from_none], obj.get("checksum"))
        component_ref = from_union([lambda x: UUID(x), from_none], obj.get("componentRef"))
        description = from_union([from_str, from_none], obj.get("description"))
        return ContentReference(type, uri, checksum, component_ref, description)

    def to_dict(self) -> dict:
        result: dict = {}
        result["type"] = to_enum(ContentType, self.type)
        result["uri"] = from_str(self.uri)
        if self.checksum is not None:
            result["checksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.checksum)
        if self.component_ref is not None:
            result["componentRef"] = from_union([lambda x: str(x), from_none], self.component_ref)
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


@dataclass
class Integrity:
    """Cryptographic integrity information for verifying this evidence package has not been
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
    """Identity of who prepared this evidence package.
    
    Represents an identity that performed an action, such as capturing evidence or applying
    an override.
    
    The identity that created this signature.
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
    """Digital signature covering the entire evidence package.
    
    A digital signature following W3C Data Integrity Proofs pattern. Supports hardware
    security tokens (PKCS#11/PKCS#12), Yubikeys, GPG keys, passkeys, and other cryptographic
    signing methods via JWK, PEM, or Base58 key formats.
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


@dataclass
class HdfEvidencePackage:
    """Bundles references to all HDF documents for audit, authorization, and compliance review.
    Each content entry references a document by type, URI, and checksum for integrity
    verification.
    """
    contents: List[ContentReference]
    """References to HDF documents included in this evidence package."""

    name: str
    """Human-readable name for this evidence package. Example: 'Enterprise Portal ATO Evidence -
    Q1 2026'.
    """
    completeness_check: Optional[CompletenessCheck] = None
    """Summary of assessment completeness and compliance status."""

    description: Optional[str] = None
    """Description of the evidence package's purpose and scope."""

    generator: Optional[Generator] = None
    """Information about the tool that generated this document."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this evidence package has not been
    tampered with.
    """
    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for grouping and querying evidence packages."""

    package_id: Optional[UUID] = None
    """Unique identifier for this evidence package. Optional in casual use, expected in
    production ATO submissions. Auto-generated if omitted during creation.
    """
    plan_ref: Optional[str] = None
    """URI to the hdf-plan document that drove this assessment. Used for completeness
    verification — every baseline in the plan should have a corresponding results document in
    this package.
    """
    prepared_at: Optional[datetime] = None
    """When this evidence package was prepared. ISO 8601 format."""

    prepared_by: Optional[Identity] = None
    """Identity of who prepared this evidence package."""

    signature: Optional[Signature] = None
    """Digital signature covering the entire evidence package."""

    system_ref: Optional[str] = None
    """URI to the hdf-system document this evidence package covers."""

    version: Optional[str] = None
    """Version of this evidence package."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfEvidencePackage':
        assert isinstance(obj, dict)
        contents = from_list(ContentReference.from_dict, obj.get("contents"))
        name = from_str(obj.get("name"))
        completeness_check = from_union([CompletenessCheck.from_dict, from_none], obj.get("completenessCheck"))
        description = from_union([from_str, from_none], obj.get("description"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        package_id = from_union([lambda x: UUID(x), from_none], obj.get("packageId"))
        plan_ref = from_union([from_str, from_none], obj.get("planRef"))
        prepared_at = from_union([from_datetime, from_none], obj.get("preparedAt"))
        prepared_by = from_union([Identity.from_dict, from_none], obj.get("preparedBy"))
        signature = from_union([Signature.from_dict, from_none], obj.get("signature"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        version = from_union([from_str, from_none], obj.get("version"))
        return HdfEvidencePackage(contents, name, completeness_check, description, generator, integrity, labels, package_id, plan_ref, prepared_at, prepared_by, signature, system_ref, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["contents"] = from_list(lambda x: to_class(ContentReference, x), self.contents)
        result["name"] = from_str(self.name)
        if self.completeness_check is not None:
            result["completenessCheck"] = from_union([lambda x: to_class(CompletenessCheck, x), from_none], self.completeness_check)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.package_id is not None:
            result["packageId"] = from_union([lambda x: str(x), from_none], self.package_id)
        if self.plan_ref is not None:
            result["planRef"] = from_union([from_str, from_none], self.plan_ref)
        if self.prepared_at is not None:
            result["preparedAt"] = from_union([lambda x: x.isoformat(), from_none], self.prepared_at)
        if self.prepared_by is not None:
            result["preparedBy"] = from_union([lambda x: to_class(Identity, x), from_none], self.prepared_by)
        if self.signature is not None:
            result["signature"] = from_union([lambda x: to_class(Signature, x), from_none], self.signature)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


def hdf_evidence_package_from_dict(s: Any) -> HdfEvidencePackage:
    return HdfEvidencePackage.from_dict(s)


def hdf_evidence_package_to_dict(x: HdfEvidencePackage) -> Any:
    return to_class(HdfEvidencePackage, x)
