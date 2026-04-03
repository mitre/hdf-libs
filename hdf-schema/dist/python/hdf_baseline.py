from dataclasses import dataclass
from typing import Optional, Any, List, Dict, Union, TypeVar, Callable, Type, cast
from enum import Enum


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


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


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
class Generator:
    """The tool that generated this file.
    
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
    """Optional cryptographic checksum for verifying the integrity of remediation resources
    fetched from the URI. Recommended for security when referencing external automation
    scripts.
    
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
class Remediation:
    """Optional reference to automated remediation resources (Ansible playbooks, Terraform
    scripts, etc.) for implementing the security controls defined in this baseline.
    
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
class BaselineRequirement:
    """A requirement definition without assessment results.
    
    Core requirement fields shared between baseline requirements and evaluated requirements.
    Contains the fundamental requirement definition without assessment results.
    """
    descriptions: List[Description]
    """Array of labeled descriptions. At least one description with label 'default' must be
    present. Convention: place default description first. Common labels: 'default', 'check',
    'fix', 'rationale'.
    """
    id: str
    """The requirement identifier. Example: 'SV-238196'."""

    impact: float
    """The impactfulness or severity (0.0 to 1.0)."""

    tags: Dict[str, Any]
    """A set of tags - usually metadata like CCI, STIG ID, severity."""

    severity: Optional[Severity] = None
    """Explicit severity rating. Typically derived from impact score but provided explicitly for
    clarity.
    """
    code: Optional[str] = None
    """The raw source code of the requirement. Set to null for manual-only requirements or
    requirements not yet implemented. Note that if this is an overlay, it does not include
    the underlying source code.
    """
    refs: Optional[List[Reference]] = None
    """The set of references to external documents."""

    source_location: Optional[SourceLocation] = None
    """The explicit location of the requirement within the source code."""

    title: Optional[str] = None
    """The title - is nullable."""

    @staticmethod
    def from_dict(obj: Any) -> 'BaselineRequirement':
        assert isinstance(obj, dict)
        descriptions = from_list(Description.from_dict, obj.get("descriptions"))
        id = from_str(obj.get("id"))
        impact = from_float(obj.get("impact"))
        tags = from_dict(lambda x: x, obj.get("tags"))
        severity = from_union([Severity, from_none], obj.get("severity"))
        code = from_union([from_str, from_none], obj.get("code"))
        refs = from_union([lambda x: from_list(Reference.from_dict, x), from_none], obj.get("refs"))
        source_location = from_union([SourceLocation.from_dict, from_none], obj.get("sourceLocation"))
        title = from_union([from_str, from_none], obj.get("title"))
        return BaselineRequirement(descriptions, id, impact, tags, severity, code, refs, source_location, title)

    def to_dict(self) -> dict:
        result: dict = {}
        result["descriptions"] = from_list(lambda x: to_class(Description, x), self.descriptions)
        result["id"] = from_str(self.id)
        result["impact"] = to_float(self.impact)
        result["tags"] = from_dict(lambda x: x, self.tags)
        if self.severity is not None:
            result["severity"] = from_union([lambda x: to_enum(Severity, x), from_none], self.severity)
        if self.code is not None:
            result["code"] = from_union([from_str, from_none], self.code)
        if self.refs is not None:
            result["refs"] = from_union([lambda x: from_list(lambda x: to_class(Reference, x), x), from_none], self.refs)
        if self.source_location is not None:
            result["sourceLocation"] = from_union([lambda x: to_class(SourceLocation, x), from_none], self.source_location)
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
class HdfBaseline:
    """Information on the set of requirements that can be assessed, including baseline metadata
    and requirement definitions.
    
    Shared metadata fields for baselines. Used in both standalone baseline documents and
    evaluated baseline results.
    """
    requirements: List[BaselineRequirement]
    """The set of requirements - contains no findings as the assessment has not yet occurred."""

    name: str
    """The name - must be unique."""

    depends: Optional[List[Dependency]] = None
    """The set of dependencies this baseline depends on."""

    generator: Optional[Generator] = None
    """The tool that generated this file."""

    groups: Optional[List[RequirementGroup]] = None
    """A set of descriptions for the requirement groups."""

    inputs: Optional[List[Input]] = None
    """The input(s) or attribute(s) to be used in the run."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this baseline has not been tampered
    with.
    """
    remediation: Optional[Remediation] = None
    """Optional reference to automated remediation resources (Ansible playbooks, Terraform
    scripts, etc.) for implementing the security controls defined in this baseline.
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
    def from_dict(obj: Any) -> 'HdfBaseline':
        assert isinstance(obj, dict)
        requirements = from_list(BaselineRequirement.from_dict, obj.get("requirements"))
        name = from_str(obj.get("name"))
        depends = from_union([lambda x: from_list(Dependency.from_dict, x), from_none], obj.get("depends"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        groups = from_union([lambda x: from_list(RequirementGroup.from_dict, x), from_none], obj.get("groups"))
        inputs = from_union([lambda x: from_list(Input.from_dict, x), from_none], obj.get("inputs"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        remediation = from_union([Remediation.from_dict, from_none], obj.get("remediation"))
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
        return HdfBaseline(requirements, name, depends, generator, groups, inputs, integrity, remediation, copyright, copyright_email, labels, license, maintainer, status, summary, supports, title, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["requirements"] = from_list(lambda x: to_class(BaselineRequirement, x), self.requirements)
        result["name"] = from_str(self.name)
        if self.depends is not None:
            result["depends"] = from_union([lambda x: from_list(lambda x: to_class(Dependency, x), x), from_none], self.depends)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.groups is not None:
            result["groups"] = from_union([lambda x: from_list(lambda x: to_class(RequirementGroup, x), x), from_none], self.groups)
        if self.inputs is not None:
            result["inputs"] = from_union([lambda x: from_list(lambda x: to_class(Input, x), x), from_none], self.inputs)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.remediation is not None:
            result["remediation"] = from_union([lambda x: to_class(Remediation, x), from_none], self.remediation)
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


def hdf_baseline_from_dict(s: Any) -> HdfBaseline:
    return HdfBaseline.from_dict(s)


def hdf_baseline_to_dict(x: HdfBaseline) -> Any:
    return to_class(HdfBaseline, x)
