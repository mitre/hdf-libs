from dataclasses import dataclass
from typing import Optional, Any, Dict, List, TypeVar, Callable, Type, cast
from uuid import UUID
from enum import Enum
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


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


@dataclass
class RunnerConfig:
    """Runner/scanner configuration for this assessment.
    
    Configuration for the assessment runner/scanner.
    """
    name: Optional[str] = None
    """Name of the assessment runner. Example: 'cinc-auditor', 'inspec', 'openscap'."""

    version: Optional[str] = None
    """Version of the runner."""

    @staticmethod
    def from_dict(obj: Any) -> 'RunnerConfig':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        version = from_union([from_str, from_none], obj.get("version"))
        return RunnerConfig(name, version)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.name is not None:
            result["name"] = from_union([from_str, from_none], self.name)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


@dataclass
class Assessment:
    """A single assessment within a plan — defines which baseline to run against which targets
    with what configuration.
    """
    baseline_ref: str
    """Reference to the baseline to evaluate. May be a baseline name (e.g. 'RHEL9-STIG'), a
    relative path to an HDF Baseline document (e.g. 'rhel9-stig.hdf-baseline.json'), or an
    absolute URI.
    """
    component_ref: Optional[UUID] = None
    """componentId of the system component this assessment targets. Use for direct component
    binding. Alternative to targetSelector.
    """
    description: Optional[str] = None
    """Description of this assessment's purpose."""

    inputs: Optional[Dict[str, Any]] = None
    """Resolved input values for this assessment. Keys are input names, values are the final
    resolved values (after baseline defaults + system overrides).
    """
    runner: Optional[RunnerConfig] = None
    """Runner/scanner configuration for this assessment."""

    target_selector: Optional[Dict[str, str]] = None
    """Label selector to match targets for this assessment. Overrides the system component's
    targetSelector if provided.
    """

    @staticmethod
    def from_dict(obj: Any) -> 'Assessment':
        assert isinstance(obj, dict)
        baseline_ref = from_str(obj.get("baselineRef"))
        component_ref = from_union([lambda x: UUID(x), from_none], obj.get("componentRef"))
        description = from_union([from_str, from_none], obj.get("description"))
        inputs = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("inputs"))
        runner = from_union([RunnerConfig.from_dict, from_none], obj.get("runner"))
        target_selector = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("targetSelector"))
        return Assessment(baseline_ref, component_ref, description, inputs, runner, target_selector)

    def to_dict(self) -> dict:
        result: dict = {}
        result["baselineRef"] = from_str(self.baseline_ref)
        if self.component_ref is not None:
            result["componentRef"] = from_union([lambda x: str(x), from_none], self.component_ref)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.inputs is not None:
            result["inputs"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.inputs)
        if self.runner is not None:
            result["runner"] = from_union([lambda x: to_class(RunnerConfig, x), from_none], self.runner)
        if self.target_selector is not None:
            result["targetSelector"] = from_union([lambda x: from_dict(from_str, x), from_none], self.target_selector)
        return result


@dataclass
class Generator:
    """Information about the tool that generated this plan.
    
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
    """Cryptographic integrity information for verifying this plan document has not been
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
class Schedule:
    """Optional scheduling configuration for recurring assessments.
    
    Scheduling configuration for recurring assessments.
    """
    cron: Optional[str] = None
    """Cron expression for recurring assessments. Example: '0 2 1 * *' (2 AM on the 1st of each
    month).
    """
    end_date: Optional[datetime] = None
    """Date after which assessments should no longer run. ISO 8601 format."""

    notify_on_completion: Optional[List[str]] = None
    """Email addresses or notification endpoints to alert when assessments complete."""

    notify_on_regression: Optional[List[str]] = None
    """Email addresses or notification endpoints to alert when regressions are detected."""

    start_date: Optional[datetime] = None
    """Earliest date to begin assessments. ISO 8601 format."""

    @staticmethod
    def from_dict(obj: Any) -> 'Schedule':
        assert isinstance(obj, dict)
        cron = from_union([from_str, from_none], obj.get("cron"))
        end_date = from_union([from_datetime, from_none], obj.get("endDate"))
        notify_on_completion = from_union([lambda x: from_list(from_str, x), from_none], obj.get("notifyOnCompletion"))
        notify_on_regression = from_union([lambda x: from_list(from_str, x), from_none], obj.get("notifyOnRegression"))
        start_date = from_union([from_datetime, from_none], obj.get("startDate"))
        return Schedule(cron, end_date, notify_on_completion, notify_on_regression, start_date)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.cron is not None:
            result["cron"] = from_union([from_str, from_none], self.cron)
        if self.end_date is not None:
            result["endDate"] = from_union([lambda x: x.isoformat(), from_none], self.end_date)
        if self.notify_on_completion is not None:
            result["notifyOnCompletion"] = from_union([lambda x: from_list(from_str, x), from_none], self.notify_on_completion)
        if self.notify_on_regression is not None:
            result["notifyOnRegression"] = from_union([lambda x: from_list(from_str, x), from_none], self.notify_on_regression)
        if self.start_date is not None:
            result["startDate"] = from_union([lambda x: x.isoformat(), from_none], self.start_date)
        return result


class PlanType(Enum):
    """The type of assessment plan.
    
    The type of assessment. 'automated' for scanner-driven, 'manual' for human-performed,
    'hybrid' for both.
    """
    AUTOMATED = "automated"
    HYBRID = "hybrid"
    MANUAL = "manual"


@dataclass
class HdfPlan:
    """Defines an assessment plan — what baselines to run against which targets, with resolved
    inputs and scheduling. Maps to OSCAL Assessment Plan.
    """
    assessments: List[Assessment]
    """The assessments to perform. Each assessment pairs a baseline with targets and resolved
    inputs.
    """
    name: str
    """Human-readable plan name. Example: 'Portal Monthly Assessment'."""

    description: Optional[str] = None
    """Description of the plan's purpose and scope."""

    generator: Optional[Generator] = None
    """Information about the tool that generated this plan."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this plan document has not been
    tampered with.
    """
    labels: Optional[Dict[str, str]] = None
    """Optional key-value labels for grouping and querying plans."""

    plan_id: Optional[UUID] = None
    """Unique identifier for this plan. Optional in casual use, expected in production
    documents. Auto-generated if omitted during creation.
    """
    schedule: Optional[Schedule] = None
    """Optional scheduling configuration for recurring assessments."""

    system_ref: Optional[str] = None
    """URI to the hdf-system document this plan targets. Example: 'portal-prod.hdf-system.json'."""

    type: Optional[PlanType] = None
    """The type of assessment plan."""

    version: Optional[str] = None
    """Version of this plan document."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfPlan':
        assert isinstance(obj, dict)
        assessments = from_list(Assessment.from_dict, obj.get("assessments"))
        name = from_str(obj.get("name"))
        description = from_union([from_str, from_none], obj.get("description"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        labels = from_union([lambda x: from_dict(from_str, x), from_none], obj.get("labels"))
        plan_id = from_union([lambda x: UUID(x), from_none], obj.get("planId"))
        schedule = from_union([Schedule.from_dict, from_none], obj.get("schedule"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        type = from_union([PlanType, from_none], obj.get("type"))
        version = from_union([from_str, from_none], obj.get("version"))
        return HdfPlan(assessments, name, description, generator, integrity, labels, plan_id, schedule, system_ref, type, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["assessments"] = from_list(lambda x: to_class(Assessment, x), self.assessments)
        result["name"] = from_str(self.name)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.labels is not None:
            result["labels"] = from_union([lambda x: from_dict(from_str, x), from_none], self.labels)
        if self.plan_id is not None:
            result["planId"] = from_union([lambda x: str(x), from_none], self.plan_id)
        if self.schedule is not None:
            result["schedule"] = from_union([lambda x: to_class(Schedule, x), from_none], self.schedule)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        if self.type is not None:
            result["type"] = from_union([lambda x: to_enum(PlanType, x), from_none], self.type)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


def hdf_plan_from_dict(s: Any) -> HdfPlan:
    return HdfPlan.from_dict(s)


def hdf_plan_to_dict(x: HdfPlan) -> Any:
    return to_class(HdfPlan, x)
