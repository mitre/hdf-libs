from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, List, Dict, TypeVar, Type, Callable, cast
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


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_dict(f: Callable[[Any], T], x: Any) -> Dict[str, T]:
    assert isinstance(x, dict)
    return { k: f(v) for (k, v) in x.items() }


def from_float(x: Any) -> float:
    assert isinstance(x, (float, int)) and not isinstance(x, bool)
    return float(x)


def to_float(x: Any) -> float:
    assert isinstance(x, (int, float))
    return x


def from_datetime(x: Any) -> datetime:
    return dateutil.parser.parse(x)


class AnnotationCategory(Enum):
    """The category of this annotation.
    
    The category of an annotation attached to a comparison.
    """
    BASELINE_CHANGE = "baselineChange"
    DRIFT = "drift"
    REMEDIATION = "remediation"
    SCANNER_NOTE = "scannerNote"
    WAIVER = "waiver"


@dataclass
class Annotation:
    """An annotation attached to a comparison, providing context or action items."""

    label: str
    """Human-readable label for this annotation."""

    category: Optional[AnnotationCategory] = None
    """The category of this annotation."""

    description: Optional[str] = None
    """Detailed description of the annotation."""

    needs_confirmation: Optional[bool] = None
    """Whether this annotation requires human confirmation before acting on it."""

    @staticmethod
    def from_dict(obj: Any) -> 'Annotation':
        assert isinstance(obj, dict)
        label = from_str(obj.get("label"))
        category = from_union([AnnotationCategory, from_none], obj.get("category"))
        description = from_union([from_str, from_none], obj.get("description"))
        needs_confirmation = from_union([from_bool, from_none], obj.get("needsConfirmation"))
        return Annotation(label, category, description, needs_confirmation)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_str(self.label)
        if self.category is not None:
            result["category"] = from_union([lambda x: to_enum(AnnotationCategory, x), from_none], self.category)
        if self.description is not None:
            result["description"] = from_union([from_str, from_none], self.description)
        if self.needs_confirmation is not None:
            result["needsConfirmation"] = from_union([from_bool, from_none], self.needs_confirmation)
        return result


class BaselineDiffState(Enum):
    """The state of this baseline in the comparison.
    
    The state of this component in the comparison.
    """
    ABSENT = "absent"
    NEW = "new"
    UNCHANGED = "unchanged"
    UPDATED = "updated"


@dataclass
class BaselineDiff:
    """Comparison of a baseline between sources."""

    name: str
    """Name of the baseline being compared."""

    state: BaselineDiffState
    """The state of this baseline in the comparison."""

    mapping_source: Optional[str] = None
    """The source of any ID mapping used to correlate requirements across baseline versions."""

    new_version: Optional[str] = None
    """Version of the baseline in the new source."""

    old_version: Optional[str] = None
    """Version of the baseline in the old source."""

    @staticmethod
    def from_dict(obj: Any) -> 'BaselineDiff':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        state = BaselineDiffState(obj.get("state"))
        mapping_source = from_union([from_str, from_none], obj.get("mappingSource"))
        new_version = from_union([from_str, from_none], obj.get("newVersion"))
        old_version = from_union([from_str, from_none], obj.get("oldVersion"))
        return BaselineDiff(name, state, mapping_source, new_version, old_version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["state"] = to_enum(BaselineDiffState, self.state)
        if self.mapping_source is not None:
            result["mappingSource"] = from_union([from_str, from_none], self.mapping_source)
        if self.new_version is not None:
            result["newVersion"] = from_union([from_str, from_none], self.new_version)
        if self.old_version is not None:
            result["oldVersion"] = from_union([from_str, from_none], self.old_version)
        return result


class ComparisonMode(Enum):
    """The mode of comparison being performed.
    
    The mode of comparison. 'temporal' compares the same target over time. 'baseline'
    compares against a golden reference. 'fleet' compares across multiple systems.
    'multiSource' compares outputs from different scanners. 'baselineEvolution' compares two
    baseline documents to detect requirement changes between versions. 'systemDrift' compares
    two system documents to detect component-level changes.
    """
    BASELINE = "baseline"
    BASELINE_EVOLUTION = "baselineEvolution"
    FLEET = "fleet"
    MULTI_SOURCE = "multiSource"
    SYSTEM_DRIFT = "systemDrift"
    TEMPORAL = "temporal"


class Op(Enum):
    """The type of change operation."""

    ADD = "add"
    REMOVE = "remove"
    REPLACE = "replace"


@dataclass
class FieldChange:
    """A single field-level change between two versions of a requirement."""

    op: Op
    """The type of change operation."""

    path: str
    """JSON Pointer path to the changed field."""

    new_value: Any
    """The new value of the field (for 'add' and 'replace' operations)."""

    old_value: Any
    """The previous value of the field (for 'remove' and 'replace' operations)."""

    @staticmethod
    def from_dict(obj: Any) -> 'FieldChange':
        assert isinstance(obj, dict)
        op = Op(obj.get("op"))
        path = from_str(obj.get("path"))
        new_value = obj.get("newValue")
        old_value = obj.get("oldValue")
        return FieldChange(op, path, new_value, old_value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["op"] = to_enum(Op, self.op)
        result["path"] = from_str(self.path)
        if self.new_value is not None:
            result["newValue"] = self.new_value
        if self.old_value is not None:
            result["oldValue"] = self.old_value
        return result


@dataclass
class ComponentDiff:
    """Comparison of a single component between two system document versions."""

    name: str
    """Component name used for matching across system versions."""

    state: BaselineDiffState
    """The state of this component in the comparison."""

    after: Any
    """Component snapshot from the new system document."""

    before: Any
    """Component snapshot from the old system document."""

    field_changes: Optional[List[FieldChange]] = None
    """Detailed field-level changes between the before and after component snapshots."""

    @staticmethod
    def from_dict(obj: Any) -> 'ComponentDiff':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        state = BaselineDiffState(obj.get("state"))
        after = obj.get("after")
        before = obj.get("before")
        field_changes = from_union([lambda x: from_list(FieldChange.from_dict, x), from_none], obj.get("fieldChanges"))
        return ComponentDiff(name, state, after, before, field_changes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        result["state"] = to_enum(BaselineDiffState, self.state)
        if self.after is not None:
            result["after"] = self.after
        if self.before is not None:
            result["before"] = self.before
        if self.field_changes is not None:
            result["fieldChanges"] = from_union([lambda x: from_list(lambda x: to_class(FieldChange, x), x), from_none], self.field_changes)
        return result


class ChangeReason(Enum):
    """The reason a requirement's state changed between sources."""

    BASELINE_UPGRADED = "baselineUpgraded"
    CONFIG_CHANGED = "configChanged"
    CONTROL_MAPPED = "controlMapped"
    IMPACT_CHANGED = "impactChanged"
    METADATA_CHANGED = "metadataChanged"
    OVERRIDE_ADDED = "overrideAdded"
    OVERRIDE_EXPIRED = "overrideExpired"
    OVERRIDE_MODIFIED = "overrideModified"
    OVERRIDE_REMOVED = "overrideRemoved"
    RESULT_CHANGED = "resultChanged"
    SCANNER_CHANGED = "scannerChanged"
    TARGET_CHANGED = "targetChanged"


class ConflictResolution(Enum):
    """How the conflict was resolved.
    
    How a conflict between multiple scanner results was resolved.
    """
    MANUAL = "manual"
    MOST_RECENT = "mostRecent"
    MOST_SEVERE = "mostSevere"
    UNRESOLVED = "unresolved"


@dataclass
class Value:
    source_index: int
    """Zero-based index into the sources array."""

    source_label: str
    """Human-readable label for the source."""

    value: Any
    """The value reported by this source for the conflicting field."""

    @staticmethod
    def from_dict(obj: Any) -> 'Value':
        assert isinstance(obj, dict)
        source_index = from_int(obj.get("sourceIndex"))
        source_label = from_str(obj.get("sourceLabel"))
        value = obj.get("value")
        return Value(source_index, source_label, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["sourceIndex"] = from_int(self.source_index)
        result["sourceLabel"] = from_str(self.source_label)
        result["value"] = self.value
        return result


@dataclass
class ScannerConflict:
    """A conflict between scanner results for the same requirement."""

    field: str
    """The field where the conflict occurs."""

    values: List[Value]
    """The conflicting values from each source."""

    resolution: Optional[ConflictResolution] = None
    """How the conflict was resolved."""

    resolved_index: Optional[int] = None
    """Index of the source whose value was chosen as the resolution."""

    @staticmethod
    def from_dict(obj: Any) -> 'ScannerConflict':
        assert isinstance(obj, dict)
        field = from_str(obj.get("field"))
        values = from_list(Value.from_dict, obj.get("values"))
        resolution = from_union([ConflictResolution, from_none], obj.get("resolution"))
        resolved_index = from_union([from_int, from_none], obj.get("resolvedIndex"))
        return ScannerConflict(field, values, resolution, resolved_index)

    def to_dict(self) -> dict:
        result: dict = {}
        result["field"] = from_str(self.field)
        result["values"] = from_list(lambda x: to_class(Value, x), self.values)
        if self.resolution is not None:
            result["resolution"] = from_union([lambda x: to_enum(ConflictResolution, x), from_none], self.resolution)
        if self.resolved_index is not None:
            result["resolvedIndex"] = from_union([from_int, from_none], self.resolved_index)
        return result


class MatchStrategy(Enum):
    """The strategy that was used to match this requirement across sources.
    
    The strategy used to match requirements across sources. 'exactId' matches by identical
    IDs. 'mappedId' uses an ID mapping table. 'cciMatch'/'nistMatch' match by framework
    identifiers. 'fuzzyTitle'/'fuzzyContent' use text similarity.
    
    The primary strategy used to match requirements across sources.
    """
    CCI_MATCH = "cciMatch"
    EXACT_ID = "exactId"
    FUZZY_CONTENT = "fuzzyContent"
    FUZZY_TITLE = "fuzzyTitle"
    MAPPED_ID = "mappedId"
    NIST_MATCH = "nistMatch"


class RequirementState(Enum):
    """The state of this requirement in the comparison.
    
    SARIF-compatible vocabulary extended for security. 'new' = present only in new source,
    'absent' = present only in old, 'unchanged' = same effective status, 'updated' = status
    changed (generic), 'fixed' = was failing now passing, 'regressed' = was passing now
    failing, 'moved' = reorganized same content, 'split'/'merged' = reserved for v1.1.
    """
    ABSENT = "absent"
    FIXED = "fixed"
    MERGED = "merged"
    MOVED = "moved"
    NEW = "new"
    REGRESSED = "regressed"
    SPLIT = "split"
    UNCHANGED = "unchanged"
    UPDATED = "updated"


@dataclass
class RequirementDiff:
    """A comparison of a single requirement between sources, including state, changes, and full
    before/after snapshots.
    """
    after: Any
    """The requirement as it appeared in the new source. Null when state is 'absent'."""

    before: Any
    """The requirement as it appeared in the old/reference source. Null when state is 'new'."""

    change_reasons: List[ChangeReason]
    """The reasons for the state change."""

    field_changes: List[FieldChange]
    """Detailed field-level changes between the before and after versions."""

    id: str
    """The canonical requirement identifier used for this diff."""

    state: RequirementState
    """The state of this requirement in the comparison."""

    after_sensitive: Optional[Dict[str, Any]] = None
    """Sensitive data from the new source that should not be included in the main after snapshot."""

    annotation_ids: Optional[List[str]] = None
    """IDs of annotations attached to this requirement diff."""

    before_sensitive: Optional[Dict[str, Any]] = None
    """Sensitive data from the old source that should not be included in the main before
    snapshot.
    """
    conflicts: Optional[List[ScannerConflict]] = None
    """Conflicts between multiple scanner results for this requirement."""

    match_confidence: Optional[float] = None
    """Confidence score for the match (0-1)."""

    match_manual: Optional[bool] = None
    """Whether the match was manually confirmed by a human."""

    match_strategy: Optional[MatchStrategy] = None
    """The strategy that was used to match this requirement across sources."""

    new_effective_status: Optional[str] = None
    """The effective status of the requirement in the new source."""

    new_id: Optional[str] = None
    """The requirement ID in the new source, if different from the canonical id."""

    new_impact: Optional[float] = None
    """The impact score of the requirement in the new source (0-1)."""

    old_effective_status: Optional[str] = None
    """The effective status of the requirement in the old source."""

    old_id: Optional[str] = None
    """The requirement ID in the old source, if different from the canonical id."""

    old_impact: Optional[float] = None
    """The impact score of the requirement in the old source (0-1)."""

    source_index: Optional[int] = None
    """Index into the sources array for multi-source comparisons."""

    title: Optional[str] = None
    """The requirement title for human readability."""

    @staticmethod
    def from_dict(obj: Any) -> 'RequirementDiff':
        assert isinstance(obj, dict)
        after = obj.get("after")
        before = obj.get("before")
        change_reasons = from_list(ChangeReason, obj.get("changeReasons"))
        field_changes = from_list(FieldChange.from_dict, obj.get("fieldChanges"))
        id = from_str(obj.get("id"))
        state = RequirementState(obj.get("state"))
        after_sensitive = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("afterSensitive"))
        annotation_ids = from_union([lambda x: from_list(from_str, x), from_none], obj.get("annotationIds"))
        before_sensitive = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("beforeSensitive"))
        conflicts = from_union([lambda x: from_list(ScannerConflict.from_dict, x), from_none], obj.get("conflicts"))
        match_confidence = from_union([from_float, from_none], obj.get("matchConfidence"))
        match_manual = from_union([from_bool, from_none], obj.get("matchManual"))
        match_strategy = from_union([MatchStrategy, from_none], obj.get("matchStrategy"))
        new_effective_status = from_union([from_str, from_none], obj.get("newEffectiveStatus"))
        new_id = from_union([from_str, from_none], obj.get("newId"))
        new_impact = from_union([from_float, from_none], obj.get("newImpact"))
        old_effective_status = from_union([from_str, from_none], obj.get("oldEffectiveStatus"))
        old_id = from_union([from_str, from_none], obj.get("oldId"))
        old_impact = from_union([from_float, from_none], obj.get("oldImpact"))
        source_index = from_union([from_int, from_none], obj.get("sourceIndex"))
        title = from_union([from_str, from_none], obj.get("title"))
        return RequirementDiff(after, before, change_reasons, field_changes, id, state, after_sensitive, annotation_ids, before_sensitive, conflicts, match_confidence, match_manual, match_strategy, new_effective_status, new_id, new_impact, old_effective_status, old_id, old_impact, source_index, title)

    def to_dict(self) -> dict:
        result: dict = {}
        result["after"] = self.after
        result["before"] = self.before
        result["changeReasons"] = from_list(lambda x: to_enum(ChangeReason, x), self.change_reasons)
        result["fieldChanges"] = from_list(lambda x: to_class(FieldChange, x), self.field_changes)
        result["id"] = from_str(self.id)
        result["state"] = to_enum(RequirementState, self.state)
        if self.after_sensitive is not None:
            result["afterSensitive"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.after_sensitive)
        if self.annotation_ids is not None:
            result["annotationIds"] = from_union([lambda x: from_list(from_str, x), from_none], self.annotation_ids)
        if self.before_sensitive is not None:
            result["beforeSensitive"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.before_sensitive)
        if self.conflicts is not None:
            result["conflicts"] = from_union([lambda x: from_list(lambda x: to_class(ScannerConflict, x), x), from_none], self.conflicts)
        if self.match_confidence is not None:
            result["matchConfidence"] = from_union([to_float, from_none], self.match_confidence)
        if self.match_manual is not None:
            result["matchManual"] = from_union([from_bool, from_none], self.match_manual)
        if self.match_strategy is not None:
            result["matchStrategy"] = from_union([lambda x: to_enum(MatchStrategy, x), from_none], self.match_strategy)
        if self.new_effective_status is not None:
            result["newEffectiveStatus"] = from_union([from_str, from_none], self.new_effective_status)
        if self.new_id is not None:
            result["newId"] = from_union([from_str, from_none], self.new_id)
        if self.new_impact is not None:
            result["newImpact"] = from_union([to_float, from_none], self.new_impact)
        if self.old_effective_status is not None:
            result["oldEffectiveStatus"] = from_union([from_str, from_none], self.old_effective_status)
        if self.old_id is not None:
            result["oldId"] = from_union([from_str, from_none], self.old_id)
        if self.old_impact is not None:
            result["oldImpact"] = from_union([to_float, from_none], self.old_impact)
        if self.source_index is not None:
            result["sourceIndex"] = from_union([from_int, from_none], self.source_index)
        if self.title is not None:
            result["title"] = from_union([from_str, from_none], self.title)
        return result


class FormatVersion(Enum):
    THE_100 = "1.0.0"


@dataclass
class Generator:
    """Information about the tool that generated this comparison.
    
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
    """Cryptographic integrity information for verifying this comparison document.
    
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
class MatchingConfig:
    """Configuration for how requirements were matched across sources.
    
    Configuration for how requirements are matched across sources.
    """
    primary_strategy: MatchStrategy
    """The primary strategy used to match requirements across sources."""

    fallback_strategies: Optional[List[MatchStrategy]] = None
    """Ordered list of fallback strategies tried when the primary strategy fails to find a match."""

    fingerprint_fields: Optional[List[str]] = None
    """Fields used to compute a fingerprint for fuzzy matching."""

    mapping_table_uri: Optional[str] = None
    """URI pointing to an external mapping table used for ID translation."""

    minimum_confidence: Optional[float] = None
    """Minimum confidence score (0-1) required to accept a match."""

    @staticmethod
    def from_dict(obj: Any) -> 'MatchingConfig':
        assert isinstance(obj, dict)
        primary_strategy = MatchStrategy(obj.get("primaryStrategy"))
        fallback_strategies = from_union([lambda x: from_list(MatchStrategy, x), from_none], obj.get("fallbackStrategies"))
        fingerprint_fields = from_union([lambda x: from_list(from_str, x), from_none], obj.get("fingerprintFields"))
        mapping_table_uri = from_union([from_str, from_none], obj.get("mappingTableUri"))
        minimum_confidence = from_union([from_float, from_none], obj.get("minimumConfidence"))
        return MatchingConfig(primary_strategy, fallback_strategies, fingerprint_fields, mapping_table_uri, minimum_confidence)

    def to_dict(self) -> dict:
        result: dict = {}
        result["primaryStrategy"] = to_enum(MatchStrategy, self.primary_strategy)
        if self.fallback_strategies is not None:
            result["fallbackStrategies"] = from_union([lambda x: from_list(lambda x: to_enum(MatchStrategy, x), x), from_none], self.fallback_strategies)
        if self.fingerprint_fields is not None:
            result["fingerprintFields"] = from_union([lambda x: from_list(from_str, x), from_none], self.fingerprint_fields)
        if self.mapping_table_uri is not None:
            result["mappingTableUri"] = from_union([from_str, from_none], self.mapping_table_uri)
        if self.minimum_confidence is not None:
            result["minimumConfidence"] = from_union([to_float, from_none], self.minimum_confidence)
        return result


class PackageDiffState(Enum):
    """The state of this package: added (new in new SBOM), removed (absent from new SBOM),
    updated (version changed), unchanged.
    """
    ADDED = "added"
    REMOVED = "removed"
    UNCHANGED = "unchanged"
    UPDATED = "updated"


@dataclass
class PackageDiff:
    """Comparison of a single package between two SBOM versions, matched by purl."""

    purl: str
    """Package URL (purl) used as the identity key for matching across SBOMs."""

    state: PackageDiffState
    """The state of this package: added (new in new SBOM), removed (absent from new SBOM),
    updated (version changed), unchanged.
    """
    licenses: Optional[List[str]] = None
    """License identifiers for this package."""

    name: Optional[str] = None
    """Human-readable package name."""

    new_version: Optional[str] = None
    """Package version in the new SBOM."""

    old_version: Optional[str] = None
    """Package version in the old SBOM."""

    @staticmethod
    def from_dict(obj: Any) -> 'PackageDiff':
        assert isinstance(obj, dict)
        purl = from_str(obj.get("purl"))
        state = PackageDiffState(obj.get("state"))
        licenses = from_union([lambda x: from_list(from_str, x), from_none], obj.get("licenses"))
        name = from_union([from_str, from_none], obj.get("name"))
        new_version = from_union([from_str, from_none], obj.get("newVersion"))
        old_version = from_union([from_str, from_none], obj.get("oldVersion"))
        return PackageDiff(purl, state, licenses, name, new_version, old_version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["purl"] = from_str(self.purl)
        result["state"] = to_enum(PackageDiffState, self.state)
        if self.licenses is not None:
            result["licenses"] = from_union([lambda x: from_list(from_str, x), from_none], self.licenses)
        if self.name is not None:
            result["name"] = from_union([from_str, from_none], self.name)
        if self.new_version is not None:
            result["newVersion"] = from_union([from_str, from_none], self.new_version)
        if self.old_version is not None:
            result["oldVersion"] = from_union([from_str, from_none], self.old_version)
        return result


@dataclass
class BaselineRef:
    """Reference to the baseline used in this source assessment."""

    name: str
    """Name of the baseline used in this source."""

    version: Optional[str] = None
    """Version of the baseline used in this source."""

    @staticmethod
    def from_dict(obj: Any) -> 'BaselineRef':
        assert isinstance(obj, dict)
        name = from_str(obj.get("name"))
        version = from_union([from_str, from_none], obj.get("version"))
        return BaselineRef(name, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_str(self.name)
        if self.version is not None:
            result["version"] = from_union([from_str, from_none], self.version)
        return result


@dataclass
class Checksum:
    """Cryptographic checksum of the source document for integrity verification.
    
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


class Description(Enum):
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

    type: Description
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
        type = Description(obj.get("type"))
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
        result["type"] = to_enum(Description, self.type)
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


class OriginalFormat(Enum):
    """The original format of the source document before conversion to HDF."""

    HDF_V2 = "hdf-v2"
    INSPEC_V1 = "inspec-v1"
    OSCAL_AR = "oscal-ar"
    SARIF = "sarif"
    XCCDF = "xccdf"


class SourceRole(Enum):
    """The role of this source in the comparison.
    
    The role of a source document in the comparison.
    """
    GOLDEN = "golden"
    NEW = "new"
    OLD = "old"
    REFERENCE = "reference"
    SYSTEM = "system"


@dataclass
class Tool:
    """The security tool that produced the assessment data in this source.
    
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
class Source:
    """A source document participating in the comparison."""

    label: str
    """Human-readable label for this source. Example: 'Before remediation scan'."""

    role: SourceRole
    """The role of this source in the comparison."""

    assessment_timestamp: Optional[datetime] = None
    """When the source assessment was performed. ISO 8601 format."""

    baseline_ref: Optional[BaselineRef] = None
    """Reference to the baseline used in this source assessment."""

    checksum: Optional[Checksum] = None
    """Cryptographic checksum of the source document for integrity verification."""

    components: Optional[List[Component]] = None
    """The components assessed in this source."""

    original_format: Optional[OriginalFormat] = None
    """The original format of the source document before conversion to HDF."""

    tool: Optional[Tool] = None
    """The security tool that produced the assessment data in this source."""

    uri: Optional[str] = None
    """URI pointing to the source document."""

    @staticmethod
    def from_dict(obj: Any) -> 'Source':
        assert isinstance(obj, dict)
        label = from_str(obj.get("label"))
        role = SourceRole(obj.get("role"))
        assessment_timestamp = from_union([from_datetime, from_none], obj.get("assessmentTimestamp"))
        baseline_ref = from_union([BaselineRef.from_dict, from_none], obj.get("baselineRef"))
        checksum = from_union([Checksum.from_dict, from_none], obj.get("checksum"))
        components = from_union([lambda x: from_list(Component.from_dict, x), from_none], obj.get("components"))
        original_format = from_union([OriginalFormat, from_none], obj.get("originalFormat"))
        tool = from_union([Tool.from_dict, from_none], obj.get("tool"))
        uri = from_union([from_str, from_none], obj.get("uri"))
        return Source(label, role, assessment_timestamp, baseline_ref, checksum, components, original_format, tool, uri)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_str(self.label)
        result["role"] = to_enum(SourceRole, self.role)
        if self.assessment_timestamp is not None:
            result["assessmentTimestamp"] = from_union([lambda x: x.isoformat(), from_none], self.assessment_timestamp)
        if self.baseline_ref is not None:
            result["baselineRef"] = from_union([lambda x: to_class(BaselineRef, x), from_none], self.baseline_ref)
        if self.checksum is not None:
            result["checksum"] = from_union([lambda x: to_class(Checksum, x), from_none], self.checksum)
        if self.components is not None:
            result["components"] = from_union([lambda x: from_list(lambda x: to_class(Component, x), x), from_none], self.components)
        if self.original_format is not None:
            result["originalFormat"] = from_union([lambda x: to_enum(OriginalFormat, x), from_none], self.original_format)
        if self.tool is not None:
            result["tool"] = from_union([lambda x: to_class(Tool, x), from_none], self.tool)
        if self.uri is not None:
            result["uri"] = from_union([from_str, from_none], self.uri)
        return result


@dataclass
class StateCounts:
    """State counts for critical severity requirements.
    
    Counts of requirements in each state.
    
    State counts for high severity requirements.
    
    State counts for low severity requirements.
    
    State counts for medium severity requirements.
    """
    absent: Optional[int] = None
    """Number of requirements present only in the old source."""

    fixed: Optional[int] = None
    """Number of requirements that changed from failing to passing."""

    moved: Optional[int] = None
    """Number of requirements that were reorganized without content change."""

    new: Optional[int] = None
    """Number of requirements present only in the new source."""

    regressed: Optional[int] = None
    """Number of requirements that changed from passing to failing."""

    unchanged: Optional[int] = None
    """Number of requirements with the same effective status."""

    updated: Optional[int] = None
    """Number of requirements with a generic status change."""

    @staticmethod
    def from_dict(obj: Any) -> 'StateCounts':
        assert isinstance(obj, dict)
        absent = from_union([from_int, from_none], obj.get("absent"))
        fixed = from_union([from_int, from_none], obj.get("fixed"))
        moved = from_union([from_int, from_none], obj.get("moved"))
        new = from_union([from_int, from_none], obj.get("new"))
        regressed = from_union([from_int, from_none], obj.get("regressed"))
        unchanged = from_union([from_int, from_none], obj.get("unchanged"))
        updated = from_union([from_int, from_none], obj.get("updated"))
        return StateCounts(absent, fixed, moved, new, regressed, unchanged, updated)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.absent is not None:
            result["absent"] = from_union([from_int, from_none], self.absent)
        if self.fixed is not None:
            result["fixed"] = from_union([from_int, from_none], self.fixed)
        if self.moved is not None:
            result["moved"] = from_union([from_int, from_none], self.moved)
        if self.new is not None:
            result["new"] = from_union([from_int, from_none], self.new)
        if self.regressed is not None:
            result["regressed"] = from_union([from_int, from_none], self.regressed)
        if self.unchanged is not None:
            result["unchanged"] = from_union([from_int, from_none], self.unchanged)
        if self.updated is not None:
            result["updated"] = from_union([from_int, from_none], self.updated)
        return result


@dataclass
class SeverityBreakdown:
    """State counts broken down by severity level.
    
    Breakdown of state counts by severity level.
    """
    critical: Optional[StateCounts] = None
    """State counts for critical severity requirements."""

    high: Optional[StateCounts] = None
    """State counts for high severity requirements."""

    low: Optional[StateCounts] = None
    """State counts for low severity requirements."""

    medium: Optional[StateCounts] = None
    """State counts for medium severity requirements."""

    @staticmethod
    def from_dict(obj: Any) -> 'SeverityBreakdown':
        assert isinstance(obj, dict)
        critical = from_union([StateCounts.from_dict, from_none], obj.get("critical"))
        high = from_union([StateCounts.from_dict, from_none], obj.get("high"))
        low = from_union([StateCounts.from_dict, from_none], obj.get("low"))
        medium = from_union([StateCounts.from_dict, from_none], obj.get("medium"))
        return SeverityBreakdown(critical, high, low, medium)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.critical is not None:
            result["critical"] = from_union([lambda x: to_class(StateCounts, x), from_none], self.critical)
        if self.high is not None:
            result["high"] = from_union([lambda x: to_class(StateCounts, x), from_none], self.high)
        if self.low is not None:
            result["low"] = from_union([lambda x: to_class(StateCounts, x), from_none], self.low)
        if self.medium is not None:
            result["medium"] = from_union([lambda x: to_class(StateCounts, x), from_none], self.medium)
        return result


@dataclass
class PerSourceSummary:
    """Summary statistics for a single source in a multi-source comparison."""

    label: str
    """Human-readable label for this source."""

    source_index: int
    """Zero-based index into the sources array identifying which source this summary is for."""

    absent: Optional[int] = None
    """Number of requirements present only in the old source."""

    fixed: Optional[int] = None
    """Number of requirements that changed from failing to passing."""

    moved: Optional[int] = None
    """Number of requirements that were reorganized without content change."""

    new: Optional[int] = None
    """Number of requirements present only in the new source."""

    regressed: Optional[int] = None
    """Number of requirements that changed from passing to failing."""

    unchanged: Optional[int] = None
    """Number of requirements with the same effective status."""

    updated: Optional[int] = None
    """Number of requirements with a generic status change."""

    @staticmethod
    def from_dict(obj: Any) -> 'PerSourceSummary':
        assert isinstance(obj, dict)
        label = from_str(obj.get("label"))
        source_index = from_int(obj.get("sourceIndex"))
        absent = from_union([from_int, from_none], obj.get("absent"))
        fixed = from_union([from_int, from_none], obj.get("fixed"))
        moved = from_union([from_int, from_none], obj.get("moved"))
        new = from_union([from_int, from_none], obj.get("new"))
        regressed = from_union([from_int, from_none], obj.get("regressed"))
        unchanged = from_union([from_int, from_none], obj.get("unchanged"))
        updated = from_union([from_int, from_none], obj.get("updated"))
        return PerSourceSummary(label, source_index, absent, fixed, moved, new, regressed, unchanged, updated)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_str(self.label)
        result["sourceIndex"] = from_int(self.source_index)
        if self.absent is not None:
            result["absent"] = from_union([from_int, from_none], self.absent)
        if self.fixed is not None:
            result["fixed"] = from_union([from_int, from_none], self.fixed)
        if self.moved is not None:
            result["moved"] = from_union([from_int, from_none], self.moved)
        if self.new is not None:
            result["new"] = from_union([from_int, from_none], self.new)
        if self.regressed is not None:
            result["regressed"] = from_union([from_int, from_none], self.regressed)
        if self.unchanged is not None:
            result["unchanged"] = from_union([from_int, from_none], self.unchanged)
        if self.updated is not None:
            result["updated"] = from_union([from_int, from_none], self.updated)
        return result


@dataclass
class ComparisonSummary:
    """Summary statistics for the overall comparison."""

    matched_count: int
    """Number of requirements successfully matched between sources."""

    total: int
    """Total number of unique requirements across all sources."""

    unmatched_new_count: int
    """Number of requirements in the new source with no match in the old source."""

    unmatched_old_count: int
    """Number of requirements in the old source with no match in the new source."""

    absent: Optional[int] = None
    """Number of requirements present only in the old source."""

    average_match_confidence: Optional[float] = None
    """Average confidence score across all requirement matches (0-1)."""

    by_severity: Optional[SeverityBreakdown] = None
    """State counts broken down by severity level."""

    compliance_delta: Optional[float] = None
    """Change in compliance percentage (new - old)."""

    fixed: Optional[int] = None
    """Number of requirements that changed from failing to passing."""

    moved: Optional[int] = None
    """Number of requirements that were reorganized without content change."""

    new: Optional[int] = None
    """Number of requirements present only in the new source."""

    new_compliance_percent: Optional[float] = None
    """Compliance percentage of the new source (0-100)."""

    old_compliance_percent: Optional[float] = None
    """Compliance percentage of the old source (0-100)."""

    per_source: Optional[List[PerSourceSummary]] = None
    """Summary statistics for each individual source in a multi-source comparison."""

    regressed: Optional[int] = None
    """Number of requirements that changed from passing to failing."""

    unchanged: Optional[int] = None
    """Number of requirements with the same effective status."""

    updated: Optional[int] = None
    """Number of requirements with a generic status change."""

    @staticmethod
    def from_dict(obj: Any) -> 'ComparisonSummary':
        assert isinstance(obj, dict)
        matched_count = from_int(obj.get("matchedCount"))
        total = from_int(obj.get("total"))
        unmatched_new_count = from_int(obj.get("unmatchedNewCount"))
        unmatched_old_count = from_int(obj.get("unmatchedOldCount"))
        absent = from_union([from_int, from_none], obj.get("absent"))
        average_match_confidence = from_union([from_float, from_none], obj.get("averageMatchConfidence"))
        by_severity = from_union([SeverityBreakdown.from_dict, from_none], obj.get("bySeverity"))
        compliance_delta = from_union([from_float, from_none], obj.get("complianceDelta"))
        fixed = from_union([from_int, from_none], obj.get("fixed"))
        moved = from_union([from_int, from_none], obj.get("moved"))
        new = from_union([from_int, from_none], obj.get("new"))
        new_compliance_percent = from_union([from_float, from_none], obj.get("newCompliancePercent"))
        old_compliance_percent = from_union([from_float, from_none], obj.get("oldCompliancePercent"))
        per_source = from_union([lambda x: from_list(PerSourceSummary.from_dict, x), from_none], obj.get("perSource"))
        regressed = from_union([from_int, from_none], obj.get("regressed"))
        unchanged = from_union([from_int, from_none], obj.get("unchanged"))
        updated = from_union([from_int, from_none], obj.get("updated"))
        return ComparisonSummary(matched_count, total, unmatched_new_count, unmatched_old_count, absent, average_match_confidence, by_severity, compliance_delta, fixed, moved, new, new_compliance_percent, old_compliance_percent, per_source, regressed, unchanged, updated)

    def to_dict(self) -> dict:
        result: dict = {}
        result["matchedCount"] = from_int(self.matched_count)
        result["total"] = from_int(self.total)
        result["unmatchedNewCount"] = from_int(self.unmatched_new_count)
        result["unmatchedOldCount"] = from_int(self.unmatched_old_count)
        if self.absent is not None:
            result["absent"] = from_union([from_int, from_none], self.absent)
        if self.average_match_confidence is not None:
            result["averageMatchConfidence"] = from_union([to_float, from_none], self.average_match_confidence)
        if self.by_severity is not None:
            result["bySeverity"] = from_union([lambda x: to_class(SeverityBreakdown, x), from_none], self.by_severity)
        if self.compliance_delta is not None:
            result["complianceDelta"] = from_union([to_float, from_none], self.compliance_delta)
        if self.fixed is not None:
            result["fixed"] = from_union([from_int, from_none], self.fixed)
        if self.moved is not None:
            result["moved"] = from_union([from_int, from_none], self.moved)
        if self.new is not None:
            result["new"] = from_union([from_int, from_none], self.new)
        if self.new_compliance_percent is not None:
            result["newCompliancePercent"] = from_union([to_float, from_none], self.new_compliance_percent)
        if self.old_compliance_percent is not None:
            result["oldCompliancePercent"] = from_union([to_float, from_none], self.old_compliance_percent)
        if self.per_source is not None:
            result["perSource"] = from_union([lambda x: from_list(lambda x: to_class(PerSourceSummary, x), x), from_none], self.per_source)
        if self.regressed is not None:
            result["regressed"] = from_union([from_int, from_none], self.regressed)
        if self.unchanged is not None:
            result["unchanged"] = from_union([from_int, from_none], self.unchanged)
        if self.updated is not None:
            result["updated"] = from_union([from_int, from_none], self.updated)
        return result


@dataclass
class HdfComparison:
    """Structured comparison between two or more HDF security assessment documents. Supports
    temporal, baseline, fleet, and multi-source comparison modes.
    """
    comparison_mode: ComparisonMode
    """The mode of comparison being performed."""

    format_version: FormatVersion
    """Schema version for this comparison format."""

    requirement_diffs: List[RequirementDiff]
    """Detailed comparison of individual requirements between sources."""

    sources: List[Source]
    """The source documents being compared. At least two sources are required."""

    summary: ComparisonSummary
    """Summary statistics for the overall comparison."""

    annotations: Optional[Dict[str, Annotation]] = None
    """Map of annotation IDs to annotation objects, providing context or action items for
    requirement diffs.
    """
    baseline_diffs: Optional[List[BaselineDiff]] = None
    """Comparison of baselines between sources."""

    component_diffs: Optional[List[ComponentDiff]] = None
    """Comparison of components between two system documents. Used in systemDrift mode."""

    drift: Optional[List[RequirementDiff]] = None
    """External/metadata changes separate from status changes (Terraform pattern)."""

    extensions: Optional[Dict[str, Any]] = None
    """Reserved for tool-specific data not defined in the HDF standard."""

    generator: Optional[Generator] = None
    """Information about the tool that generated this comparison."""

    integrity: Optional[Integrity] = None
    """Cryptographic integrity information for verifying this comparison document."""

    matching: Optional[MatchingConfig] = None
    """Configuration for how requirements were matched across sources."""

    package_diffs: Optional[List[PackageDiff]] = None
    """Comparison of packages between two SBOMs. Used in systemDrift mode for SBOM comparison."""

    system_ref: Optional[str] = None
    """URI identifying the system being compared in systemDrift mode."""

    timestamp: Optional[datetime] = None
    """When this comparison was performed."""

    @staticmethod
    def from_dict(obj: Any) -> 'HdfComparison':
        assert isinstance(obj, dict)
        comparison_mode = ComparisonMode(obj.get("comparisonMode"))
        format_version = FormatVersion(obj.get("formatVersion"))
        requirement_diffs = from_list(RequirementDiff.from_dict, obj.get("requirementDiffs"))
        sources = from_list(Source.from_dict, obj.get("sources"))
        summary = ComparisonSummary.from_dict(obj.get("summary"))
        annotations = from_union([lambda x: from_dict(Annotation.from_dict, x), from_none], obj.get("annotations"))
        baseline_diffs = from_union([lambda x: from_list(BaselineDiff.from_dict, x), from_none], obj.get("baselineDiffs"))
        component_diffs = from_union([lambda x: from_list(ComponentDiff.from_dict, x), from_none], obj.get("componentDiffs"))
        drift = from_union([lambda x: from_list(RequirementDiff.from_dict, x), from_none], obj.get("drift"))
        extensions = from_union([lambda x: from_dict(lambda x: x, x), from_none], obj.get("extensions"))
        generator = from_union([Generator.from_dict, from_none], obj.get("generator"))
        integrity = from_union([Integrity.from_dict, from_none], obj.get("integrity"))
        matching = from_union([MatchingConfig.from_dict, from_none], obj.get("matching"))
        package_diffs = from_union([lambda x: from_list(PackageDiff.from_dict, x), from_none], obj.get("packageDiffs"))
        system_ref = from_union([from_str, from_none], obj.get("systemRef"))
        timestamp = from_union([from_datetime, from_none], obj.get("timestamp"))
        return HdfComparison(comparison_mode, format_version, requirement_diffs, sources, summary, annotations, baseline_diffs, component_diffs, drift, extensions, generator, integrity, matching, package_diffs, system_ref, timestamp)

    def to_dict(self) -> dict:
        result: dict = {}
        result["comparisonMode"] = to_enum(ComparisonMode, self.comparison_mode)
        result["formatVersion"] = to_enum(FormatVersion, self.format_version)
        result["requirementDiffs"] = from_list(lambda x: to_class(RequirementDiff, x), self.requirement_diffs)
        result["sources"] = from_list(lambda x: to_class(Source, x), self.sources)
        result["summary"] = to_class(ComparisonSummary, self.summary)
        if self.annotations is not None:
            result["annotations"] = from_union([lambda x: from_dict(lambda x: to_class(Annotation, x), x), from_none], self.annotations)
        if self.baseline_diffs is not None:
            result["baselineDiffs"] = from_union([lambda x: from_list(lambda x: to_class(BaselineDiff, x), x), from_none], self.baseline_diffs)
        if self.component_diffs is not None:
            result["componentDiffs"] = from_union([lambda x: from_list(lambda x: to_class(ComponentDiff, x), x), from_none], self.component_diffs)
        if self.drift is not None:
            result["drift"] = from_union([lambda x: from_list(lambda x: to_class(RequirementDiff, x), x), from_none], self.drift)
        if self.extensions is not None:
            result["extensions"] = from_union([lambda x: from_dict(lambda x: x, x), from_none], self.extensions)
        if self.generator is not None:
            result["generator"] = from_union([lambda x: to_class(Generator, x), from_none], self.generator)
        if self.integrity is not None:
            result["integrity"] = from_union([lambda x: to_class(Integrity, x), from_none], self.integrity)
        if self.matching is not None:
            result["matching"] = from_union([lambda x: to_class(MatchingConfig, x), from_none], self.matching)
        if self.package_diffs is not None:
            result["packageDiffs"] = from_union([lambda x: from_list(lambda x: to_class(PackageDiff, x), x), from_none], self.package_diffs)
        if self.system_ref is not None:
            result["systemRef"] = from_union([from_str, from_none], self.system_ref)
        if self.timestamp is not None:
            result["timestamp"] = from_union([lambda x: x.isoformat(), from_none], self.timestamp)
        return result


def hdf_comparison_from_dict(s: Any) -> HdfComparison:
    return HdfComparison.from_dict(s)


def hdf_comparison_to_dict(x: HdfComparison) -> Any:
    return to_class(HdfComparison, x)
