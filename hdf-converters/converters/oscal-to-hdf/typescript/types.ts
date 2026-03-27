// Generated from OSCAL complete schema v1.2.1 (oscal_complete_schema.json) using quicktype.
// Source: https://github.com/usnistgov/OSCAL/releases/tag/v1.2.1
// DO NOT EDIT — regenerate with: npx quicktype --src-lang schema --lang typescript --just-types --top-level Oscal schemas/oscal_complete_schema.json
/* eslint-disable @typescript-eslint/no-empty-object-type */
export interface Oscal {
    $schema?:                         string;
    catalog?:                         Catalog;
    "mapping-collection"?:            MappingCollection;
    profile?:                         Profile;
    "component-definition"?:          ComponentDefinition;
    "system-security-plan"?:          SystemSecurityPlanSSP;
    "assessment-plan"?:               SecurityAssessmentPlanSAP;
    "assessment-results"?:            SecurityAssessmentResultsSAR;
    "plan-of-action-and-milestones"?: PlanOfActionAndMilestonesPOAM;
}

/**
 * An assessment plan, such as those provided by a FedRAMP assessor.
 */
export interface SecurityAssessmentPlanSAP {
    "assessment-assets"?:   AssessmentAssets;
    "assessment-subjects"?: SubjectOfAssessment[];
    "back-matter"?:         BackMatter;
    "import-ssp":           ImportSystemSecurityPlan;
    /**
     * Used to define data objects that are used in the assessment plan, that do not appear in
     * the referenced SSP.
     */
    "local-definitions"?: AssessmentPlanLocalDefinitions;
    metadata:             DocumentMetadata;
    "reviewed-controls":  ReviewedControlsAndControlObjectives;
    tasks?:               Task[];
    /**
     * Used to define various terms and conditions under which an assessment, described by the
     * plan, can be performed. Each child part defines a different type of term or condition.
     */
    "terms-and-conditions"?: AssessmentPlanTermsAndConditions;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this assessment plan in this or other OSCAL instances. The locally defined
     * UUID of the assessment plan can be used to reference the data item locally or globally
     * (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which
     * means it should be consistently used to identify the same subject across revisions of the
     * document.
     */
    uuid: string;
}

/**
 * Identifies the assets used to perform this assessment, such as the assessment team,
 * scanning tools, and assumptions.
 */
export interface AssessmentAssets {
    "assessment-platforms": AssessmentPlatform[];
    components?:            AssessmentAssetsComponent[];
}

/**
 * Used to represent the toolset used to perform aspects of the assessment.
 */
export interface AssessmentPlatform {
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * The title or name for the assessment platform.
     */
    title?:             string;
    "uses-components"?: UsesComponent[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this assessment platform elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the assessment platform can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * A reference to a local or remote resource, that has a specific relation to the containing
 * object.
 */
export interface Link {
    /**
     * A resolvable URL reference to a resource.
     */
    href: string;
    /**
     * A label that indicates the nature of a resource, as a data serialization or format.
     */
    "media-type"?: string;
    /**
     * Describes the type of relationship provided by the link's hypertext reference. This can
     * be an indicator of the link's purpose.
     */
    rel?: string;
    /**
     * In case where the href points to a back-matter/resource, this value will indicate the URI
     * fragment to append to any rlink associated with the resource. This value MUST be URI
     * encoded.
     */
    "resource-fragment"?: string;
    /**
     * A textual label to associate with the link, which may be used for presentation in a tool.
     */
    text?: string;
}

/**
 * An attribute, characteristic, or quality of the containing object expressed as a
 * namespace qualified name/value pair.
 */
export interface Property {
    /**
     * A textual label that provides a sub-type or characterization of the property's name.
     */
    class?: string;
    /**
     * An identifier for relating distinct sets of properties.
     */
    group?: string;
    /**
     * A textual label, within a namespace, that identifies a specific attribute,
     * characteristic, or quality of the property's containing object.
     */
    name: string;
    /**
     * A namespace qualifying the property's name. This allows different organizations to
     * associate distinct semantics with the same name.
     */
    ns?:      string;
    remarks?: string;
    /**
     * A unique identifier for a property.
     */
    uuid?: string;
    /**
     * Indicates the value of the attribute, characteristic, or quality.
     */
    value: string;
}

/**
 * The set of components that are used by the assessment platform.
 */
export interface UsesComponent {
    /**
     * A machine-oriented identifier reference to a component that is implemented as part of an
     * inventory item.
     */
    "component-uuid":       string;
    links?:                 Link[];
    props?:                 Property[];
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
}

/**
 * A reference to a set of persons and/or organizations that have responsibility for
 * performing the referenced role in the context of the containing object.
 */
export interface ResponsibleParty {
    links?:        Link[];
    "party-uuids": string[];
    props?:        Property[];
    remarks?:      string;
    /**
     * A reference to a role performed by a party.
     */
    "role-id": string;
}

/**
 * A defined component that can be part of an implemented system.
 */
export interface AssessmentAssetsComponent {
    /**
     * A description of the component, including information about its function.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    protocols?:  ServiceProtocolInformation[];
    /**
     * A summary of the technological or business purpose of the component.
     */
    purpose?:             string;
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * Describes the operational status of the system component.
     */
    status: ComponentStatus;
    /**
     * A human readable name for the system component.
     */
    title: string;
    /**
     * A category describing the purpose of the component.
     */
    type: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this component elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the component can be used to reference the data item locally or globally
     * (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which
     * means it should be consistently used to identify the same subject across revisions of the
     * document.
     */
    uuid: string;
}

/**
 * Information about the protocol used to provide a service.
 */
export interface ServiceProtocolInformation {
    /**
     * The common name of the protocol, which should be the appropriate "service name" from the
     * IANA Service Name and Transport Protocol Port Number Registry.
     */
    name?:          string;
    "port-ranges"?: PortRange[];
    /**
     * A human readable name for the protocol (e.g., Transport Layer Security).
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this service protocol information elsewhere in this or other OSCAL
     * instances. The locally defined UUID of the service protocol can be used to reference the
     * data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be
     * assigned per-subject, which means it should be consistently used to identify the same
     * subject across revisions of the document.
     */
    uuid?: string;
}

/**
 * Where applicable this is the transport layer protocol port range an IPv4-based or
 * IPv6-based service uses.
 */
export interface PortRange {
    /**
     * Indicates the ending port number in a port range for a transport layer protocol
     */
    end?:     number;
    remarks?: string;
    /**
     * Indicates the starting port number in a port range for a transport layer protocol
     */
    start?: number;
    /**
     * Indicates the transport type.
     */
    transport?: Transport;
}

/**
 * Indicates the transport type.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum Transport {
    TCP = "TCP",
    UDP = "UDP",
}

/**
 * A reference to a role with responsibility for performing a function relative to the
 * containing object, optionally associated with a set of persons and/or organizations that
 * perform that role.
 */
export interface ResponsibleRole {
    links?:         Link[];
    "party-uuids"?: string[];
    props?:         Property[];
    remarks?:       string;
    /**
     * A human-oriented identifier reference to a role performed.
     */
    "role-id": string;
}

/**
 * Describes the operational status of the system component.
 */
export interface ComponentStatus {
    remarks?: string;
    /**
     * The operational status.
     */
    state: ComponentStatusState;
}

/**
 * The operational status.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum ComponentStatusState {
    Disposition = "disposition",
    Operational = "operational",
    Other = "other",
    UnderDevelopment = "under-development",
}

/**
 * Identifies system elements being assessed, such as components, inventory items, and
 * locations. In the assessment plan, this identifies a planned assessment subject. In the
 * assessment results this is an actual assessment subject, and reflects any changes from
 * the plan. exactly what will be the focus of this assessment. Any subjects not identified
 * in this way are out-of-scope.
 */
export interface SubjectOfAssessment {
    /**
     * A human-readable description of the collection of subjects being included in this
     * assessment.
     */
    description?:        string;
    "exclude-subjects"?: SelectAssessmentSubject[];
    "include-all"?:      IncludeAll;
    links?:              Link[];
    props?:              Property[];
    remarks?:            string;
    /**
     * Indicates the type of assessment subject, such as a component, inventory, item, location,
     * or party represented by this selection statement.
     */
    type?:               string;
    "include-subjects"?: SelectAssessmentSubject[];
}

/**
 * Identifies a set of assessment subjects to include/exclude by UUID.
 */
export interface SelectAssessmentSubject {
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * A machine-oriented identifier reference to a component, inventory-item, location, party,
     * user, or resource using it's UUID.
     */
    "subject-uuid": string;
    /**
     * Used to indicate the type of object pointed to by the uuid-ref within a subject.
     */
    type: string;
}

/**
 * Include all controls from the imported catalog or profile resources.
 */
export interface IncludeAll {
}

/**
 * A collection of resources that may be referenced from within the OSCAL document instance.
 */
export interface BackMatter {
    resources?: Resource[];
}

/**
 * A resource associated with content in the containing document instance. A resource may be
 * directly included in the document using base64 encoding or may point to one or more
 * equivalent internet resources.
 */
export interface Resource {
    /**
     * A resource encoded using the Base64 alphabet defined by RFC 2045.
     */
    base64?: Base64;
    /**
     * An optional citation consisting of end note text using structured markup.
     */
    citation?: Citation;
    /**
     * An optional short summary of the resource used to indicate the purpose of the resource.
     */
    description?:    string;
    "document-ids"?: DocumentIdentifier[];
    props?:          Property[];
    remarks?:        string;
    rlinks?:         ResourceLink[];
    /**
     * An optional name given to the resource, which may be used by a tool for display and
     * navigation.
     */
    title?: string;
    /**
     * A unique identifier for a resource.
     */
    uuid: string;
}

/**
 * A resource encoded using the Base64 alphabet defined by RFC 2045.
 */
export interface Base64 {
    /**
     * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
     * the name that will be assigned to the file when the file is decoded.
     */
    filename?: string;
    /**
     * A label that indicates the nature of a resource, as a data serialization or format.
     */
    "media-type"?: string;
    value:         string;
}

/**
 * An optional citation consisting of end note text using structured markup.
 */
export interface Citation {
    links?: Link[];
    props?: Property[];
    /**
     * A line of citation text.
     */
    text: string;
}

/**
 * A document identifier qualified by an identifier scheme.
 */
export interface DocumentIdentifier {
    identifier: string;
    /**
     * Qualifies the kind of document identifier using a URI. If the scheme is not provided the
     * value of the element will be interpreted as a string of characters.
     */
    scheme?: string;
}

/**
 * A URL-based pointer to an external resource with an optional hash for verification and
 * change detection.
 */
export interface ResourceLink {
    hashes?: Hash[];
    /**
     * A resolvable URL pointing to the referenced resource.
     */
    href: string;
    /**
     * A label that indicates the nature of a resource, as a data serialization or format.
     */
    "media-type"?: string;
}

/**
 * A representation of a cryptographic digest generated over a resource using a specified
 * hash algorithm.
 */
export interface Hash {
    /**
     * The digest method by which a hash is derived.
     */
    algorithm: string;
    value:     string;
}

/**
 * Used by the assessment plan and POA&M to import information about the system.
 */
export interface ImportSystemSecurityPlan {
    /**
     * A resolvable URL reference to the system security plan for the system being assessed.
     */
    href:     string;
    remarks?: string;
}

/**
 * Used to define data objects that are used in the assessment plan, that do not appear in
 * the referenced SSP.
 */
export interface AssessmentPlanLocalDefinitions {
    activities?:               Activity[];
    components?:               AssessmentAssetsComponent[];
    "inventory-items"?:        InventoryItem[];
    "objectives-and-methods"?: AssessmentSpecificControlObjective[];
    remarks?:                  string;
    users?:                    SystemUser[];
}

/**
 * Identifies an assessment or related process that can be performed. In the assessment
 * plan, this is an intended activity which may be associated with an assessment task. In
 * the assessment results, this an activity that was actually performed as part of an
 * assessment.
 */
export interface Activity {
    /**
     * A human-readable description of this included activity.
     */
    description:          string;
    links?:               Link[];
    props?:               Property[];
    "related-controls"?:  ReviewedControlsAndControlObjectives;
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    steps?:               Step[];
    /**
     * The title for this included activity.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this assessment activity elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the activity can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Identifies the controls being assessed and their control objectives.
 */
export interface ReviewedControlsAndControlObjectives {
    "control-objective-selections"?: ReferencedControlObjectives[];
    "control-selections":            AssessedControls[];
    /**
     * A human-readable description of control objectives.
     */
    description?: string;
    links?:       Link[];
    props?:       Property[];
    remarks?:     string;
}

/**
 * Identifies the control objectives of the assessment. In the assessment plan, these are
 * the planned objectives. In the assessment results, these are the assessed objectives, and
 * reflects any changes from the plan.
 */
export interface ReferencedControlObjectives {
    /**
     * A human-readable description of this collection of control objectives.
     */
    description?:          string;
    "exclude-objectives"?: SelectObjective[];
    "include-all"?:        IncludeAll;
    links?:                Link[];
    props?:                Property[];
    remarks?:              string;
    "include-objectives"?: SelectObjective[];
}

/**
 * Used to select a control objective for inclusion/exclusion based on the control
 * objective's identifier.
 */
export interface SelectObjective {
    /**
     * Points to an assessment objective.
     */
    "objective-id": string;
    remarks?:       string;
}

/**
 * Identifies the controls being assessed. In the assessment plan, these are the planned
 * controls. In the assessment results, these are the actual controls, and reflects any
 * changes from the plan.
 */
export interface AssessedControls {
    /**
     * A human-readable description of in-scope controls specified for assessment.
     */
    description?:        string;
    "exclude-controls"?: AssessedControlsExcludeControl[];
    "include-all"?:      IncludeAll;
    links?:              Link[];
    props?:              Property[];
    remarks?:            string;
    "include-controls"?: AssessedControlsExcludeControl[];
}

/**
 * Used to select a control for inclusion/exclusion based on one or more control
 * identifiers. A set of statement identifiers can be used to target the inclusion/exclusion
 * to only specific control statements providing more granularity over the specific
 * statements that are within the assessment scope.
 */
export interface AssessedControlsExcludeControl {
    /**
     * A reference to a control with a corresponding id value. When referencing an externally
     * defined control, the Control Identifier Reference must be used in the context of the
     * external / imported OSCAL instance (e.g., uri-reference).
     */
    "control-id":     string;
    "statement-ids"?: string[];
}

/**
 * Identifies an individual step in a series of steps related to an activity, such as an
 * assessment test or examination procedure.
 */
export interface Step {
    /**
     * A human-readable description of this step.
     */
    description:          string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    "reviewed-controls"?: ReviewedControlsAndControlObjectives;
    /**
     * The title for this step.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this step elsewhere in this or other OSCAL instances. The locally defined
     * UUID of the step (in a series of steps) can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * A single managed inventory item within the system.
 */
export interface InventoryItem {
    /**
     * A summary of the inventory item stating its purpose within the system.
     */
    description:               string;
    "implemented-components"?: ImplementedComponent[];
    links?:                    Link[];
    props?:                    Property[];
    remarks?:                  string;
    "responsible-parties"?:    ResponsibleParty[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this inventory item elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the inventory item can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * The set of components that are implemented in a given system inventory item.
 */
export interface ImplementedComponent {
    /**
     * A machine-oriented identifier reference to a component that is implemented as part of an
     * inventory item.
     */
    "component-uuid":       string;
    links?:                 Link[];
    props?:                 Property[];
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
}

/**
 * A local definition of a control objective for this assessment. Uses catalog syntax for
 * control objective and assessment actions.
 */
export interface AssessmentSpecificControlObjective {
    /**
     * A reference to a control with a corresponding id value. When referencing an externally
     * defined control, the Control Identifier Reference must be used in the context of the
     * external / imported OSCAL instance (e.g., uri-reference).
     */
    "control-id": string;
    /**
     * A human-readable description of this control objective.
     */
    description?: string;
    links?:       Link[];
    parts:        Part[];
    props?:       Property[];
    remarks?:     string;
}

/**
 * An annotated, markup-based textual element of a control's or catalog group's definition,
 * or a child of another part.
 */
export interface Part {
    /**
     * An optional textual providing a sub-type or characterization of the part's name, or a
     * category to which the part belongs.
     */
    class?: string;
    /**
     * A unique identifier for the part.
     */
    id?:    string;
    links?: Link[];
    /**
     * A textual label that uniquely identifies the part's semantic type, which exists in a
     * value space qualified by the ns.
     */
    name: string;
    /**
     * An optional namespace qualifying the part's name. This allows different organizations to
     * associate distinct semantics with the same name.
     */
    ns?:    string;
    parts?: Part[];
    props?: Property[];
    /**
     * Permits multiple paragraphs, lists, tables etc.
     */
    prose?: string;
    /**
     * An optional name given to the part, which may be used by a tool for display and
     * navigation.
     */
    title?: string;
}

/**
 * A type of user that interacts with the system based on an associated role.
 */
export interface SystemUser {
    "authorized-privileges"?: Privilege[];
    /**
     * A summary of the user's purpose within the system.
     */
    description?: string;
    links?:       Link[];
    props?:       Property[];
    remarks?:     string;
    "role-ids"?:  string[];
    /**
     * A short common name, abbreviation, or acronym for the user.
     */
    "short-name"?: string;
    /**
     * A name given to the user, which may be used by a tool for display and navigation.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this user class elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the system user can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Identifies a specific system privilege held by the user, along with an associated
 * description and/or rationale for the privilege.
 */
export interface Privilege {
    /**
     * A summary of the privilege's purpose within the system.
     */
    description?:          string;
    "functions-performed": string[];
    /**
     * A human readable name for the privilege.
     */
    title: string;
}

/**
 * Provides information about the containing document, and defines concepts that are shared
 * across the document.
 */
export interface DocumentMetadata {
    actions?:               Action[];
    "document-ids"?:        DocumentIdentifier[];
    "last-modified":        Date;
    links?:                 Link[];
    locations?:             Location[];
    "oscal-version":        string;
    parties?:               Party[];
    props?:                 Property[];
    published?:             Date;
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
    revisions?:             RevisionHistoryEntry[];
    roles?:                 Role[];
    /**
     * A name given to the document, which may be used by a tool for display and navigation.
     */
    title:   string;
    version: string;
}

/**
 * An action applied by a role within a given party to the content.
 */
export interface Action {
    /**
     * The date and time when the action occurred.
     */
    date?:                  Date;
    links?:                 Link[];
    props?:                 Property[];
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
    /**
     * Specifies the action type system used.
     */
    system: string;
    /**
     * The type of action documented by the assembly, such as an approval.
     */
    type: string;
    /**
     * A unique identifier that can be used to reference this defined action elsewhere in an
     * OSCAL document. A UUID should be consistently used for a given location across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * A physical point of presence, which may be associated with people, organizations, or
 * other concepts within the current or linked OSCAL document.
 */
export interface Location {
    address?:             Address;
    "email-addresses"?:   string[];
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "telephone-numbers"?: TelephoneNumber[];
    /**
     * A name given to the location, which may be used by a tool for display and navigation.
     */
    title?: string;
    urls?:  string[];
    /**
     * A unique ID for the location, for reference.
     */
    uuid: string;
}

/**
 * A postal address for the location.
 */
export interface Address {
    "addr-lines"?: string[];
    /**
     * City, town or geographical region for the mailing address.
     */
    city?: string;
    /**
     * The ISO 3166-1 alpha-2 country code for the mailing address.
     */
    country?: string;
    /**
     * Postal or ZIP code for mailing address.
     */
    "postal-code"?: string;
    /**
     * State, province or analogous geographical region for a mailing address.
     */
    state?: string;
    /**
     * Indicates the type of address.
     */
    type?: string;
}

/**
 * A telephone service number as defined by ITU-T E.164.
 */
export interface TelephoneNumber {
    number: string;
    /**
     * Indicates the type of phone number.
     */
    type?: string;
}

/**
 * An organization or person, which may be associated with roles or other concepts within
 * the current or linked OSCAL document.
 */
export interface Party {
    addresses?:                 Address[];
    "email-addresses"?:         string[];
    "external-ids"?:            PartyExternalIdentifier[];
    links?:                     Link[];
    "member-of-organizations"?: string[];
    /**
     * The full name of the party. This is typically the legal name associated with the party.
     */
    name?:    string;
    props?:   Property[];
    remarks?: string;
    /**
     * A short common name, abbreviation, or acronym for the party.
     */
    "short-name"?:        string;
    "telephone-numbers"?: TelephoneNumber[];
    /**
     * A category describing the kind of party the object describes.
     */
    type?: PartyType;
    /**
     * A unique identifier for the party.
     */
    uuid?:             string;
    "location-uuids"?: string[];
}

/**
 * An identifier for a person or organization using a designated scheme. e.g. an Open
 * Researcher and Contributor ID (ORCID).
 */
export interface PartyExternalIdentifier {
    id: string;
    /**
     * Indicates the type of external identifier.
     */
    scheme: string;
}

/**
 * A category describing the kind of party the object describes.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum PartyType {
    Organization = "organization",
    Person = "person",
}

/**
 * An entry in a sequential list of revisions to the containing document, expected to be in
 * reverse chronological order (i.e. latest first).
 */
export interface RevisionHistoryEntry {
    "last-modified"?: Date;
    links?:           Link[];
    "oscal-version"?: string;
    props?:           Property[];
    published?:       Date;
    remarks?:         string;
    /**
     * A name given to the document revision, which may be used by a tool for display and
     * navigation.
     */
    title?:  string;
    version: string;
}

/**
 * Defines a function, which might be assigned to a party in a specific situation.
 */
export interface Role {
    /**
     * A summary of the role's purpose and associated responsibilities.
     */
    description?: string;
    /**
     * A unique identifier for the role.
     */
    id:       string;
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * A short common name, abbreviation, or acronym for the role.
     */
    "short-name"?: string;
    /**
     * A name given to the role, which may be used by a tool for display and navigation.
     */
    title: string;
}

/**
 * Represents a scheduled event or milestone, which may be associated with a series of
 * assessment actions.
 */
export interface Task {
    "associated-activities"?: AssociatedActivity[];
    dependencies?:            TaskDependency[];
    /**
     * A human-readable description of this task.
     */
    description?:         string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    subjects?:            SubjectOfAssessment[];
    tasks?:               Task[];
    /**
     * The timing under which the task is intended to occur.
     */
    timing?: EventTiming;
    /**
     * The title for this task.
     */
    title: string;
    /**
     * The type of task.
     */
    type: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this task elsewhere in this or other OSCAL instances. The locally defined
     * UUID of the task can be used to reference the data item locally or globally (e.g., in an
     * imported OSCAL instance). This UUID should be assigned per-subject, which means it should
     * be consistently used to identify the same subject across revisions of the document.
     */
    uuid: string;
}

/**
 * Identifies an individual activity to be performed as part of a task.
 */
export interface AssociatedActivity {
    /**
     * A machine-oriented identifier reference to an activity defined in the list of activities.
     */
    "activity-uuid":      string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    subjects:             SubjectOfAssessment[];
}

/**
 * Used to indicate that a task is dependent on another task.
 */
export interface TaskDependency {
    remarks?: string;
    /**
     * A machine-oriented identifier reference to a unique task.
     */
    "task-uuid": string;
}

/**
 * The timing under which the task is intended to occur.
 */
export interface EventTiming {
    /**
     * The task is intended to occur on the specified date.
     */
    "on-date"?: OnDateCondition;
    /**
     * The task is intended to occur within the specified date range.
     */
    "within-date-range"?: OnDateRangeCondition;
    /**
     * The task is intended to occur at the specified frequency.
     */
    "at-frequency"?: FrequencyCondition;
}

/**
 * The task is intended to occur at the specified frequency.
 */
export interface FrequencyCondition {
    /**
     * The task must occur after the specified period has elapsed.
     */
    period:   number;
    remarks?: string;
    /**
     * The unit of time for the period.
     */
    unit: TimeUnit;
}

/**
 * The unit of time for the period.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum TimeUnit {
    Days = "days",
    Hours = "hours",
    Minutes = "minutes",
    Months = "months",
    Seconds = "seconds",
    Years = "years",
}

/**
 * The task is intended to occur on the specified date.
 */
export interface OnDateCondition {
    /**
     * The task must occur on the specified date.
     */
    date:     Date;
    remarks?: string;
}

/**
 * The task is intended to occur within the specified date range.
 */
export interface OnDateRangeCondition {
    /**
     * The task must occur on or before the specified date.
     */
    end:      Date;
    remarks?: string;
    /**
     * The task must occur on or after the specified date.
     */
    start: Date;
}

/**
 * Used to define various terms and conditions under which an assessment, described by the
 * plan, can be performed. Each child part defines a different type of term or condition.
 */
export interface AssessmentPlanTermsAndConditions {
    parts?: AssessmentPart[];
}

/**
 * A partition of an assessment plan or results or a child of another part.
 */
export interface AssessmentPart {
    /**
     * A textual label that provides a sub-type or characterization of the part's name. This can
     * be used to further distinguish or discriminate between the semantics of multiple parts of
     * the same control with the same name and ns.
     */
    class?: string;
    links?: Link[];
    /**
     * A textual label that uniquely identifies the part's semantic type.
     */
    name: string;
    /**
     * A namespace qualifying the part's name. This allows different organizations to associate
     * distinct semantics with the same name.
     */
    ns?:    string;
    parts?: AssessmentPart[];
    props?: Property[];
    /**
     * Permits multiple paragraphs, lists, tables etc.
     */
    prose?: string;
    /**
     * A name given to the part, which may be used by a tool for display and navigation.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this part elsewhere in this or other OSCAL instances. The locally defined
     * UUID of the part can be used to reference the data item locally or globally (e.g., in an
     * ported OSCAL instance). This UUID should be assigned per-subject, which means it should
     * be consistently used to identify the same subject across revisions of the document.
     */
    uuid?: string;
}

/**
 * Security assessment results, such as those provided by a FedRAMP assessor in the FedRAMP
 * Security Assessment Report.
 */
export interface SecurityAssessmentResultsSAR {
    "back-matter"?: BackMatter;
    "import-ap":    ImportAssessmentPlan;
    /**
     * Used to define data objects that are used in the assessment plan, that do not appear in
     * the referenced SSP.
     */
    "local-definitions"?: AssessmentResultsLocalDefinitions;
    metadata:             DocumentMetadata;
    results:              AssessmentResult[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this assessment results instance in this or other OSCAL instances. The
     * locally defined UUID of the assessment result can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * Used by assessment-results to import information about the original plan for assessing
 * the system.
 */
export interface ImportAssessmentPlan {
    /**
     * A resolvable URL reference to the assessment plan governing the assessment activities.
     */
    href:     string;
    remarks?: string;
}

/**
 * Used to define data objects that are used in the assessment plan, that do not appear in
 * the referenced SSP.
 */
export interface AssessmentResultsLocalDefinitions {
    activities?:               Activity[];
    "objectives-and-methods"?: AssessmentSpecificControlObjective[];
    remarks?:                  string;
}

/**
 * Used by the assessment results and POA&M. In the assessment results, this identifies all
 * of the assessment observations and findings, initial and residual risks, deviations, and
 * disposition. In the POA&M, this identifies initial and residual risks, deviations, and
 * disposition.
 */
export interface AssessmentResult {
    /**
     * A log of all assessment-related actions taken.
     */
    "assessment-log"?: AssessmentLog;
    attestations?:     AttestationStatements[];
    /**
     * A human-readable description of this set of test results.
     */
    description: string;
    /**
     * Date/time stamp identifying the end of the evidence collection reflected in these
     * results. In a continuous motoring scenario, this may contain the same value as start if
     * appropriate.
     */
    end?:      Date;
    findings?: Finding[];
    links?:    Link[];
    /**
     * Used to define data objects that are used in the assessment plan, that do not appear in
     * the referenced SSP.
     */
    "local-definitions"?: ResultLocalDefinitions;
    observations?:        Observation[];
    props?:               Property[];
    remarks?:             string;
    "reviewed-controls":  ReviewedControlsAndControlObjectives;
    risks?:               IdentifiedRisk[];
    /**
     * Date/time stamp identifying the start of the evidence collection reflected in these
     * results.
     */
    start: Date;
    /**
     * The title for this set of results.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this set of results in this or other OSCAL instances. The locally defined
     * UUID of the assessment result can be used to reference the data item locally or globally
     * (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which
     * means it should be consistently used to identify the same subject across revisions of the
     * document.
     */
    uuid: string;
}

/**
 * A log of all assessment-related actions taken.
 */
export interface AssessmentLog {
    entries: AssessmentLogEntry[];
}

/**
 * Identifies the result of an action and/or task that occurred as part of executing an
 * assessment plan or an assessment event that occurred in producing the assessment results.
 */
export interface AssessmentLogEntry {
    /**
     * A human-readable description of this event.
     */
    description?: string;
    /**
     * Identifies the end date and time of an event. If the event is a point in time, the start
     * and end will be the same date and time.
     */
    end?:             Date;
    links?:           Link[];
    "logged-by"?:     LoggedBy[];
    props?:           Property[];
    "related-tasks"?: TaskReference[];
    remarks?:         string;
    /**
     * Identifies the start date and time of an event.
     */
    start: Date;
    /**
     * The title for this event.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference an assessment event in this or other OSCAL instances. The locally defined
     * UUID of the assessment log entry can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Used to indicate who created a log entry in what role.
 */
export interface LoggedBy {
    /**
     * A machine-oriented identifier reference to the party who is making the log entry.
     */
    "party-uuid": string;
    remarks?:     string;
    /**
     * A point to the role-id of the role in which the party is making the log entry.
     */
    "role-id"?: string;
}

/**
 * Identifies an individual task for which the containing object is a consequence of.
 */
export interface TaskReference {
    /**
     * Used to detail assessment subjects that were identified by this task.
     */
    "identified-subject"?:  IdentifiedSubject;
    links?:                 Link[];
    props?:                 Property[];
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
    subjects?:              SubjectOfAssessment[];
    /**
     * A machine-oriented identifier reference to a unique task.
     */
    "task-uuid": string;
}

/**
 * Used to detail assessment subjects that were identified by this task.
 */
export interface IdentifiedSubject {
    /**
     * A machine-oriented identifier reference to a unique assessment subject placeholder
     * defined by this task.
     */
    "subject-placeholder-uuid": string;
    subjects:                   SubjectOfAssessment[];
}

/**
 * A set of textual statements, typically written by the assessor.
 */
export interface AttestationStatements {
    parts:                  AssessmentPart[];
    "responsible-parties"?: ResponsibleParty[];
}

/**
 * Describes an individual finding.
 */
export interface Finding {
    /**
     * A human-readable description of this finding.
     */
    description: string;
    /**
     * A machine-oriented identifier reference to the implementation statement in the SSP to
     * which this finding is related.
     */
    "implementation-statement-uuid"?: string;
    links?:                           Link[];
    origins?:                         FindingOrigin[];
    props?:                           Property[];
    "related-observations"?:          RelatedObservation[];
    "related-risks"?:                 AssociatedRisk[];
    remarks?:                         string;
    target:                           TargetClass;
    /**
     * The title for this finding.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this finding in this or other OSCAL instances. The locally defined UUID of
     * the finding can be used to reference the data item locally or globally (e.g., in an
     * imported OSCAL instance). This UUID should be assigned per-subject, which means it should
     * be consistently used to identify the same subject across revisions of the document.
     */
    uuid: string;
}

/**
 * Identifies the source of the finding, such as a tool, interviewed person, or activity.
 */
export interface FindingOrigin {
    actors:           OriginatingActor[];
    "related-tasks"?: TaskReference[];
}

/**
 * The actor that produces an observation, a finding, or a risk. One or more actor type can
 * be used to specify a person that is using a tool.
 */
export interface OriginatingActor {
    /**
     * A machine-oriented identifier reference to the tool or person based on the associated
     * type.
     */
    "actor-uuid": string;
    links?:       Link[];
    props?:       Property[];
    /**
     * For a party, this can optionally be used to specify the role the actor was performing.
     */
    "role-id"?: string;
    /**
     * The kind of actor.
     */
    type: ActorType;
}

/**
 * The kind of actor.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum ActorType {
    AssessmentPlatform = "assessment-platform",
    Party = "party",
    Tool = "tool",
}

/**
 * Relates the identified element to a set of referenced observations that were used to
 * support its determination.
 */
export interface RelatedObservation {
    /**
     * A machine-oriented identifier reference to an observation defined in the list of
     * observations.
     */
    "observation-uuid": string;
    remarks?:           string;
}

/**
 * Relates the finding to a set of referenced risks that were used to determine the finding.
 */
export interface AssociatedRisk {
    remarks?: string;
    /**
     * A machine-oriented identifier reference to a risk defined in the list of risks.
     */
    "risk-uuid": string;
}

/**
 * Captures an assessor's conclusions regarding the degree to which an objective is
 * satisfied.
 */
export interface TargetClass {
    /**
     * A human-readable description of the assessor's conclusions regarding the degree to which
     * an objective is satisfied.
     */
    description?:             string;
    "implementation-status"?: ImplementationStatus;
    links?:                   Link[];
    props?:                   Property[];
    remarks?:                 string;
    /**
     * A determination of if the objective is satisfied or not within a given system.
     */
    status: StatusClass;
    /**
     * A machine-oriented identifier reference for a specific target qualified by the type.
     */
    "target-id": string;
    /**
     * The title for this objective status.
     */
    title?: string;
    /**
     * Identifies the type of the target.
     */
    type: FindingTargetType;
}

/**
 * Indicates the degree to which the a given control is implemented.
 */
export interface ImplementationStatus {
    remarks?: string;
    /**
     * Identifies the implementation status of the control or control objective.
     */
    state: string;
}

/**
 * A determination of if the objective is satisfied or not within a given system.
 */
export interface StatusClass {
    /**
     * The reason the objective was given it's status.
     */
    reason?:  string;
    remarks?: string;
    /**
     * An indication as to whether the objective is satisfied or not.
     */
    state: ObjectiveStatusState;
}

/**
 * An indication as to whether the objective is satisfied or not.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum ObjectiveStatusState {
    NotSatisfied = "not-satisfied",
    Satisfied = "satisfied",
}

/**
 * Identifies the type of the target.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum FindingTargetType {
    ObjectiveID = "objective-id",
    StatementID = "statement-id",
}

/**
 * Used to define data objects that are used in the assessment plan, that do not appear in
 * the referenced SSP.
 */
export interface ResultLocalDefinitions {
    "assessment-assets"?: AssessmentAssets;
    components?:          AssessmentAssetsComponent[];
    "inventory-items"?:   InventoryItem[];
    tasks?:               Task[];
    users?:               SystemUser[];
}

/**
 * Describes an individual observation.
 */
export interface Observation {
    /**
     * Date/time stamp identifying when the finding information was collected.
     */
    collected: Date;
    /**
     * A human-readable description of this assessment observation.
     */
    description: string;
    /**
     * Date/time identifying when the finding information is out-of-date and no longer valid.
     * Typically used with continuous assessment scenarios.
     */
    expires?:             Date;
    links?:               Link[];
    methods:              string[];
    origins?:             FindingOrigin[];
    props?:               Property[];
    "relevant-evidence"?: RelevantEvidence[];
    remarks?:             string;
    subjects?:            IdentifiesTheSubject[];
    /**
     * The title for this observation.
     */
    title?: string;
    types?: string[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this observation elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the observation can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Links this observation to relevant evidence.
 */
export interface RelevantEvidence {
    /**
     * A human-readable description of this evidence.
     */
    description: string;
    /**
     * A resolvable URL reference to relevant evidence.
     */
    href?:    string;
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
}

/**
 * A human-oriented identifier reference to a resource. Use type to indicate whether the
 * identified resource is a component, inventory item, location, user, or something else.
 */
export interface IdentifiesTheSubject {
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * A machine-oriented identifier reference to a component, inventory-item, location, party,
     * user, or resource using it's UUID.
     */
    "subject-uuid": string;
    /**
     * The title or name for the referenced subject.
     */
    title?: string;
    /**
     * Used to indicate the type of object pointed to by the uuid-ref within a subject.
     */
    type: string;
}

/**
 * An identified risk.
 */
export interface IdentifiedRisk {
    characterizations?: Characterization[];
    /**
     * The date/time by which the risk must be resolved.
     */
    deadline?: Date;
    /**
     * A human-readable summary of the identified risk, to include a statement of how the risk
     * impacts the system.
     */
    description:             string;
    links?:                  Link[];
    "mitigating-factors"?:   MitigatingFactor[];
    origins?:                FindingOrigin[];
    props?:                  Property[];
    "related-observations"?: RelatedObservation[];
    remediations?:           RiskResponse[];
    /**
     * A log of all risk-related tasks taken.
     */
    "risk-log"?: RiskLog;
    /**
     * An summary of impact for how the risk affects the system.
     */
    statement:     string;
    status:        string;
    "threat-ids"?: ThreatID[];
    /**
     * The title for this risk.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this risk elsewhere in this or other OSCAL instances. The locally defined
     * UUID of the risk can be used to reference the data item locally or globally (e.g., in an
     * imported OSCAL instance). This UUID should be assigned per-subject, which means it should
     * be consistently used to identify the same subject across revisions of the document.
     */
    uuid: string;
}

/**
 * A collection of descriptive data about the containing object from a specific origin.
 */
export interface Characterization {
    facets: Facet[];
    links?: Link[];
    origin: FindingOrigin;
    props?: Property[];
}

/**
 * An individual characteristic that is part of a larger set produced by the same actor.
 */
export interface Facet {
    links?: Link[];
    /**
     * The name of the risk metric within the specified system.
     */
    name:     string;
    props?:   Property[];
    remarks?: string;
    /**
     * Specifies the naming system under which this risk metric is organized, which allows for
     * the same names to be used in different systems controlled by different parties. This
     * avoids the potential of a name clash.
     */
    system: string;
    /**
     * Indicates the value of the facet.
     */
    value: string;
}

/**
 * Describes an existing mitigating factor that may affect the overall determination of the
 * risk, with an optional link to an implementation statement in the SSP.
 */
export interface MitigatingFactor {
    /**
     * A human-readable description of this mitigating factor.
     */
    description: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this implementation statement elsewhere in this or other OSCAL instancess.
     * The locally defined UUID of the implementation statement can be used to reference the
     * data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be
     * assigned per-subject, which means it should be consistently used to identify the same
     * subject across revisions of the document.
     */
    "implementation-uuid"?: string;
    links?:                 Link[];
    props?:                 Property[];
    subjects?:              IdentifiesTheSubject[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this mitigating factor elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the mitigating factor can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * Describes either recommended or an actual plan for addressing the risk.
 */
export interface RiskResponse {
    /**
     * A human-readable description of this response plan.
     */
    description: string;
    /**
     * Identifies whether this is a recommendation, such as from an assessor or tool, or an
     * actual plan accepted by the system owner.
     */
    lifecycle:          string;
    links?:             Link[];
    origins?:           FindingOrigin[];
    props?:             Property[];
    remarks?:           string;
    "required-assets"?: RequiredAsset[];
    tasks?:             Task[];
    /**
     * The title for this response activity.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this remediation elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the risk response can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Identifies an asset required to achieve remediation.
 */
export interface RequiredAsset {
    /**
     * A human-readable description of this required asset.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    remarks?:    string;
    subjects?:   IdentifiesTheSubject[];
    /**
     * The title for this required asset.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this required asset elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the asset can be used to reference the data item locally or globally
     * (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which
     * means it should be consistently used to identify the same subject across revisions of the
     * document.
     */
    uuid: string;
}

/**
 * A log of all risk-related tasks taken.
 */
export interface RiskLog {
    entries: RiskLogEntry[];
}

/**
 * Identifies an individual risk response that occurred as part of managing an identified
 * risk.
 */
export interface RiskLogEntry {
    /**
     * A human-readable description of what was done regarding the risk.
     */
    description?: string;
    /**
     * Identifies the end date and time of the event. If the event is a point in time, the start
     * and end will be the same date and time.
     */
    end?:                 Date;
    links?:               Link[];
    "logged-by"?:         LoggedBy[];
    props?:               Property[];
    "related-responses"?: RiskResponseReference[];
    remarks?:             string;
    /**
     * Identifies the start date and time of the event.
     */
    start:            Date;
    "status-change"?: string;
    /**
     * The title for this risk log entry.
     */
    title?: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this risk log entry elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the risk log entry can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Identifies an individual risk response that this log entry is for.
 */
export interface RiskResponseReference {
    links?:           Link[];
    props?:           Property[];
    "related-tasks"?: TaskReference[];
    remarks?:         string;
    /**
     * A machine-oriented identifier reference to a unique risk response.
     */
    "response-uuid": string;
}

/**
 * A pointer, by ID, to an externally-defined threat.
 */
export interface ThreatID {
    /**
     * An optional location for the threat data, from which this ID originates.
     */
    href?: string;
    id:    string;
    /**
     * Specifies the source of the threat information.
     */
    system: string;
}

/**
 * A structured, organized collection of control information.
 */
export interface Catalog {
    "back-matter"?: BackMatter;
    controls?:      Control[];
    groups?:        CatalogControlGroup[];
    metadata:       DocumentMetadata;
    params?:        Parameter[];
    /**
     * Provides a globally unique means to identify a given catalog instance.
     */
    uuid: string;
}

/**
 * A structured object representing a requirement or guideline, which when implemented will
 * reduce an aspect of risk related to an information system and its information.
 */
export interface Control {
    /**
     * A textual label that provides a sub-type or characterization of the control.
     */
    class?:    string;
    controls?: Control[];
    /**
     * Identifies a control such that it can be referenced in the defining catalog and other
     * OSCAL instances (e.g., profiles).
     */
    id:      string;
    links?:  Link[];
    params?: Parameter[];
    parts?:  Part[];
    props?:  Property[];
    /**
     * A name given to the control, which may be used by a tool for display and navigation.
     */
    title: string;
}

/**
 * Parameters provide a mechanism for the dynamic assignment of value(s) in a control.
 */
export interface Parameter {
    /**
     * A textual label that provides a characterization of the type, purpose, use or scope of
     * the parameter.
     */
    class?:       string;
    constraints?: Constraint[];
    /**
     * (deprecated) Another parameter invoking this one. This construct has been deprecated and
     * should not be used.
     */
    "depends-on"?: string;
    guidelines?:   Guideline[];
    /**
     * A unique identifier for the parameter.
     */
    id?: string;
    /**
     * A short, placeholder name for the parameter, which can be used as a substitute for a
     * value if no value is assigned.
     */
    label?:   string;
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * Describes the purpose and use of a parameter.
     */
    usage?:  string;
    values?: string[];
    select?: Selection;
}

/**
 * A formal or informal expression of a constraint or test.
 */
export interface Constraint {
    /**
     * A textual summary of the constraint to be applied.
     */
    description?: string;
    tests?:       ConstraintTest[];
}

/**
 * A test expression which is expected to be evaluated by a tool.
 */
export interface ConstraintTest {
    /**
     * A formal (executable) expression of a constraint.
     */
    expression: string;
    remarks?:   string;
}

/**
 * A prose statement that provides a recommendation for the use of a parameter.
 */
export interface Guideline {
    /**
     * Prose permits multiple paragraphs, lists, tables etc.
     */
    prose: string;
}

/**
 * Presenting a choice among alternatives.
 */
export interface Selection {
    choice?: string[];
    /**
     * Describes the number of selections that must occur. Without this setting, only one value
     * should be assumed to be permitted.
     */
    "how-many"?: ParameterCardinality;
}

/**
 * Describes the number of selections that must occur. Without this setting, only one value
 * should be assumed to be permitted.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum ParameterCardinality {
    One = "one",
    OneOrMore = "one-or-more",
}

/**
 * A group of controls, or of groups of controls.
 */
export interface CatalogControlGroup {
    /**
     * A textual label that provides a sub-type or characterization of the group.
     */
    class?:  string;
    groups?: CatalogControlGroup[];
    /**
     * Identifies the group for the purpose of cross-linking within the defining instance or
     * from other instances that reference the catalog.
     */
    id?:     string;
    links?:  Link[];
    params?: Parameter[];
    parts?:  Part[];
    props?:  Property[];
    /**
     * A name given to the group, which may be used by a tool for display and navigation.
     */
    title:     string;
    controls?: Control[];
}

/**
 * A collection of component descriptions, which may optionally be grouped by capability.
 */
export interface ComponentDefinition {
    "back-matter"?:                  BackMatter;
    capabilities?:                   Capability[];
    components?:                     ComponentDefinitionComponent[];
    "import-component-definitions"?: ImportComponentDefinition[];
    metadata:                        DocumentMetadata;
    /**
     * Provides a globally unique means to identify a given component definition instance.
     */
    uuid: string;
}

/**
 * A grouping of other components and/or capabilities.
 */
export interface Capability {
    "control-implementations"?: ControlImplementationSet[];
    /**
     * A summary of the capability.
     */
    description:                string;
    "incorporates-components"?: IncorporatesComponent[];
    links?:                     Link[];
    /**
     * The capability's human-readable name.
     */
    name:     string;
    props?:   Property[];
    remarks?: string;
    /**
     * Provides a globally unique means to identify a given capability.
     */
    uuid: string;
}

/**
 * Defines how the component or capability supports a set of controls.
 */
export interface ControlImplementationSet {
    /**
     * A description of how the specified set of controls are implemented for the containing
     * component or capability.
     */
    description:                string;
    "implemented-requirements": ImplementedRequirementElement[];
    links?:                     Link[];
    props?:                     Property[];
    "set-parameters"?:          SetParameterValue[];
    /**
     * A reference to an OSCAL catalog or profile providing the referenced control or subcontrol
     * definition.
     */
    source: string;
    /**
     * Provides a means to identify a set of control implementations that are supported by a
     * given component or capability.
     */
    uuid: string;
}

/**
 * Describes how the containing component or capability implements an individual control.
 */
export interface ImplementedRequirementElement {
    /**
     * A reference to a control with a corresponding id value. When referencing an externally
     * defined control, the Control Identifier Reference must be used in the context of the
     * external / imported OSCAL instance (e.g., uri-reference).
     */
    "control-id": string;
    /**
     * A suggestion from the supplier (e.g., component vendor or author) for how the specified
     * control may be implemented if the containing component or capability is instantiated in a
     * system security plan.
     */
    description:          string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    "set-parameters"?:    SetParameterValue[];
    statements?:          ControlStatementImplementation[];
    /**
     * Provides a globally unique means to identify a given control implementation by a
     * component.
     */
    uuid: string;
}

/**
 * Identifies the parameter that will be set by the enclosed value.
 */
export interface SetParameterValue {
    /**
     * A human-oriented reference to a parameter within a control, who's catalog has been
     * imported into the current implementation context.
     */
    "param-id": string;
    remarks?:   string;
    values:     string[];
}

/**
 * Identifies which statements within a control are addressed.
 */
export interface ControlStatementImplementation {
    /**
     * A summary of how the containing control statement is implemented by the component or
     * capability.
     */
    description:          string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A human-oriented identifier reference to a control statement.
     */
    "statement-id": string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this control statement elsewhere in this or other OSCAL instances. The UUID
     * of the control statement in the source OSCAL instance is sufficient to reference the data
     * item locally or globally (e.g., in an imported OSCAL instance).
     */
    uuid: string;
}

/**
 * The collection of components comprising this capability.
 */
export interface IncorporatesComponent {
    /**
     * A machine-oriented identifier reference to a component.
     */
    "component-uuid": string;
    /**
     * A description of the component, including information about its function.
     */
    description: string;
}

/**
 * A defined component that can be part of an implemented system.
 */
export interface ComponentDefinitionComponent {
    "control-implementations"?: ControlImplementationSet[];
    /**
     * A description of the component, including information about its function.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    protocols?:  ServiceProtocolInformation[];
    /**
     * A summary of the technological or business purpose of the component.
     */
    purpose?:             string;
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A human readable name for the component.
     */
    title: string;
    /**
     * A category describing the purpose of the component.
     */
    type: string;
    /**
     * Provides a globally unique means to identify a given component.
     */
    uuid: string;
}

/**
 * Loads a component definition from another resource.
 */
export interface ImportComponentDefinition {
    /**
     * A link to a resource that defines a set of components and/or capabilities to import into
     * this collection.
     */
    href:     string;
    remarks?: string;
}

/**
 * A collection of relationship-based control and/or control statement mappings.
 */
export interface MappingCollection {
    "back-matter"?: BackMatter;
    mappings:       ControlMapping[] | ControlMapping;
    metadata:       DocumentMetadata;
    provenance:     MappingProvenance;
    /**
     * A globally unique identifier with cross-instance scope for this catalog instance. This
     * UUID should be changed when this document is revised.
     */
    uuid: string;
}

/**
 * A mapping between two target resources.
 */
export interface ControlMapping {
    "confidence-score"?:    ConfidenceScore;
    coverage?:              Coverage;
    links?:                 Link[];
    "mapping-description"?: string;
    maps:                   MappingEntry[];
    /**
     * The method used for relating controls within the mapping. The supported methods are
     * aligned with the NIST Interagency Report (IR) 8477, Section 4.3 Set Theory Relationship
     * Mapping.
     */
    "matching-rationale"?: Matching;
    /**
     * The method used to complete the overall mapping.
     */
    method?:               Method;
    props?:                Property[];
    remarks?:              string;
    "source-gap-summary"?: GapSummary;
    "source-resource":     MappedResourceReference;
    /**
     * The current status of this mapping document.
     */
    status?:               StatusEnum;
    "target-gap-summary"?: GapSummary;
    "target-resource":     MappedResourceReference;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this mapping definition elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the mapping can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same mapping across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * This records either a string category or a decimal value from 0-1 representing a
 * percentage. Both of these values describe an estimation of the author's confidence that
 * this mapping is correct and accurate.
 */
export interface ConfidenceScore {
    category?:   string;
    percentage?: number;
}

/**
 * A decimal value from 0-1, representing the percentage coverage of the targets by the
 * sources.
 */
export interface Coverage {
    /**
     * The method used to determine the coverage value.
     */
    "generation-method"?: string;
    "target-coverage":    number;
}

/**
 * A relationship-based mapping between a source and target set consisting of members (i.e.,
 * controls, control statements) from the respective source and target.
 */
export interface MappingEntry {
    "confidence-score"?: ConfidenceScore;
    coverage?:           Coverage;
    links?:              Link[];
    /**
     * The method used for relating controls within the mapping. The supported methods are
     * aligned with the NIST Interagency Report (IR) 8477, Section 4.3 Set Theory Relationship
     * Mapping.
     */
    "matching-rationale"?: Matching;
    /**
     * A namespace qualifying the relationship's value. This allows different organizations to
     * associate distinct semantics for relationships with the same name.
     */
    ns?:         string;
    props?:      Property[];
    qualifiers?: RelationshipQualifier[];
    /**
     * The relationship type for the mapping entry, which describes the relationship between the
     * effective requirements of the specified source and target sets in the context of the
     * matching-rationale method globaly defined in the provenance unless overwritten locally in
     * the map. The relationship type and the matching-rationale must be used together. However,
     * more than one matching-rationale method may apply to a source and target pair.
     */
    relationship: string;
    remarks?:     string;
    sources:      MappingEntryItemSourceOrTarget[];
    components:      MappingEntryItemSourceOrTarget[];
    /**
     * The unique identifier for the mapping entry.
     */
    uuid: string;
}

/**
 * The method used for relating controls within the mapping. The supported methods are
 * aligned with the NIST Interagency Report (IR) 8477, Section 4.3 Set Theory Relationship
 * Mapping.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum Matching {
    Functional = "functional",
    Semantic = "semantic",
    Syntactic = "syntactic",
}

/**
 * Describes requirements, incompatibilities and gaps that are identified between a target
 * and source in a mapping item.
 */
export interface RelationshipQualifier {
    /**
     * The category expresses the resolvable nature of the predicate.
     */
    category: Category;
    /**
     * Details that outline what requirements must be met, or cannot be met. If the qualifier
     * identifies a gap, this should idenfity the gap, and any incompatibilities.
     */
    description: string;
    /**
     * The predicate describes how the qualifer applies to the subject.
     */
    predicate: Predicate;
    remarks?:  string;
    /**
     * The focus of the qualifier.
     */
    subject: Subject;
}

/**
 * The category expresses the resolvable nature of the predicate.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum Category {
    Addressable = "addressable",
    Blocked = "blocked",
    Restricted = "restricted",
}

/**
 * The predicate describes how the qualifer applies to the subject.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum Predicate {
    HasIncompatibility = "has-incompatibility",
    HasRequirement = "has-requirement",
}

/**
 * The focus of the qualifier.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum Subject {
    Both = "both",
    Source = "source",
    Component = "target",
}

/**
 * A specific edge within a source or target that is the subject of a mapping.
 */
export interface MappingEntryItemSourceOrTarget {
    /**
     * A reference to an identified subject that is of the specified type .
     */
    "id-ref": string;
    links?:   Link[];
    props?:   Property[];
    remarks?: string;
    /**
     * The semantic type of the subject.
     */
    type: SubjectType;
}

/**
 * The semantic type of the subject.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum SubjectType {
    Control = "control",
    Statement = "statement",
}

/**
 * The method used to complete the overall mapping.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum Method {
    Automation = "automation",
    Human = "human",
    Hybrid = "hybrid",
}

/**
 * A by-id collection of all controls that were not mapped at all in this
 * mapping-collection. If a control is partially mapped, the parts of the control are not
 * mappable, the gap and discrepancies should be documented in the relationship-gal.
 */
export interface GapSummary {
    "unmapped-controls": UnmappedControlElement[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this mapping gap summary elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the SSP can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance).This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Select a control or controls from an imported control set.
 */
export interface UnmappedControlElement {
    matching?: MatchControlsByPattern[];
    /**
     * When a control is included, whether its child (dependent) controls are also included.
     */
    "with-child-controls"?: IncludeContainedControlsWithControl;
    "with-ids"?:            string[];
}

/**
 * Selecting a set of controls by matching their IDs with a wildcard pattern.
 */
export interface MatchControlsByPattern {
    /**
     * A glob expression matching the IDs of one or more controls to be selected.
     */
    pattern?: string;
    remarks?: string;
}

/**
 * When a control is included, whether its child (dependent) controls are also included.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum IncludeContainedControlsWithControl {
    No = "no",
    Yes = "yes",
}

/**
 * A reference to a resource that is either the source or the target of a mapping.
 */
export interface MappedResourceReference {
    /**
     * A resolvable URL reference to the base catalog or profile that this profile is tailoring.
     */
    href:   string;
    links?: Link[];
    /**
     * An optional namespace qualifying the resource's type.
     */
    ns?:      string;
    props?:   Property[];
    remarks?: string;
    /**
     * The semantic type of the resource.
     */
    type: string;
}

/**
 * The current status of this mapping document.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum StatusEnum {
    Complete = "complete",
    Deprecated = "deprecated",
    Draft = "draft",
    NotComplete = "not-complete",
    Superseded = "superseded",
}

/**
 * Describes requirements, incompatibilities and gaps that are identified between a target
 * and source in a mapping item.
 */
export interface MappingProvenance {
    "confidence-score"?:   ConfidenceScore;
    coverage?:             Coverage;
    links?:                Link[];
    "mapping-description": string;
    /**
     * The method used for relating controls within the mapping. The supported methods are
     * aligned with the NIST Interagency Report (IR) 8477, Section 4.3 Set Theory Relationship
     * Mapping.
     */
    "matching-rationale": Matching;
    /**
     * The method used to complete the overall mapping.
     */
    method:                 Method;
    props?:                 Property[];
    remarks?:               string;
    "responsible-parties"?: ResponsibleParty[];
    /**
     * The current status of this mapping document.
     */
    status: StatusEnum;
}

/**
 * A plan of action and milestones which identifies initial and residual risks, deviations,
 * and disposition, such as those required by FedRAMP.
 */
export interface PlanOfActionAndMilestonesPOAM {
    "back-matter"?:       BackMatter;
    findings?:            Finding[];
    "import-ssp"?:        ImportSystemSecurityPlan;
    "local-definitions"?: PlanOfActionAndMilestonesLocalDefinitions;
    metadata:             DocumentMetadata;
    observations?:        Observation[];
    "poam-items":         POAMItem[];
    risks?:               IdentifiedRisk[];
    "system-id"?:         SystemIdentification;
    /**
     * A machine-oriented, globally unique identifier with instancescope that can be used to
     * reference this POA&M instance in this OSCAL instance. This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * Allows components, and inventory-items to be defined within the POA&M for circumstances
 * where no OSCAL-based SSP exists, or is not delivered with the POA&M.
 */
export interface PlanOfActionAndMilestonesLocalDefinitions {
    "assessment-assets"?: AssessmentAssets;
    components?:          AssessmentAssetsComponent[];
    "inventory-items"?:   InventoryItem[];
    remarks?:             string;
}

/**
 * Describes an individual POA&M item.
 */
export interface POAMItem {
    /**
     * A human-readable description of POA&M item.
     */
    description:             string;
    links?:                  Link[];
    origins?:                PoamItemOrigin[];
    props?:                  Property[];
    "related-findings"?:     RelatedFinding[];
    "related-observations"?: RelatedObservation[];
    "related-risks"?:        AssociatedRisk[];
    remarks?:                string;
    /**
     * The title or name for this POA&M item .
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with instance scope that can be used to
     * reference this POA&M item entry in this OSCAL instance. This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid?: string;
}

/**
 * Identifies the source of the finding, such as a tool or person.
 */
export interface PoamItemOrigin {
    actors: OriginatingActor[];
}

/**
 * Relates the poam-item to referenced finding(s).
 */
export interface RelatedFinding {
    /**
     * A machine-oriented identifier reference to a finding defined in the list of findings.
     */
    "finding-uuid": string;
    remarks?:       string;
}

/**
 * A human-oriented, globally unique identifier with cross-instance scope that can be used
 * to reference this system identification property elsewhere in this or other OSCAL
 * instances. When referencing an externally defined system identification, the system
 * identification must be used in the context of the external / imported OSCAL instance
 * (e.g., uri-reference). This string should be assigned per-subject, which means it should
 * be consistently used to identify the same system across revisions of the document.
 */
export interface SystemIdentification {
    id: string;
    /**
     * Identifies the identification system from which the provided identifier was assigned.
     */
    "identifier-type"?: string;
}

/**
 * Each OSCAL profile is defined by a profile element.
 */
export interface Profile {
    "back-matter"?: BackMatter;
    imports:        ImportResource[];
    merge?:         MergeControls;
    metadata:       DocumentMetadata;
    modify?:        ModifyControls;
    /**
     * Provides a globally unique means to identify a given profile instance.
     */
    uuid: string;
}

/**
 * Designates a referenced source catalog or profile that provides a source of control
 * information for use in creating a new overlay or baseline.
 */
export interface ImportResource {
    "exclude-controls"?: UnmappedControlElement[];
    /**
     * A resolvable URL reference to the base catalog or profile that this profile is tailoring.
     */
    href?:               string;
    "include-all"?:      IncludeAll;
    "include-controls"?: UnmappedControlElement[];
}

/**
 * Provides structuring directives that instruct how controls are organized after profile
 * resolution.
 */
export interface MergeControls {
    /**
     * A Combine element defines how to resolve duplicate instances of the same control (e.g.,
     * controls with the same ID).
     */
    combine?: CombinationRule;
    /**
     * Directs that controls appear without any grouping structure.
     */
    flat?: FlatWithoutGrouping;
    /**
     * Indicates that the controls selected should retain their original grouping as defined in
     * the import source.
     */
    "as-is"?: boolean;
    /**
     * Provides an alternate grouping structure that selected controls will be placed in.
     */
    custom?: CustomGrouping;
}

/**
 * A Combine element defines how to resolve duplicate instances of the same control (e.g.,
 * controls with the same ID).
 */
export interface CombinationRule {
}

/**
 * Provides an alternate grouping structure that selected controls will be placed in.
 */
export interface CustomGrouping {
    groups?:            CustomControlGroup[];
    "insert-controls"?: InsertControls[];
}

/**
 * A group of (selected) controls or of groups of controls.
 */
export interface CustomControlGroup {
    /**
     * A textual label that provides a sub-type or characterization of the group.
     */
    class?:  string;
    groups?: CustomControlGroup[];
    /**
     * Identifies the group.
     */
    id?:     string;
    links?:  Link[];
    params?: Parameter[];
    parts?:  Part[];
    props?:  Property[];
    /**
     * A name to be given to the group for use in display.
     */
    title:              string;
    "insert-controls"?: InsertControls[];
}

/**
 * Specifies which controls to use in the containing context.
 */
export interface InsertControls {
    "exclude-controls"?: UnmappedControlElement[];
    "include-all"?:      IncludeAll;
    /**
     * A designation of how a selection of controls in a profile is to be ordered.
     */
    order?:              Order;
    "include-controls"?: UnmappedControlElement[];
}

/**
 * A designation of how a selection of controls in a profile is to be ordered.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum Order {
    Ascending = "ascending",
    Descending = "descending",
    Keep = "keep",
}

/**
 * Directs that controls appear without any grouping structure.
 */
export interface FlatWithoutGrouping {
}

/**
 * Set parameters or amend controls in resolution.
 */
export interface ModifyControls {
    alters?:           Alteration[];
    "set-parameters"?: ParameterSetting[];
}

/**
 * Specifies changes to be made to an included control when a profile is resolved.
 */
export interface Alteration {
    adds?: Addition[];
    /**
     * A reference to a control with a corresponding id value. When referencing an externally
     * defined control, the Control Identifier Reference must be used in the context of the
     * external / imported OSCAL instance (e.g., uri-reference).
     */
    "control-id": string;
    removes?:     Removal[];
}

/**
 * Specifies contents to be added into controls, in resolution.
 */
export interface Addition {
    /**
     * Target location of the addition.
     */
    "by-id"?: string;
    links?:   Link[];
    params?:  Parameter[];
    parts?:   Part[];
    /**
     * Where to add the new content with respect to the targeted element (beside it or inside
     * it).
     */
    position?: Position;
    props?:    Property[];
    /**
     * A name given to the control, which may be used by a tool for display and navigation.
     */
    title?: string;
}

/**
 * Where to add the new content with respect to the targeted element (beside it or inside
 * it).
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum Position {
    After = "after",
    Before = "before",
    Ending = "ending",
    Starting = "starting",
}

/**
 * Specifies objects to be removed from a control based on specific aspects of the object
 * that must all match.
 */
export interface Removal {
    /**
     * Identify items to remove by matching their class.
     */
    "by-class"?: string;
    /**
     * Identify items to remove indicated by their id.
     */
    "by-id"?: string;
    /**
     * Identify items to remove by the name of the item's information object name, e.g. title or
     * prop.
     */
    "by-item-name"?: ItemNameReference;
    /**
     * Identify items remove by matching their assigned name.
     */
    "by-name"?: string;
    /**
     * Identify items to remove by the item's ns, which is the namespace associated with a part,
     * or prop.
     */
    "by-ns"?: string;
    remarks?: string;
}

/**
 * Identify items to remove by the name of the item's information object name, e.g. title or
 * prop.
 *
 * Name of the file before it was encoded as Base64 to be embedded in a resource. This is
 * the name that will be assigned to the file when the file is decoded.
 *
 * A non-colonized name as defined by XML Schema Part 2: Datatypes Second Edition.
 * https://www.w3.org/TR/xmlschema11-2/#NCName.
 *
 * A textual label that provides a sub-type or characterization of the property's name.
 *
 * An identifier for relating distinct sets of properties.
 *
 * A textual label, within a namespace, that identifies a specific attribute,
 * characteristic, or quality of the property's containing object.
 *
 * A textual label that provides a sub-type or characterization of the control.
 *
 * Identifies a control such that it can be referenced in the defining catalog and other
 * OSCAL instances (e.g., profiles).
 *
 * A textual label that provides a characterization of the type, purpose, use or scope of
 * the parameter.
 *
 * (deprecated) Another parameter invoking this one. This construct has been deprecated and
 * should not be used.
 *
 * A unique identifier for the parameter.
 *
 * An optional textual providing a sub-type or characterization of the part's name, or a
 * category to which the part belongs.
 *
 * A unique identifier for the part.
 *
 * A textual label that uniquely identifies the part's semantic type, which exists in a
 * value space qualified by the ns.
 *
 * A textual label that provides a sub-type or characterization of the group.
 *
 * Identifies the group for the purpose of cross-linking within the defining instance or
 * from other instances that reference the catalog.
 *
 * A reference to a role performed by a party.
 *
 * The type of action documented by the assembly, such as an approval.
 *
 * A unique identifier for the role.
 *
 * The relationship type for the mapping entry, which describes the relationship between the
 * effective requirements of the specified source and target sets in the context of the
 * matching-rationale method globaly defined in the provenance unless overwritten locally in
 * the map. The relationship type and the matching-rationale must be used together. However,
 * more than one matching-rationale method may apply to a source and target pair.
 *
 * Selecting a control by its ID given as a literal.
 *
 * Identifies the group.
 *
 * Target location of the addition.
 *
 * A reference to a control with a corresponding id value. When referencing an externally
 * defined control, the Control Identifier Reference must be used in the context of the
 * external / imported OSCAL instance (e.g., uri-reference).
 *
 * Identify items to remove by matching their class.
 *
 * Identify items to remove indicated by their id.
 *
 * Identify items remove by matching their assigned name.
 *
 * A textual label that provides a characterization of the parameter.
 *
 * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
 * and should not be used.
 *
 * An identifier for the parameter.
 *
 * A human-oriented identifier reference to a role performed.
 *
 * A human-oriented reference to a parameter within a control, who's catalog has been
 * imported into the current implementation context.
 *
 * A human-oriented identifier reference to a control statement.
 *
 * Reference to a role by UUID.
 *
 * Points to an assessment objective.
 *
 * Used to constrain the selection to only specificity identified statements.
 *
 * A textual label that provides a sub-type or characterization of the part's name. This can
 * be used to further distinguish or discriminate between the semantics of multiple parts of
 * the same control with the same name and ns.
 *
 * A point to the role-id of the role in which the party is making the log entry.
 *
 * For a party, this can optionally be used to specify the role the actor was performing.
 *
 * A machine-oriented identifier reference for a specific target qualified by the type.
 *
 * The name of the risk metric within the specified system.
 *
 * Describes the type of relationship provided by the link's hypertext reference. This can
 * be an indicator of the link's purpose.
 *
 * Indicates the type of address.
 *
 * The semantic type of the resource.
 *
 * Identifies the implementation status of the control or control objective.
 *
 * Used to indicate the type of object pointed to by the uuid-ref within a subject.
 *
 * Indicates the type of assessment subject, such as a component, inventory, item, location,
 * or party represented by this selection statement.
 *
 * The type of task.
 *
 * A textual label that uniquely identifies the part's semantic type.
 *
 * The reason the objective was given it's status.
 *
 * Identifies the nature of the observation. More than one may be used to further qualify
 * and enable filtering.
 *
 * Identifies whether this is a recommendation, such as from an assessor or tool, or an
 * actual plan accepted by the system owner.
 *
 * Describes the status of the associated risk.
 */
export enum ItemNameReference {
    Link = "link",
    Map = "map",
    Mapping = "mapping",
    Param = "param",
    Part = "part",
    Prop = "prop",
}

/**
 * A parameter setting, to be propagated to points of insertion.
 */
export interface ParameterSetting {
    /**
     * A textual label that provides a characterization of the parameter.
     */
    class?:       string;
    constraints?: Constraint[];
    /**
     * **(deprecated)** Another parameter invoking this one. This construct has been deprecated
     * and should not be used.
     */
    "depends-on"?: string;
    guidelines?:   Guideline[];
    /**
     * A short, placeholder name for the parameter, which can be used as a substitute for a
     * value if no value is assigned.
     */
    label?: string;
    links?: Link[];
    /**
     * An identifier for the parameter.
     */
    "param-id"?: string;
    props?:      Property[];
    /**
     * Describes the purpose and use of a parameter.
     */
    usage?:  string;
    values?: string[];
    select?: Selection;
}

/**
 * A system security plan, such as those described in NIST SP 800-18.
 */
export interface SystemSecurityPlanSSP {
    "back-matter"?:           BackMatter;
    "control-implementation": ControlImplementationClass;
    "import-profile":         ImportProfile;
    metadata:                 DocumentMetadata;
    "system-characteristics": SystemCharacteristics;
    "system-implementation":  SystemImplementation;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this system security plan (SSP) elsewhere in this or other OSCAL instances.
     * The locally defined UUID of the SSP can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance).This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Describes how the system satisfies a set of controls.
 */
export interface ControlImplementationClass {
    /**
     * A statement describing important things to know about how this set of control
     * satisfaction documentation is approached.
     */
    description:                string;
    "implemented-requirements": ControlBasedRequirement[];
    "set-parameters"?:          SetParameterValue[];
}

/**
 * Describes how the system satisfies the requirements of an individual control.
 */
export interface ControlBasedRequirement {
    "by-components"?: ComponentControlImplementation[];
    /**
     * A reference to a control with a corresponding id value. When referencing an externally
     * defined control, the Control Identifier Reference must be used in the context of the
     * external / imported OSCAL instance (e.g., uri-reference).
     */
    "control-id":         string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    "set-parameters"?:    SetParameterValue[];
    statements?:          SpecificControlStatement[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this control requirement elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the control requirement can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * Defines how the referenced component implements a set of controls.
 */
export interface ComponentControlImplementation {
    /**
     * A machine-oriented identifier reference to the component that is implementing a given
     * control.
     */
    "component-uuid": string;
    /**
     * An implementation statement that describes how a control or a control statement is
     * implemented within the referenced system component.
     */
    description: string;
    /**
     * Identifies content intended for external consumption, such as with leveraged
     * organizations.
     */
    export?:                  Export;
    "implementation-status"?: ImplementationStatus;
    inherited?:               InheritedControlImplementation[];
    links?:                   Link[];
    props?:                   Property[];
    remarks?:                 string;
    "responsible-roles"?:     ResponsibleRole[];
    satisfied?:               SatisfiedControlImplementationResponsibility[];
    "set-parameters"?:        SetParameterValue[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this by-component entry elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the by-component entry can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid: string;
}

/**
 * Identifies content intended for external consumption, such as with leveraged
 * organizations.
 */
export interface Export {
    /**
     * An implementation statement that describes the aspects of the control or control
     * statement implementation that can be available to another system leveraging this system.
     */
    description?:      string;
    links?:            Link[];
    props?:            Property[];
    provided?:         ProvidedControlImplementation[];
    remarks?:          string;
    responsibilities?: ControlImplementationResponsibility[];
}

/**
 * Describes a capability which may be inherited by a leveraging system.
 */
export interface ProvidedControlImplementation {
    /**
     * An implementation statement that describes the aspects of the control or control
     * statement implementation that can be provided to another system leveraging this system.
     */
    description:          string;
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this provided entry elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the provided entry can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Describes a control implementation responsibility imposed on a leveraging system.
 */
export interface ControlImplementationResponsibility {
    /**
     * An implementation statement that describes the aspects of the control or control
     * statement implementation that a leveraging system must implement to satisfy the control
     * provided by a leveraged system.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    /**
     * A machine-oriented identifier reference to an inherited control implementation that a
     * leveraging system is inheriting from a leveraged system.
     */
    "provided-uuid"?:     string;
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this responsibility elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the responsibility can be used to reference the data item locally or
     * globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject,
     * which means it should be consistently used to identify the same subject across revisions
     * of the document.
     */
    uuid: string;
}

/**
 * Describes a control implementation inherited by a leveraging system.
 */
export interface InheritedControlImplementation {
    /**
     * An implementation statement that describes the aspects of a control or control statement
     * implementation that a leveraging system is inheriting from a leveraged system.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    /**
     * A machine-oriented identifier reference to an inherited control implementation that a
     * leveraging system is inheriting from a leveraged system.
     */
    "provided-uuid"?:     string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this inherited entry elsewhere in this or other OSCAL instances. The locally
     * defined UUID of the inherited control implementation can be used to reference the data
     * item locally or globally (e.g., in an imported OSCAL instance). This UUID should be
     * assigned per-subject, which means it should be consistently used to identify the same
     * subject across revisions of the document.
     */
    uuid: string;
}

/**
 * Describes how this system satisfies a responsibility imposed by a leveraged system.
 */
export interface SatisfiedControlImplementationResponsibility {
    /**
     * An implementation statement that describes the aspects of a control or control statement
     * implementation that a leveraging system is implementing based on a requirement from a
     * leveraged system.
     */
    description: string;
    links?:      Link[];
    props?:      Property[];
    remarks?:    string;
    /**
     * A machine-oriented identifier reference to a control implementation that satisfies a
     * responsibility imposed by a leveraged system.
     */
    "responsibility-uuid"?: string;
    "responsible-roles"?:   ResponsibleRole[];
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this satisfied control implementation entry elsewhere in this or other OSCAL
     * instances. The locally defined UUID of the control implementation can be used to
     * reference the data item locally or globally (e.g., in an imported OSCAL instance). This
     * UUID should be assigned per-subject, which means it should be consistently used to
     * identify the same subject across revisions of the document.
     */
    uuid: string;
}

/**
 * Identifies which statements within a control are addressed.
 */
export interface SpecificControlStatement {
    "by-components"?:     ComponentControlImplementation[];
    links?:               Link[];
    props?:               Property[];
    remarks?:             string;
    "responsible-roles"?: ResponsibleRole[];
    /**
     * A human-oriented identifier reference to a control statement.
     */
    "statement-id": string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this control statement elsewhere in this or other OSCAL instances. The UUID
     * of the control statement in the source OSCAL instance is sufficient to reference the data
     * item locally or globally (e.g., in an imported OSCAL instance).
     */
    uuid: string;
}

/**
 * Used to import the OSCAL profile representing the system's control baseline.
 */
export interface ImportProfile {
    /**
     * A resolvable URL reference to the profile or catalog to use as the system's control
     * baseline.
     */
    href:     string;
    remarks?: string;
}

/**
 * Contains the characteristics of the system, such as its name, purpose, and security
 * impact level.
 */
export interface SystemCharacteristics {
    "authorization-boundary": AuthorizationBoundary;
    "data-flow"?:             DataFlow;
    "date-authorized"?:       string;
    /**
     * A summary of the system.
     */
    description:              string;
    links?:                   Link[];
    "network-architecture"?:  NetworkArchitecture;
    props?:                   Property[];
    remarks?:                 string;
    "responsible-parties"?:   ResponsibleParty[];
    "security-impact-level"?: SecurityImpactLevel;
    /**
     * The overall information system sensitivity categorization, such as defined by FIPS-199.
     */
    "security-sensitivity-level"?: string;
    status:                        SystemCharacteristicsStatus;
    "system-ids":                  SystemIdentification[];
    "system-information":          SystemInformation;
    /**
     * The full name of the system.
     */
    "system-name": string;
    /**
     * A short name for the system, such as an acronym, that is suitable for display in a data
     * table or summary list.
     */
    "system-name-short"?: string;
}

/**
 * A description of this system's authorization boundary, optionally supplemented by
 * diagrams that illustrate the authorization boundary.
 */
export interface AuthorizationBoundary {
    /**
     * A summary of the system's authorization boundary.
     */
    description: string;
    diagrams?:   Diagram[];
    links?:      Link[];
    props?:      Property[];
    remarks?:    string;
}

/**
 * A graphic that provides a visual representation the system, or some aspect of it.
 */
export interface Diagram {
    /**
     * A brief caption to annotate the diagram.
     */
    caption?: string;
    /**
     * A summary of the diagram.
     */
    description?: string;
    links?:       Link[];
    props?:       Property[];
    remarks?:     string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this diagram elsewhere in this or other OSCAL instances. The locally defined
     * UUID of the diagram can be used to reference the data item locally or globally (e.g., in
     * an imported OSCAL instance). This UUID should be assigned per-subject, which means it
     * should be consistently used to identify the same subject across revisions of the document.
     */
    uuid: string;
}

/**
 * A description of the logical flow of information within the system and across its
 * boundaries, optionally supplemented by diagrams that illustrate these flows.
 */
export interface DataFlow {
    /**
     * A summary of the system's data flow.
     */
    description: string;
    diagrams?:   Diagram[];
    links?:      Link[];
    props?:      Property[];
    remarks?:    string;
}

/**
 * A description of the system's network architecture, optionally supplemented by diagrams
 * that illustrate the network architecture.
 */
export interface NetworkArchitecture {
    /**
     * A summary of the system's network architecture.
     */
    description: string;
    diagrams?:   Diagram[];
    links?:      Link[];
    props?:      Property[];
    remarks?:    string;
}

/**
 * The overall level of expected impact resulting from unauthorized disclosure,
 * modification, or loss of access to information.
 */
export interface SecurityImpactLevel {
    /**
     * A target-level of availability for the system, based on the sensitivity of information
     * within the system.
     */
    "security-objective-availability": string;
    /**
     * A target-level of confidentiality for the system, based on the sensitivity of information
     * within the system.
     */
    "security-objective-confidentiality": string;
    /**
     * A target-level of integrity for the system, based on the sensitivity of information
     * within the system.
     */
    "security-objective-integrity": string;
}

/**
 * Describes the operational status of the system.
 */
export interface SystemCharacteristicsStatus {
    remarks?: string;
    /**
     * The current operating status.
     */
    state: SystemCharacteristicStatusState;
}

/**
 * The current operating status.
 *
 * A label that indicates the nature of a resource, as a data serialization or format.
 *
 * A non-empty string with leading and trailing whitespace disallowed. Whitespace is: U+9,
 * U+10, U+32 or [
 * ]+
 *
 * In case where the href points to a back-matter/resource, this value will indicate the URI
 * fragment to append to any rlink associated with the resource. This value MUST be URI
 * encoded.
 *
 * Indicates the value of the attribute, characteristic, or quality.
 *
 * A formal (executable) expression of a constraint.
 *
 * A parameter value or set of values.
 *
 * A single line of an address.
 *
 * City, town or geographical region for the mailing address.
 *
 * The ISO 3166-1 alpha-2 country code for the mailing address.
 *
 * Postal or ZIP code for mailing address.
 *
 * State, province or analogous geographical region for a mailing address.
 *
 * The OSCAL model version the document was authored against and will conform to as valid.
 *
 * The full name of the party. This is typically the legal name associated with the party.
 *
 * A short common name, abbreviation, or acronym for the party.
 *
 * Used to distinguish a specific revision of an OSCAL document from other previous and
 * future versions.
 *
 * A short common name, abbreviation, or acronym for the role.
 *
 * A reference to an identified subject that is of the specified type .
 *
 * A glob expression matching the IDs of one or more controls to be selected.
 *
 * The capability's human-readable name.
 *
 * The common name of the protocol, which should be the appropriate "service name" from the
 * IANA Service Name and Transport Protocol Port Number Registry.
 *
 * A target-level of availability for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of confidentiality for the system, based on the sensitivity of information
 * within the system.
 *
 * A target-level of integrity for the system, based on the sensitivity of information
 * within the system.
 *
 * The overall information system sensitivity categorization, such as defined by FIPS-199.
 *
 * The prescribed base (Confidentiality, Integrity, or Availability) security impact level.
 *
 * The selected (Confidentiality, Integrity, or Availability) security impact level.
 *
 * A human-oriented, globally unique identifier qualified by the given identification system
 * used, such as NIST SP 800-60. This identifier has cross-instance scope and can be used to
 * reference this system elsewhere in this or other OSCAL instances. This id should be
 * assigned per-subject, which means it should be consistently used to identify the same
 * subject across revisions of the document.
 *
 * The full name of the system.
 *
 * A short name for the system, such as an acronym, that is suitable for display in a data
 * table or summary list.
 *
 * Describes a function performed for a given authorized privilege by this user class.
 *
 * A short common name, abbreviation, or acronym for the user.
 *
 * Indicates the value of the facet.
 *
 * The digest method by which a hash is derived.
 *
 * Indicates the type of phone number.
 *
 * The method used to determine the coverage value.
 *
 * A category describing the purpose of the component.
 *
 * Identifies how the observation was made.
 */
export enum SystemCharacteristicStatusState {
    Disposition = "disposition",
    Operational = "operational",
    Other = "other",
    UnderDevelopment = "under-development",
    UnderMajorModification = "under-major-modification",
}

/**
 * Contains details about all information types that are stored, processed, or transmitted
 * by the system, such as privacy information, and those defined in NIST SP 800-60.
 */
export interface SystemInformation {
    "information-types": InformationType[];
    links?:              Link[];
    props?:              Property[];
}

/**
 * Contains details about one information type that is stored, processed, or transmitted by
 * the system, such as privacy information, and those defined in NIST SP 800-60.
 */
export interface InformationType {
    "availability-impact"?:    ImpactLevel;
    categorizations?:          InformationTypeCategorization[];
    "confidentiality-impact"?: ImpactLevel;
    /**
     * A summary of how this information type is used within the system.
     */
    description:         string;
    "integrity-impact"?: ImpactLevel;
    links?:              Link[];
    props?:              Property[];
    /**
     * A human readable name for the information type. This title should be meaningful within
     * the context of the system.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope that can be used
     * to reference this information type elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the information type can be used to reference the data item
     * locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned
     * per-subject, which means it should be consistently used to identify the same subject
     * across revisions of the document.
     */
    uuid?: string;
}

/**
 * The expected level of impact resulting from the described information.
 */
export interface ImpactLevel {
    "adjustment-justification"?: string;
    base:                        string;
    links?:                      Link[];
    props?:                      Property[];
    selected?:                   string;
}

/**
 * A set of information type identifiers qualified by the given identification system used,
 * such as NIST SP 800-60.
 */
export interface InformationTypeCategorization {
    "information-type-ids"?: string[];
    /**
     * Specifies the information type identification system used.
     */
    system: string;
}

/**
 * Provides information as to how the system is implemented.
 */
export interface SystemImplementation {
    components:                  AssessmentAssetsComponent[];
    "inventory-items"?:          InventoryItem[];
    "leveraged-authorizations"?: LeveragedAuthorization[];
    links?:                      Link[];
    props?:                      Property[];
    remarks?:                    string;
    users?:                      SystemUser[];
}

/**
 * A description of another authorized system from which this system inherits capabilities
 * that satisfy security requirements. Another term for this concept is a common control
 * provider.
 */
export interface LeveragedAuthorization {
    "date-authorized": string;
    links?:            Link[];
    /**
     * A machine-oriented identifier reference to the party that manages the leveraged system.
     */
    "party-uuid": string;
    props?:       Property[];
    remarks?:     string;
    /**
     * A human readable name for the leveraged authorization in the context of the system.
     */
    title: string;
    /**
     * A machine-oriented, globally unique identifier with cross-instance scope and can be used
     * to reference this leveraged authorization elsewhere in this or other OSCAL instances. The
     * locally defined UUID of the leveraged authorization can be used to reference the data
     * item locally or globally (e.g., in an imported OSCAL instance). This UUID should be
     * assigned per-subject, which means it should be consistently used to identify the same
     * subject across revisions of the document.
     */
    uuid: string;
}
