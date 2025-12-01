// Code generated from JSON Schema using quicktype. DO NOT EDIT.
// To parse and unparse this JSON data, add this code to your project and do:
//
//    hdfResults, err := UnmarshalHdfResults(bytes)
//    bytes, err = hdfResults.Marshal()

package hdf

import "bytes"
import "errors"
import "time"

import "encoding/json"

func UnmarshalHdfResults(data []byte) (HdfResults, error) {
	var r HdfResults
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HdfResults) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// The top level value containing all assessment results.
type HdfResults struct {
	// Information about the tool that generated this file.
	Generator *Generator `json:"generator"`
	// Unique identifier for this assessment run.
	ID *string `json:"id,omitempty"`
	// Cryptographic integrity information for verifying this file.
	Integrity *Integrity `json:"integrity"`
	// Information on the platform the run from the tool that generated the findings was from.
	Platform Platform `json:"platform"`
	// Information on the baselines that were evaluated, including findings.
	Profiles []EvaluatedBaseline `json:"profiles"`
	// Statistics for the assessment run, including duration and result counts.
	Statistics Statistics `json:"statistics"`
	// The target systems that were assessed. Supports multiple targets of different types.
	Targets []Target `json:"targets,omitempty"`
	// When this assessment was executed.
	Timestamp *time.Time `json:"timestamp,omitempty"`
	// Version number of the tool that generated the findings. Example: '5.22.3' is a version of
	// Chef InSpec.
	Version string `json:"version"`
}

// Information about the tool that generated this HDF file.
type Generator struct {
	// The name of the tool that generated this file. Example: 'Chef InSpec'.
	Name string `json:"name"`
	// The version of the tool. Example: '5.22.3'.
	Version string `json:"version"`
}

// Cryptographic integrity information for verifying the HDF file has not been tampered
// with. If algorithm is provided, checksum must also be provided, and vice versa.
type Integrity struct {
	// The hash algorithm used for the checksum.
	Algorithm *Algorithm `json:"algorithm,omitempty"`
	// The checksum value.
	Checksum *string `json:"checksum,omitempty"`
	// Optional cryptographic signature.
	Signature *string `json:"signature"`
	// Identifier of who signed this file.
	SignedBy *string `json:"signed_by"`
}

// Information on the platform the run from the tool that generated the findings was from.
type Platform struct {
	// The name of the platform this was run on.
	Name string `json:"name"`
	// The version of the platform this was run on.
	Release string `json:"release"`
	// The id of the target. Example: the name and version of the operating system were not
	// sufficient to identify the platform so a release identifier can additionally be provided
	// like '21H2' for the release version of MS Windows 10.
	TargetID *string `json:"target_id"`
}

// Information on a baseline that was evaluated, including any findings.
type EvaluatedBaseline struct {
	// The input(s) or attribute(s) used in the run.
	Attributes []map[string]interface{} `json:"attributes"`
	// The set of requirements including any findings.
	Controls []EvaluatedRequirement `json:"controls"`
	// The copyright holder(s).
	Copyright *string `json:"copyright"`
	// The email address or other contact information of the copyright holder(s).
	CopyrightEmail *string `json:"copyright_email"`
	// The set of dependencies this baseline depends on.
	Depends []Dependency `json:"depends"`
	// The description - should be more detailed than the summary.
	Description *string `json:"description"`
	// A set of descriptions for the requirement groups.
	Groups []RequirementGroup `json:"groups"`
	// The version of InSpec used to execute this baseline.
	InspecVersion *string `json:"inspec_version"`
	// The copyright license. Example: 'Apache-2.0'.
	License *string `json:"license"`
	// The maintainer(s).
	Maintainer *string `json:"maintainer"`
	// The name - must be unique.
	Name string `json:"name"`
	// The name of the parent baseline if this is a dependency of another.
	ParentProfile *string `json:"parent_profile"`
	// The SHA-256 checksum of the baseline.
	Sha256 *string `json:"sha256,omitempty"`
	// The SHA-512 checksum of the baseline (optional).
	Sha512 *string `json:"sha512"`
	// The reason for skipping if it was skipped.
	SkipMessage *string `json:"skip_message"`
	// The status. Example: 'loaded'.
	Status *string `json:"status"`
	// The reason for the status. Example: why it was skipped or failed to load.
	StatusMessage *string `json:"status_message"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.
	Summary *string `json:"summary"`
	// The set of supported platform targets.
	Supports []SupportedPlatform `json:"supports"`
	// The title - should be human readable.
	Title *string `json:"title"`
	// The version of the baseline.
	Version *string `json:"version"`
}

// A requirement that has been evaluated, including any findings.
type EvaluatedRequirement struct {
	// Attestation information if this requirement has been manually attested.
	AttestationData *AttestationData `json:"attestation_data"`
	// The raw source code of the requirement. Note that if this is an overlay, it does not
	// include the underlying source code.
	Code *string `json:"code"`
	// The description for the overarching requirement.
	Desc *string `json:"desc"`
	// A set of additional descriptions. Example: the 'fix' text.
	Descriptions []RequirementDescription `json:"descriptions"`
	// The requirement identifier. Example: 'SV-238196'.
	ID string `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).
	Impact float64 `json:"impact"`
	// The final status of this requirement after all post-processing (attestations, waivers) is
	// applied.
	OverallStatus *OverallStatus `json:"overall_status"`
	// The set of references to external documents.
	Refs []Reference `json:"refs"`
	// The set of all tests within the requirement and their results.
	Results []RequirementResult `json:"results"`
	// The explicit location of the requirement within the source code.
	SourceLocation SourceLocation `json:"source_location"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.
	Tags map[string]interface{} `json:"tags"`
	// The title - is nullable.
	Title *string `json:"title"`
	// Waiver information if this requirement has been waived.
	WaiverData *WaiverData `json:"waiver_data"`
}

// Data for a manual attestation that overrides automated assessment results.
type AttestationData struct {
	// The ID of the requirement being attested.
	ControlID string `json:"control_id"`
	// Explanation of the attestation.
	Explanation string `json:"explanation"`
	// How often this attestation should be reviewed. Example: 'annually', 'quarterly'.
	Frequency string `json:"frequency"`
	// The attested status.
	Status AttestationStatus `json:"status"`
	// When this attestation was last updated.
	Updated string `json:"updated"`
	// Who last updated this attestation.
	UpdatedBy string `json:"updated_by"`
}

// A labeled description for a requirement, such as fix text or check instructions.
type RequirementDescription struct {
	// The text of the description.
	Data string `json:"data"`
	// The type of description. Examples: 'fix', 'check', 'rationale'.
	Label string `json:"label"`
}

// A reference to an external document.
//
// A reference using the 'ref' field.
//
// A URL pointing at the reference.
//
// A URI pointing at the reference.
type Reference struct {
	Ref *Ref    `json:"ref"`
	URL *string `json:"url,omitempty"`
	URI *string `json:"uri,omitempty"`
}

// A test within a requirement and its results and findings such as how long it took to run.
type RequirementResult struct {
	// The stacktrace/backtrace of the exception if one occurred.
	Backtrace []string `json:"backtrace"`
	// A description of this test. Example: 'limits.conf * is expected to include ["hard",
	// "maxlogins", "10"]'.
	CodeDesc string `json:"code_desc"`
	// The type of exception if an exception was thrown.
	Exception *string `json:"exception"`
	// An explanation of the test status - usually only provided when the test fails.
	Message *string `json:"message"`
	// The resource used in the test. Example: 'file', 'command', 'service'.
	Resource *string `json:"resource"`
	// The unique identifier of the resource. Example: '/etc/passwd'.
	ResourceID *string `json:"resource_id"`
	// The execution time in seconds for the test.
	RunTime *float64 `json:"run_time"`
	// An explanation of why the test was not reviewed or not applicable.
	SkipMessage *string `json:"skip_message"`
	// The time at which the test started.
	StartTime string `json:"start_time"`
	// The status of this test within the requirement. Example: 'failed'.
	Status *ResultStatus `json:"status"`
}

// The explicit location of the requirement within the source code.
type SourceLocation struct {
	// The line on which this requirement is located.
	Line *float64 `json:"line"`
	// Path to the file that this requirement originates from.
	Ref *string `json:"ref"`
}

// Data associated with a waiver that exempts a requirement from assessment.
type WaiverData struct {
	// The date when this waiver expires.
	ExpirationDate *string `json:"expiration_date"`
	// The justification for the waiver.
	Justification *string `json:"justification"`
	// A message associated with the waiver.
	Message *string `json:"message"`
	// Whether to run the requirement despite the waiver.
	Run *bool `json:"run"`
	// Indicates if the requirement was skipped due to this waiver.
	SkippedDueToWaiver *SkippedDueToWaiver `json:"skipped_due_to_waiver"`
}

// A dependency for a baseline. Can include relative paths or URLs for where to find the
// dependency.
type Dependency struct {
	// The branch name for a git repo.
	Branch *string `json:"branch"`
	// The 'user/profilename' attribute for an Automate server.
	Compliance *string `json:"compliance"`
	// The location of the git repo. Example:
	// 'https://github.com/my-org/ubuntu-22.04-stig-baseline.git'.
	Git *string `json:"git"`
	// The name or assigned alias.
	Name *string `json:"name"`
	// The relative path if the dependency is locally available.
	Path *string `json:"path"`
	// The status. Should be: 'loaded', 'failed', or 'skipped'.
	Status *string `json:"status"`
	// The reason for the status if it is 'failed' or 'skipped'.
	StatusMessage *string `json:"status_message"`
	// The 'user/profilename' attribute for a Supermarket server.
	Supermarket *string `json:"supermarket"`
	// The address of the dependency.
	URL *string `json:"url"`
}

// Describes a group of requirements, such as those defined in a single file.
type RequirementGroup struct {
	// Deprecated: use 'requirements' instead. The set of controls as specified by their ids in
	// this group.
	Controls []string `json:"controls,omitempty"`
	// The unique identifier for the group. Example: the relative path to the file specifying
	// the requirements.
	ID string `json:"id"`
	// The set of requirements as specified by their ids in this group. Example: 'SV-238196'.
	Requirements []string `json:"requirements,omitempty"`
	// The title of the group - should be human readable.
	Title *string `json:"title"`
}

// A supported platform target. Example: the platform name being 'ubuntu'.
type SupportedPlatform struct {
	// Deprecated in favor of platform-family.
	OSFamily *string `json:"os-family"`
	// Deprecated in favor of platform-name.
	OSName *string `json:"os-name"`
	// The location of the platform. Can be: 'os', 'aws', 'azure', or 'gcp'.
	Platform *string `json:"platform"`
	// The platform family. Example: 'redhat'.
	PlatformFamily *string `json:"platform-family"`
	// The platform name - can include wildcards. Example: 'debian'.
	PlatformName *string `json:"platform-name"`
	// The release of the platform. Example: '20.04' for 'ubuntu'.
	Release *string `json:"release"`
}

// Statistics for the assessment run, including duration and result counts.
type Statistics struct {
	// Breakdowns of requirement statistics by result status.
	Controls *StatisticHash `json:"controls"`
	// How long (in seconds) this assessment run took.
	Duration *float64 `json:"duration"`
}

// Statistics for requirement results, grouped by status.
type StatisticHash struct {
	// Statistics for requirements that encountered an error during assessment.
	Error *PurpleStatisticBlock `json:"error"`
	// Statistics for requirements that failed.
	Failed *FluffyStatisticBlock `json:"failed"`
	// Statistics for requirements that are not applicable to the target.
	NotApplicable *FluffyStatisticBlock `json:"not_applicable"`
	// Statistics for requirements that were not reviewed (manual check required).
	NotReviewed *FluffyStatisticBlock `json:"not_reviewed"`
	// Statistics for requirements that passed.
	Passed *FluffyStatisticBlock `json:"passed"`
	// Deprecated: use 'not_applicable' or 'not_reviewed' instead. Statistics for requirements
	// that were skipped.
	Skipped *FluffyStatisticBlock `json:"skipped"`
}

// Statistics for a given item, such as the total count.
type PurpleStatisticBlock struct {
	// The total count. Example: the total number of requirements in a given category for a run.
	Total float64 `json:"total"`
}

// Statistics for a given item, such as the total count.
type FluffyStatisticBlock struct {
	// The total count. Example: the total number of requirements in a given category for a run.
	Total float64 `json:"total"`
}

// A scan target. Uses discriminated union pattern with 'type' field as discriminator.
//
// A physical or virtual server, workstation, or network device.
//
// A static container image (not running).
//
// A running container instance.
//
// A container orchestration platform (Kubernetes, OpenShift, ECS, etc.) or workloads
// running on it.
//
// A cloud provider account (AWS account, Azure subscription, GCP project).
//
// A specific cloud resource (EC2 instance, S3 bucket, Azure VM, etc.).
//
// A code repository (for SAST tools).
//
// A running application or API (for DAST tools).
//
// A software artifact or dependency (for SCA tools).
//
// A network segment or network device.
//
// A database instance.
type Target struct {
	// Fully qualified domain name.
	FQDN *string `json:"fqdn"`
	// IP address of the host.
	IPAddress *string `json:"ip_address"`
	// MAC address of the host.
	MACAddress *string `json:"mac_address"`
	// Human-readable name for this target.
	Name string `json:"name"`
	// Operating system name.
	OSName *string `json:"os_name"`
	// Operating system version.
	OSVersion *string `json:"os_version"`
	// Target type discriminator.
	Type Type `json:"type"`
	// Image digest for immutable reference. Example: 'sha256:abc123...'.
	Digest *string `json:"digest"`
	// Container image ID.
	ImageID *string `json:"image_id"`
	// Container registry. Example: 'docker.io'.
	Registry *string `json:"registry"`
	// Repository name. Example: 'library/nginx'.
	Repository *string `json:"repository"`
	// Image tag. Example: '1.25'.
	Tag *string `json:"tag"`
	// Running container ID.
	ContainerID *string `json:"container_id"`
	// Image the container was started from.
	Image *string `json:"image"`
	// Container runtime. Example: 'docker', 'containerd', 'cri-o'.
	Runtime *string `json:"runtime"`
	// Cluster name.
	ClusterName *string `json:"cluster_name"`
	// Namespace within the cluster, if applicable.
	Namespace *string `json:"namespace"`
	// Platform type. Example: 'kubernetes', 'openshift', 'ecs', 'docker-swarm'.
	PlatformType *string `json:"platform_type"`
	// Platform version.
	//
	// Application version.
	//
	// Package version.
	//
	// Database version.
	Version *string `json:"version"`
	// Cloud account identifier. Example: AWS account ID, Azure subscription ID.
	AccountID *string `json:"account_id"`
	// Cloud provider.
	Provider *Provider `json:"provider"`
	// Cloud region, if applicable.
	//
	// Cloud region where the resource resides.
	Region *string `json:"region"`
	// Amazon Resource Name (AWS only).
	Arn *string `json:"arn"`
	// Provider-specific resource identifier.
	ResourceID *string `json:"resource_id"`
	// Type of cloud resource. Example: 'ec2:instance', 's3:bucket'.
	ResourceType *string `json:"resource_type"`
	// Branch that was scanned.
	Branch *string `json:"branch"`
	// Commit SHA that was scanned.
	Commit *string `json:"commit"`
	// Repository URL.
	//
	// Application URL (for DAST tools).
	URL *string `json:"url"`
	// Environment. Example: 'production', 'staging', 'development'.
	Environment *string `json:"environment"`
	// Package checksum for verification.
	Checksum *string `json:"checksum"`
	// Package manager. Example: 'npm', 'maven', 'pip', 'nuget'.
	PackageManager *string `json:"package_manager"`
	// Package name.
	PackageName *string `json:"package_name"`
	// Network CIDR block.
	CIDR *string `json:"cidr"`
	// Network gateway address.
	Gateway *string `json:"gateway"`
	// Database engine. Example: 'postgresql', 'mysql', 'oracle', 'mssql'.
	Engine *string `json:"engine"`
	// Database host.
	Host *string `json:"host"`
	// Database port.
	Port *int64 `json:"port"`
}

// The hash algorithm used for the checksum.
type Algorithm string

const (
	Sha256 Algorithm = "sha256"
	Sha384 Algorithm = "sha384"
	Sha512 Algorithm = "sha512"
)

// The attested status.
type AttestationStatus string

const (
	AttestationStatusFailed AttestationStatus = "failed"
	AttestationStatusPassed AttestationStatus = "passed"
)

// The final status of a requirement after all post-processing (attestations, waivers) is
// applied.
type OverallStatus string

const (
	OverallStatusError         OverallStatus = "error"
	OverallStatusFailed        OverallStatus = "failed"
	OverallStatusNotApplicable OverallStatus = "not_applicable"
	OverallStatusNotReviewed   OverallStatus = "not_reviewed"
	OverallStatusPassed        OverallStatus = "passed"
)

// The status of an individual test result. 'not_applicable' indicates the requirement does
// not apply to the target. 'not_reviewed' indicates the requirement was not assessed (e.g.,
// requires manual verification). 'skipped' is deprecated; use 'not_applicable' (impact=0)
// or 'not_reviewed' (impact>0) instead.
type ResultStatus string

const (
	ResultStatusError         ResultStatus = "error"
	ResultStatusFailed        ResultStatus = "failed"
	ResultStatusNotApplicable ResultStatus = "not_applicable"
	ResultStatusNotReviewed   ResultStatus = "not_reviewed"
	ResultStatusPassed        ResultStatus = "passed"
	Skipped                   ResultStatus = "skipped"
)

type Provider string

const (
	Aws   Provider = "aws"
	Azure Provider = "azure"
	Gcp   Provider = "gcp"
	Oci   Provider = "oci"
	Other Provider = "other"
)

type Type string

const (
	Application       Type = "application"
	Artifact          Type = "artifact"
	CloudAccount      Type = "cloud_account"
	CloudResource     Type = "cloud_resource"
	ContainerImage    Type = "container_image"
	ContainerInstance Type = "container_instance"
	ContainerPlatform Type = "container_platform"
	Database          Type = "database"
	Host              Type = "host"
	Network           Type = "network"
	Repository        Type = "repository"
)

type Ref struct {
	AnythingMapArray []map[string]interface{}
	String           *string
}

func (x *Ref) UnmarshalJSON(data []byte) error {
	x.AnythingMapArray = nil
	object, err := unmarshalUnion(data, nil, nil, nil, &x.String, true, &x.AnythingMapArray, false, nil, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
	}
	return nil
}

func (x *Ref) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, nil, x.String, x.AnythingMapArray != nil, x.AnythingMapArray, false, nil, false, nil, false, nil, false)
}

// Indicates if the requirement was skipped due to this waiver.
type SkippedDueToWaiver struct {
	Bool   *bool
	String *string
}

func (x *SkippedDueToWaiver) UnmarshalJSON(data []byte) error {
	object, err := unmarshalUnion(data, nil, nil, &x.Bool, &x.String, false, nil, false, nil, false, nil, false, nil, true)
	if err != nil {
		return err
	}
	if object {
	}
	return nil
}

func (x *SkippedDueToWaiver) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, x.Bool, x.String, false, nil, false, nil, false, nil, false, nil, true)
}

func unmarshalUnion(data []byte, pi **int64, pf **float64, pb **bool, ps **string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) (bool, error) {
	if pi != nil {
		*pi = nil
	}
	if pf != nil {
		*pf = nil
	}
	if pb != nil {
		*pb = nil
	}
	if ps != nil {
		*ps = nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}

	switch v := tok.(type) {
	case json.Number:
		if pi != nil {
			i, err := v.Int64()
			if err == nil {
				*pi = &i
				return false, nil
			}
		}
		if pf != nil {
			f, err := v.Float64()
			if err == nil {
				*pf = &f
				return false, nil
			}
			return false, errors.New("Unparsable number")
		}
		return false, errors.New("Union does not contain number")
	case float64:
		return false, errors.New("Decoder should not return float64")
	case bool:
		if pb != nil {
			*pb = &v
			return false, nil
		}
		return false, errors.New("Union does not contain bool")
	case string:
		if haveEnum {
			return false, json.Unmarshal(data, pe)
		}
		if ps != nil {
			*ps = &v
			return false, nil
		}
		return false, errors.New("Union does not contain string")
	case nil:
		if nullable {
			return false, nil
		}
		return false, errors.New("Union does not contain null")
	case json.Delim:
		if v == '{' {
			if haveObject {
				return true, json.Unmarshal(data, pc)
			}
			if haveMap {
				return false, json.Unmarshal(data, pm)
			}
			return false, errors.New("Union does not contain object")
		}
		if v == '[' {
			if haveArray {
				return false, json.Unmarshal(data, pa)
			}
			return false, errors.New("Union does not contain array")
		}
		return false, errors.New("Cannot handle delimiter")
	}
	return false, errors.New("Cannot unmarshal union")
}

func marshalUnion(pi *int64, pf *float64, pb *bool, ps *string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) ([]byte, error) {
	if pi != nil {
		return json.Marshal(*pi)
	}
	if pf != nil {
		return json.Marshal(*pf)
	}
	if pb != nil {
		return json.Marshal(*pb)
	}
	if ps != nil {
		return json.Marshal(*ps)
	}
	if haveArray {
		return json.Marshal(pa)
	}
	if haveObject {
		return json.Marshal(pc)
	}
	if haveMap {
		return json.Marshal(pm)
	}
	if haveEnum {
		return json.Marshal(pe)
	}
	if nullable {
		return json.Marshal(nil)
	}
	return nil, errors.New("Union must not be null")
}
