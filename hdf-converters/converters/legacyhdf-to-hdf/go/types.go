// Package legacyhdf converts HDF v1.0 (legacy) to HDF v2.0 format.
//
// V1 types are defined here manually. The official v1.0 schema (exec-json.json)
// exists in heimdall2/libs/inspecjs/schemas/ but is not yet integrated into
// hdf-libs' type generation pipeline.
// V2 types are imported from github.com/mitre/hdf-schema.
package legacyhdf

// V1Result represents a test result in HDF v1.0 format.
type V1Result struct {
	Status         string      `json:"status"`
	CodeDesc       *string     `json:"code_desc,omitempty"`
	RunTime        *float64    `json:"run_time,omitempty"`
	StartTime      *string     `json:"start_time,omitempty"`
	Message        *string     `json:"message,omitempty"`
	Exception      *string     `json:"exception,omitempty"`
	Backtrace      []string    `json:"backtrace,omitempty"`
	ResourceClass  *string     `json:"resource_class,omitempty"`
	ResourceParams *string     `json:"resource_params,omitempty"`
	ResourceID     *string     `json:"resource_id,omitempty"`
	SkipMessage    *string     `json:"skip_message,omitempty"`
}

// V1SourceLocation represents the source location of a control.
type V1SourceLocation struct {
	Ref  *string `json:"ref,omitempty"`
	Line *int    `json:"line,omitempty"`
}

// V1Description represents a labeled description.
type V1Description struct {
	Label string `json:"label"`
	Data  string `json:"data"`
}

// V1Control represents a control in HDF v1.0 format.
type V1Control struct {
	ID             string                 `json:"id"`
	Title          *string                `json:"title,omitempty"`
	Desc           *string                `json:"desc,omitempty"`
	Descriptions   []V1Description        `json:"descriptions,omitempty"`
	Impact         float64                `json:"impact"`
	Refs           []interface{}          `json:"refs,omitempty"`
	Tags           map[string]interface{} `json:"tags,omitempty"`
	Code           *string                `json:"code,omitempty"`
	SourceLocation *V1SourceLocation      `json:"source_location,omitempty"`
	WaiverData     map[string]interface{} `json:"waiver_data,omitempty"`
	Results        []V1Result             `json:"results,omitempty"`
	Status         *string                `json:"status,omitempty"`
}

// V1Group represents a group of controls in HDF v1.0 format.
type V1Group struct {
	ID       string   `json:"id"`
	Title    *string  `json:"title,omitempty"`
	Controls []string `json:"controls"`
}

// V1Dependency represents a profile dependency in HDF v1.0 format.
type V1Dependency struct {
	Name        *string `json:"name,omitempty"`
	URL         *string `json:"url,omitempty"`
	Path        *string `json:"path,omitempty"`
	Git         *string `json:"git,omitempty"`
	Branch      *string `json:"branch,omitempty"`
	Tag         *string `json:"tag,omitempty"`
	Commit      *string `json:"commit,omitempty"`
	Version     *string `json:"version,omitempty"`
	Supermarket *string `json:"supermarket,omitempty"`
	Compliance  *string `json:"compliance,omitempty"`
	Status      *string `json:"status,omitempty"`
	SkipMessage *string `json:"skip_message,omitempty"`
}

// V1Profile represents a profile in HDF v1.0 format.
type V1Profile struct {
	Name           string                 `json:"name"`
	Version        *string                `json:"version,omitempty"`
	Title          *string                `json:"title,omitempty"`
	Maintainer     *string                `json:"maintainer,omitempty"`
	Summary        *string                `json:"summary,omitempty"`
	License        *string                `json:"license,omitempty"`
	Copyright      *string                `json:"copyright,omitempty"`
	CopyrightEmail *string                `json:"copyright_email,omitempty"`
	Supports       []map[string]interface{} `json:"supports,omitempty"`
	Attributes     []map[string]interface{} `json:"attributes,omitempty"`
	Groups         []V1Group              `json:"groups,omitempty"`
	Controls       []V1Control            `json:"controls,omitempty"`
	SHA256         *string                `json:"sha256,omitempty"`
	Depends        []V1Dependency         `json:"depends,omitempty"`
	ParentProfile  *string                `json:"parent_profile,omitempty"`
	Status         *string                `json:"status,omitempty"`
	StatusMessage  *string                `json:"status_message,omitempty"`
	SkipMessage    *string                `json:"skip_message,omitempty"`
}

// V1Platform represents the platform in HDF v1.0 format.
type V1Platform struct {
	Name     string  `json:"name"`
	Release  *string `json:"release,omitempty"`
	TargetID *string `json:"target_id,omitempty"`
}

// V1Statistics represents statistics in HDF v1.0 format.
type V1Statistics struct {
	Duration *float64 `json:"duration,omitempty"`
}

// HDFV1Results represents HDF v1.0 results format.
type HDFV1Results struct {
	Version    string       `json:"version"`
	Platform   V1Platform   `json:"platform"`
	Profiles   []V1Profile  `json:"profiles"`
	Statistics V1Statistics `json:"statistics"`
}
