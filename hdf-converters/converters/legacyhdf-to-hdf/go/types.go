// Package legacyhdf converts InSpec exec-json (the legacy HDF v1 format:
// profiles/controls) to the current HDF format (baselines/requirements).
//
// Legacy types are defined here manually. The official exec-json schema
// exists in heimdall2/libs/inspecjs/schemas/ but is not yet integrated into
// hdf-libs' type generation pipeline.
// Current HDF types are imported from github.com/mitre/hdf-libs/hdf-schema/dist/go/v3.
package legacyhdf

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// LegacyResult represents a test result in HDF v1.0 format.
type LegacyResult struct {
	Status         string   `json:"status"`
	CodeDesc       *string  `json:"code_desc,omitempty"`
	RunTime        *float64 `json:"run_time,omitempty"`
	StartTime      *string  `json:"start_time,omitempty"`
	Message        *string  `json:"message,omitempty"`
	Exception      *string  `json:"exception,omitempty"`
	Backtrace      []string `json:"backtrace,omitempty"`
	ResourceClass  *string  `json:"resource_class,omitempty"`
	ResourceParams *string  `json:"resource_params,omitempty"`
	ResourceID     *string  `json:"resource_id,omitempty"`
	SkipMessage    *string  `json:"skip_message,omitempty"`
}

// LegacySourceLocation represents the source location of a control.
type LegacySourceLocation struct {
	Ref  *string `json:"ref,omitempty"`
	Line *int    `json:"line,omitempty"`
}

// LegacyDescription represents a labeled description.
type LegacyDescription struct {
	Label string `json:"label"`
	Data  string `json:"data"`
}

// LegacyControl represents a control in HDF v1.0 format.
type LegacyControl struct {
	ID           string              `json:"id"`
	Title        *string             `json:"title,omitempty"`
	Desc         *string             `json:"desc,omitempty"`
	Descriptions []LegacyDescription `json:"descriptions,omitempty"`
	Impact       float64             `json:"impact"`
	// refs/tags are required by the InSpec exec-json schema Heimdall loads (empty is
	// valid, but the key must be present), so no omitempty.
	Refs           []interface{}          `json:"refs"`
	Tags           map[string]interface{} `json:"tags"`
	Code           *string                `json:"code,omitempty"`
	SourceLocation *LegacySourceLocation  `json:"source_location,omitempty"`
	WaiverData     map[string]interface{} `json:"waiver_data,omitempty"`
	Results        []LegacyResult         `json:"results,omitempty"`
	Status         *string                `json:"status,omitempty"`
}

// LegacyGroup represents a group of controls in HDF v1.0 format.
type LegacyGroup struct {
	ID       string   `json:"id"`
	Title    *string  `json:"title,omitempty"`
	Controls []string `json:"controls"`
}

// LegacyDependency represents a profile dependency in HDF v1.0 format.
type LegacyDependency struct {
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

// LegacyProfile represents a profile in HDF v1.0 format.
type LegacyProfile struct {
	Name           string  `json:"name"`
	Version        *string `json:"version,omitempty"`
	Title          *string `json:"title,omitempty"`
	Maintainer     *string `json:"maintainer,omitempty"`
	Summary        *string `json:"summary,omitempty"`
	License        *string `json:"license,omitempty"`
	Copyright      *string `json:"copyright,omitempty"`
	CopyrightEmail *string `json:"copyright_email,omitempty"`
	// supports/attributes/groups are required by the InSpec exec-json schema Heimdall
	// loads (an empty array is valid, but the key must be present), so no omitempty.
	Supports      []map[string]interface{} `json:"supports"`
	Attributes    []map[string]interface{} `json:"attributes"`
	Groups        []LegacyGroup            `json:"groups"`
	Controls      []LegacyControl          `json:"controls,omitempty"`
	SHA256        *string                  `json:"sha256,omitempty"`
	Depends       []LegacyDependency       `json:"depends,omitempty"`
	ParentProfile *string                  `json:"parent_profile,omitempty"`
	Status        *string                  `json:"status,omitempty"`
	StatusMessage *string                  `json:"status_message,omitempty"`
	SkipMessage   *string                  `json:"skip_message,omitempty"`
}

// LegacyPlatform represents the platform in HDF v1.0 format.
type LegacyPlatform struct {
	Name     string  `json:"name"`
	Release  *string `json:"release,omitempty"`
	TargetID *string `json:"target_id,omitempty"`
}

// LegacyStatistics represents statistics in HDF v1.0 format.
type LegacyStatistics struct {
	Duration *float64 `json:"duration,omitempty"`
}

// LegacyHDFResults represents HDF v1.0 results format.
type LegacyHDFResults struct {
	Version    string           `json:"version"`
	Platform   LegacyPlatform   `json:"platform"`
	Profiles   []LegacyProfile  `json:"profiles"`
	Statistics LegacyStatistics `json:"statistics"`
	// Timestamp/Generator are absent from genuine InSpec exec-json but a
	// re-exported HDF v1 document may carry them; preserve when present.
	Timestamp *string        `json:"timestamp,omitempty"`
	Generator *hdf.Generator `json:"generator,omitempty"`
}
