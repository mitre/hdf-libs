// Code generated from JSON Schema using quicktype. DO NOT EDIT.
// To parse and unparse this JSON data, add this code to your project and do:
//
//    hdfBaseline, err := UnmarshalHdfBaseline(bytes)
//    bytes, err = hdfBaseline.Marshal()

package hdf

import "encoding/json"

func UnmarshalHdfBaseline(data []byte) (HdfBaseline, error) {
	var r HdfBaseline
	err := json.Unmarshal(data, &r)
	return r, err
}

func (r *HdfBaseline) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

// Information on the set of requirements that can be assessed. Example: it can include the
// name of the InSpec profile.
type HdfBaseline struct {
	// The set of requirements - contains no findings as the assessment has not yet occurred.
	Controls []BaselineRequirement `json:"controls"`
	// The copyright holder(s).
	Copyright *string `json:"copyright"`
	// The email address or other contact information of the copyright holder(s).
	CopyrightEmail *string `json:"copyright_email"`
	// The set of dependencies this baseline depends on.
	Depends []Dependency `json:"depends"`
	// The tool that generated this file.
	Generator *Generator `json:"generator"`
	// A set of descriptions for the requirement groups.
	Groups []RequirementGroup `json:"groups"`
	// The input(s) or attribute(s) to be used in the run.
	Inputs []map[string]interface{} `json:"inputs"`
	// The copyright license. Example: 'Apache-2.0'.
	License *string `json:"license"`
	// The maintainer(s).
	Maintainer *string `json:"maintainer"`
	// The name - must be unique.
	Name string `json:"name"`
	// The SHA-256 checksum of the baseline.
	Sha256 *string `json:"sha256,omitempty"`
	// The SHA-512 checksum of the baseline (optional).
	Sha512 *string `json:"sha512"`
	// The status. Example: 'loaded'.
	Status *string `json:"status"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.
	Summary *string `json:"summary"`
	// The set of supported platform targets.
	Supports []SupportedPlatform `json:"supports"`
	// The title - should be human readable.
	Title *string `json:"title"`
	// The version of the baseline.
	Version *string `json:"version"`
}

// A requirement definition without assessment results.
type BaselineRequirement struct {
	// The raw source code of the requirement. Note that if this is an overlay, it does not
	// include the underlying source code.
	Code string `json:"code"`
	// The description for the overarching requirement.
	Desc *string `json:"desc"`
	// A set of additional descriptions. Example: the 'fix' text.
	Descriptions map[string]string `json:"descriptions"`
	// The requirement identifier. Example: 'SV-238196'.
	ID string `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).
	Impact float64 `json:"impact"`
	// The set of references to external documents.
	Refs []Reference `json:"refs"`
	// The explicit location of the requirement within the source code.
	SourceLocation *SourceLocation `json:"source_location"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.
	Tags map[string]interface{} `json:"tags"`
	// The title - is nullable.
	Title *string `json:"title"`
}

// Note: Reference, SourceLocation, Dependency, Generator, RequirementGroup, and SupportedPlatform
// types are defined in hdf_results.go to avoid duplicate definitions.
