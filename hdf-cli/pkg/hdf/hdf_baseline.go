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

// Information on the set of requirements that can be assessed, including baseline metadata
// and requirement definitions.
//
// Shared metadata fields for baselines. Used in both standalone baseline documents and
// evaluated baseline results.
type HdfBaseline struct {
	// Cryptographic checksum for baseline integrity verification.
	Checksum Checksum `json:"checksum"`
	// The set of dependencies this baseline depends on.
	Depends []Dependency `json:"depends"`
	// The tool that generated this file.
	Generator *Generator `json:"generator"`
	// A set of descriptions for the requirement groups.
	Groups []RequirementGroup `json:"groups"`
	// The input(s) or attribute(s) to be used in the run.
	Inputs []map[string]interface{} `json:"inputs"`
	// Optional reference to automated remediation resources (Ansible playbooks, Terraform
	// scripts, etc.) for implementing the security controls defined in this baseline.
	Remediation *Remediation `json:"remediation"`
	// The set of requirements - contains no findings as the assessment has not yet occurred.
	Requirements []BaselineRequirement `json:"requirements"`
	// The name - must be unique.
	Name string `json:"name"`
	// The set of supported platform targets.
	Supports []SupportedPlatform `json:"supports"`
	// The copyright holder(s).
	Copyright *string `json:"copyright"`
	// The email address or other contact information of the copyright holder(s).
	CopyrightEmail *string `json:"copyrightEmail"`
	// The copyright license. Example: 'Apache-2.0'.
	License *string `json:"license"`
	// The maintainer(s).
	Maintainer *string `json:"maintainer"`
	// The status. Example: 'loaded'.
	Status *string `json:"status"`
	// The summary. Example: the Security Technical Implementation Guide (STIG) header.
	Summary *string `json:"summary"`
	// The title - should be human readable.
	Title *string `json:"title"`
	// The version of the baseline.
	Version *string `json:"version"`
}

// A security requirement defined in a baseline. Contains the requirement definition but no
// findings since assessment has not yet occurred.
type BaselineRequirement struct {
	// The description for the overarching requirement.
	Desc *string `json:"desc"`
	// A set of additional descriptions. Example: the 'fix' text, 'check' text.
	Descriptions []Description `json:"descriptions"`
	// The requirement identifier. Example: 'SV-238196'.
	ID string `json:"id"`
	// The impactfulness or severity (0.0 to 1.0).
	Impact float64 `json:"impact"`
	// The set of references to external documents.
	Refs []Reference `json:"refs"`
	// The explicit location of the requirement within the source code.
	SourceLocation SourceLocation `json:"sourceLocation"`
	// A set of tags - usually metadata like CCI, STIG ID, severity.
	Tags map[string]interface{} `json:"tags"`
	// The title - is nullable.
	Title *string `json:"title"`
}
