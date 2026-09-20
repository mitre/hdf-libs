// Package legacyhdf converts InSpec exec-json (the legacy HDF v1 format:
// profiles/controls) to the current HDF format (baselines/requirements).
//
// Legacy types are defined here manually. The official exec-json schema
// exists in heimdall2/libs/inspecjs/schemas/ but is not yet integrated into
// hdf-libs' type generation pipeline.
// Current HDF types are imported from github.com/mitre/hdf-libs/hdf-schema/dist/go/v3.
package legacyhdf

import (
	"encoding/json"
	"fmt"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// LegacyResourceID tolerates InSpec's out-of-spec object-valued resource_id.
// The inspecjs exec-json schema types resource_id as string|null, but some
// resources (e.g. aws_iam_password_policy) emit their identity as a settings
// hash. Both the v2 and v3 HDF schemas type the field as a string, so a
// non-string value is normalized to canonical JSON (sorted keys, escaped and
// null-stripped exactly like every other HDF content-address) rather than
// dropped or failing the whole document. Marshalling emits a plain JSON string,
// so the value round-trips through the v2 shape unchanged.
type LegacyResourceID string

// UnmarshalJSON accepts either a JSON string (kept verbatim) or any other JSON
// value (normalized to its canonical JSON string via the shared canonicalizer,
// whose TS peer is pinned against the same vectors — so Go and TS agree byte for
// byte). A literal null leaves the value unset.
func (r *LegacyResourceID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*r = LegacyResourceID(s)
		return nil
	}
	canonical, err := hdfutil.CanonicalJSON(json.RawMessage(data))
	if err != nil {
		return fmt.Errorf("resource_id: %w", err)
	}
	*r = LegacyResourceID(canonical)
	return nil
}

// LegacyResult represents a test result in HDF v1.0 format.
type LegacyResult struct {
	Status         string            `json:"status"`
	CodeDesc       *string           `json:"code_desc,omitempty"`
	RunTime        *float64          `json:"run_time,omitempty"`
	StartTime      *string           `json:"start_time,omitempty"`
	Message        *string           `json:"message,omitempty"`
	Exception      *string           `json:"exception,omitempty"`
	Backtrace      []string          `json:"backtrace,omitempty"`
	ResourceClass  *string           `json:"resource_class,omitempty"`
	ResourceParams *string           `json:"resource_params,omitempty"`
	ResourceID     *LegacyResourceID `json:"resource_id,omitempty"`
	SkipMessage    *string           `json:"skip_message,omitempty"`
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

// LegacyPassthrough carries modern (v3) data that has no native v2 slot, so a
// v3→v2→v3 round trip is lossless. It lives under a single top-level
// "passthrough" key; the InSpec exec-json schema Heimdall loads sets
// additionalProperties:true at every level, so Heimdall ignores it.
//
// It marshals as a flat object: every Provenance key sits at the top level of
// the passthrough (v2's native home for provenance — a SAF-written passthrough
// or a native extensions.passthrough), plus the reserved "hdf_components" key
// carrying the full components[]. "hdf_components" is reserved for the carrier:
// a Provenance entry of that name is overridden by HDFComponents on marshal and
// read back as components (never provenance) on unmarshal.
type LegacyPassthrough struct {
	// HDFComponents preserves the full v3 components[] (the down-pin otherwise
	// keeps only the first component, mapped to platform).
	HDFComponents []hdf.Component
	// Provenance carries the v3 extensions.passthrough back to v2's top-level
	// passthrough, so document provenance is not lost on a version downgrade.
	Provenance map[string]interface{}
}

// HDFComponentsKey is the reserved passthrough key for the components carrier;
// a provenance entry of this name is overridden by the carrier (the downgrade
// warns when that happens).
const HDFComponentsKey = "hdf_components"

// MarshalJSON flattens Provenance to the top level and adds the reserved
// components carrier, so both survive under the single v2 passthrough key. The
// reserved key is filtered out of Provenance so provenance data can never shadow
// or be mistaken for the carrier.
func (p LegacyPassthrough) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{}, len(p.Provenance)+1)
	for k, v := range p.Provenance {
		if k == HDFComponentsKey {
			continue
		}
		out[k] = v
	}
	if len(p.HDFComponents) > 0 {
		out[HDFComponentsKey] = p.HDFComponents
	}
	return json.Marshal(out)
}

// UnmarshalJSON splits the reserved components carrier from the provenance keys.
func (p *LegacyPassthrough) UnmarshalJSON(data []byte) error {
	// Reset so a reused instance cannot leak stale fields when the next document
	// omits hdf_components or carries no provenance.
	p.HDFComponents = nil
	p.Provenance = nil
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if comp, ok := raw[HDFComponentsKey]; ok {
		if err := json.Unmarshal(comp, &p.HDFComponents); err != nil {
			return err
		}
		delete(raw, HDFComponentsKey)
	}
	if len(raw) > 0 {
		p.Provenance = make(map[string]interface{}, len(raw))
		for k, v := range raw {
			var val interface{}
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			p.Provenance[k] = val
		}
	}
	return nil
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
	// Passthrough carries v3-only data with no native v2 slot for lossless
	// round-tripping; absent on genuine InSpec exec-json input.
	Passthrough *LegacyPassthrough `json:"passthrough,omitempty"`
}
