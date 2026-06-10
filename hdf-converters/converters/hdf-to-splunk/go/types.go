package hdftosplunk

// Splunk record types. The shape mirrors heimdall2's hdf2splunk wire contract
// (hdf_splunk_schema "1.1") so existing Splunk dashboards and saved searches
// keep working. snake_case field names below are part of the wire format —
// don't rename them without coordinating with downstream consumers.

// SplunkData is the top-level output: three families of records that share a
// per-call GUID. Reports are one-per-document, profiles one-per-baseline,
// controls one-per-requirement.
type SplunkData struct {
	Reports  []SplunkReport  `json:"reports"`
	Profiles []SplunkProfile `json:"profiles"`
	Controls []SplunkControl `json:"controls"`
}

// CommonMeta carries the envelope every Splunk record shares.
type CommonMeta struct {
	GUID            string `json:"guid"`
	Filename        string `json:"filename"`
	Filetype        string `json:"filetype"`
	Subtype         string `json:"subtype"`
	HDFSplunkSchema string `json:"hdf_splunk_schema"`
}

// ReportMeta extends CommonMeta — no extra fields today but matches heimdall2's
// per-type meta structure so future additions land in the right place.
type ReportMeta struct {
	CommonMeta
}

type SplunkReport struct {
	Meta        ReportMeta             `json:"meta"`
	Statistics  interface{}            `json:"statistics,omitempty"`
	Passthrough map[string]interface{} `json:"passthrough,omitempty"`
	Profiles    []interface{}          `json:"profiles"`
	Platform    Platform               `json:"platform"`
	Version     string                 `json:"version,omitempty"`
}

type Platform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
}

type ProfileMeta struct {
	CommonMeta
	IsBaseline    bool   `json:"is_baseline"`
	ProfileSHA256 string `json:"profile_sha256"`
}

type SplunkProfile struct {
	Meta           ProfileMeta   `json:"meta"`
	Summary        string        `json:"summary,omitempty"`
	SHA256         string        `json:"sha256"`
	Controls       []interface{} `json:"controls"`
	Supports       []interface{} `json:"supports"`
	Name           string        `json:"name"`
	Copyright      string        `json:"copyright,omitempty"`
	Maintainer     string        `json:"maintainer,omitempty"`
	CopyrightEmail string        `json:"copyright_email,omitempty"`
	Version        string        `json:"version,omitempty"`
	License        string        `json:"license,omitempty"`
	Title          string        `json:"title,omitempty"`
	ParentProfile  string        `json:"parent_profile,omitempty"`
	Depends        []interface{} `json:"depends"`
	Attributes     []interface{} `json:"attributes"`
	Groups         []interface{} `json:"groups"`
	Status         string        `json:"status,omitempty"`
}

type ControlMeta struct {
	CommonMeta
	Status        string `json:"status"`
	ProfileSHA256 string `json:"profile_sha256"`
	IsBaseline    bool   `json:"is_baseline"`
	IsWaived      bool   `json:"is_waived"`
	OverlayDepth  int    `json:"overlay_depth"`
}

type SplunkControl struct {
	Meta           ControlMeta            `json:"meta"`
	Title          string                 `json:"title,omitempty"`
	Code           string                 `json:"code"`
	Desc           string                 `json:"desc"`
	Descriptions   map[string]string      `json:"descriptions"`
	ID             string                 `json:"id"`
	Impact         float64                `json:"impact"`
	Refs           []interface{}          `json:"refs"`
	SourceLocation interface{}            `json:"source_location,omitempty"`
	Tags           map[string]interface{} `json:"tags"`
	Results        []interface{}          `json:"results"`
}
