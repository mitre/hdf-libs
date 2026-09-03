package semgrep

import "encoding/json"

// Report is the top-level `semgrep scan --json` output.
type Report struct {
	Results []Result      `json:"results"`
	Errors  []ScanError   `json:"errors"`
	Version LenientString `json:"version"`
	Paths   Paths         `json:"paths"`
}

// Paths records which files the scan covered. `skipped` is only emitted when
// files were actually skipped. Scanned is decoded as []any because only its
// length is consumed — entry-type variance must not abort the conversion.
type Paths struct {
	Scanned []any `json:"scanned"`
}

// UnmarshalJSON tolerates a non-object paths value.
func (p *Paths) UnmarshalJSON(data []byte) error {
	type alias Paths
	var v alias
	if err := json.Unmarshal(data, &v); err == nil {
		*p = Paths(v)
		return nil
	}
	*p = Paths{}
	return nil
}

// Result is one finding. Decoded leniently: rule metadata is arbitrary
// rule-author YAML, so a wrong-typed value in one finding must degrade to
// "absent" for that field rather than fail the whole conversion (the same
// per-field filtering the TypeScript twin applies).
type Result struct {
	CheckID LenientString `json:"check_id"`
	Path    LenientString `json:"path"`
	Start   Position      `json:"start"`
	End     Position      `json:"end"`
	Extra   Extra         `json:"extra"`
}

// UnmarshalJSON tolerates a non-object entry, leaving a zero Result whose
// empty check_id the converter skips — matching the TypeScript guard.
func (r *Result) UnmarshalJSON(data []byte) error {
	type alias Result
	var v alias
	if err := json.Unmarshal(data, &v); err == nil {
		*r = Result(v)
		return nil
	}
	*r = Result{}
	return nil
}

// Position is a location within the scanned file.
type Position struct {
	Line LenientInt `json:"line"`
	Col  LenientInt `json:"col"`
}

// UnmarshalJSON tolerates a non-object position.
func (p *Position) UnmarshalJSON(data []byte) error {
	type alias Position
	var v alias
	if err := json.Unmarshal(data, &v); err == nil {
		*p = Position(v)
		return nil
	}
	*p = Position{}
	return nil
}

// Extra carries the per-finding envelope. extra.lines is redacted to the
// literal string "requires login" unless the scan is authenticated;
// extra.fingerprint is equally redacted and deliberately not mapped.
type Extra struct {
	Message  LenientString `json:"message"`
	Metadata Metadata      `json:"metadata"`
	Severity LenientString `json:"severity"`
	Lines    LenientString `json:"lines"`
	// Fix is replacement text for the matched span; present only when a rule
	// ships an autofix.
	Fix LenientString `json:"fix"`
}

// UnmarshalJSON tolerates a non-object envelope.
func (e *Extra) UnmarshalJSON(data []byte) error {
	type alias Extra
	var v alias
	if err := json.Unmarshal(data, &v); err == nil {
		*e = Extra(v)
		return nil
	}
	*e = Extra{}
	return nil
}

// Metadata is the rule-level registry metadata. Fields documented as arrays
// arrive as bare strings when a rule declares a single value, so anything
// list-shaped is decoded through StringOrSlice.
type Metadata struct {
	CWE                StringOrSlice `json:"cwe"`
	OWASP              StringOrSlice `json:"owasp"`
	References         StringOrSlice `json:"references"`
	Subcategory        StringOrSlice `json:"subcategory"`
	Technology         StringOrSlice `json:"technology"`
	VulnerabilityClass StringOrSlice `json:"vulnerability_class"`
	Confidence         LenientString `json:"confidence"`
	Likelihood         LenientString `json:"likelihood"`
	// Impact rates the severity of the consequence -- NOT the HDF impact float.
	Impact        LenientString `json:"impact"`
	Category      LenientString `json:"category"`
	Source        LenientString `json:"source"`
	Shortlink     LenientString `json:"shortlink"`
	SourceRuleURL LenientString `json:"source-rule-url"`
	BanditCode    LenientString `json:"bandit-code"`
	ASVS          LenientMap    `json:"asvs"`
}

// UnmarshalJSON tolerates a non-object metadata value.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	type alias Metadata
	var v alias
	if err := json.Unmarshal(data, &v); err == nil {
		*m = Metadata(v)
		return nil
	}
	*m = Metadata{}
	return nil
}

// ScanError is one error reported during the scan. Type is a heterogeneous
// array -- a discriminant string followed by an optional payload, e.g.
// ["PartialParsing", [{path, start, end}]] -- so it is decoded loosely and read
// only for its discriminant. Level distinguishes fatal ("error") entries from
// advisory ("warn") ones and drives the result status.
type ScanError struct {
	Message LenientString `json:"message"`
	Level   LenientString `json:"level"`
	Type    any           `json:"type"`
	Path    LenientString `json:"path"`
}

// StringOrSlice decodes a JSON value that may be either a string or an array
// of strings into a slice.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler. Array entries are filtered
// per-entry (non-string members dropped, string members kept) so one stray
// value does not discard the whole field — mirroring the TypeScript
// normalizeToArray filter.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			*s = nil
		} else {
			*s = []string{single}
		}
		return nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil {
		out := make([]string, 0, len(raw))
		for _, entry := range raw {
			var str string
			if json.Unmarshal(entry, &str) == nil {
				out = append(out, str)
			}
		}
		if len(out) == 0 {
			*s = nil
		} else {
			*s = out
		}
		return nil
	}
	// A shape we do not model is treated as absent rather than fatal: one
	// unexpected metadata field should not fail the whole conversion.
	*s = nil
	return nil
}

// LenientString decodes a JSON string, treating any other type as absent.
type LenientString string

// UnmarshalJSON implements json.Unmarshaler.
func (s *LenientString) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err == nil {
		*s = LenientString(v)
		return nil
	}
	*s = ""
	return nil
}

// LenientInt decodes a JSON integer, treating any other type as absent (0).
type LenientInt int

// UnmarshalJSON implements json.Unmarshaler.
func (i *LenientInt) UnmarshalJSON(data []byte) error {
	var v int
	if err := json.Unmarshal(data, &v); err == nil {
		*i = LenientInt(v)
		return nil
	}
	*i = 0
	return nil
}

// LenientMap decodes a JSON object, treating any other type as absent.
type LenientMap map[string]any

// UnmarshalJSON implements json.Unmarshaler.
func (m *LenientMap) UnmarshalJSON(data []byte) error {
	var v map[string]any
	if err := json.Unmarshal(data, &v); err == nil {
		*m = v
		return nil
	}
	*m = nil
	return nil
}
