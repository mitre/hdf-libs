// Package hdftosplunk converts HDF Results into the three families of
// Splunk-shaped records consumed by the SAF Heimdall Splunk dashboards
// (Report / Profile / Control), matching the heimdall2 hdf_splunk_schema
// "1.1" wire contract.
//
// The output is intended to be either written to disk via
// `hdf convert --from hdf --to splunk` (CLI use) or fed to a Splunk push
// helper that lives in the Splunk fetcher package. This converter does
// NOT do any network I/O — the upload step is intentionally separated so
// the transform is auth-agnostic and reusable.
//
// The output's meta.filename field defaults to "hdf-results.json" as a
// placeholder; downstream uploaders typically rewrite it at submission
// time with the real input filename.
package hdftosplunk

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

const (
	hdfSplunkSchemaVersion = "1.1"
	defaultFilename        = "hdf-results.json"
	subtypeHeader          = "header"
	subtypeProfile         = "profile"
	subtypeControl         = "control"
	filetypeEvaluation     = "evaluation"
	generatorName          = "hdf-to-splunk"
)

// parsedDoc is the minimal HDF Results shape we read. Optional sub-objects
// stay as json.RawMessage so we sidestep strict time.Time decoding for
// otherwise-loose fixtures (heimdall2 InSpec data carries timestamps
// without timezones).
type parsedDoc struct {
	Baselines  []parsedBaseline       `json:"baselines"`
	Tool       *parsedTool            `json:"tool,omitempty"`
	Generator  *parsedGenerator       `json:"generator,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
	Statistics json.RawMessage        `json:"statistics,omitempty"`
}

type parsedTool struct {
	Name    *string `json:"name,omitempty"`
	Version *string `json:"version,omitempty"`
}

type parsedGenerator struct {
	Version string `json:"version,omitempty"`
}

type parsedBaseline struct {
	Name            string                 `json:"name"`
	Title           *string                `json:"title,omitempty"`
	Summary         *string                `json:"summary,omitempty"`
	Version         *string                `json:"version,omitempty"`
	Copyright       *string                `json:"copyright,omitempty"`
	CopyrightEmail  *string                `json:"copyrightEmail,omitempty"`
	Maintainer      *string                `json:"maintainer,omitempty"`
	License         *string                `json:"license,omitempty"`
	Status          *string                `json:"status,omitempty"`
	ParentBaseline  *string                `json:"parentBaseline,omitempty"`
	ResultsChecksum *parsedChecksum        `json:"resultsChecksum,omitempty"`
	Integrity       *parsedChecksum        `json:"integrity,omitempty"`
	Supports        []json.RawMessage      `json:"supports,omitempty"`
	Depends         []json.RawMessage      `json:"depends,omitempty"`
	Inputs          []json.RawMessage      `json:"inputs,omitempty"`
	Groups          []json.RawMessage      `json:"groups,omitempty"`
	Requirements    []parsedRequirement    `json:"requirements"`
	Extensions      map[string]interface{} `json:"extensions,omitempty"`
}

// parsedChecksum covers BOTH `{algorithm,value}` (HDF Checksum) and
// `{algorithm,checksum}` (HDF Integrity) — we accept either field name for
// the hash value.
type parsedChecksum struct {
	Algorithm *string `json:"algorithm,omitempty"`
	Value     *string `json:"value,omitempty"`
	Checksum  *string `json:"checksum,omitempty"`
}

func (c *parsedChecksum) hash() string {
	if c == nil {
		return ""
	}
	if c.Value != nil && *c.Value != "" {
		return *c.Value
	}
	if c.Checksum != nil {
		return *c.Checksum
	}
	return ""
}

type parsedRequirement struct {
	ID             string                 `json:"id"`
	Title          *string                `json:"title,omitempty"`
	Code           *string                `json:"code,omitempty"`
	Impact         float64                `json:"impact"`
	Tags           map[string]interface{} `json:"tags"`
	Descriptions   []parsedDescription    `json:"descriptions"`
	Refs           []json.RawMessage      `json:"refs,omitempty"`
	SourceLocation json.RawMessage        `json:"sourceLocation,omitempty"`
	Results        []parsedResult         `json:"results"`
	Disposition    *string                `json:"disposition,omitempty"`
}

type parsedDescription struct {
	Label string `json:"label"`
	Data  string `json:"data"`
}

type parsedResult struct {
	Status string          `json:"status"`
	Raw    json.RawMessage `json:"-"` // populated by custom unmarshaler
}

func (r *parsedResult) UnmarshalJSON(data []byte) error {
	r.Raw = append([]byte(nil), data...)
	// Decode status only — pass everything else through as raw bytes.
	var head struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	r.Status = head.Status
	return nil
}

// ConvertHDFToSplunk parses HDF Results JSON and emits the Splunk records
// JSON. Returns an error for invalid JSON or HDF docs with no baselines
// (which violates the HDF schema's `baselines.minItems = 1` invariant).
func ConvertHDFToSplunk(input []byte) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, generatorName, 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("%s: empty input", generatorName)
	}

	var doc parsedDoc
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("%s: parse HDF input: %w", generatorName, err)
	}
	if len(doc.Baselines) == 0 {
		return nil, fmt.Errorf("%s: HDF document contains no baselines", generatorName)
	}

	guid, err := newGUID()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", generatorName, err)
	}

	data := SplunkData{
		Reports:  []SplunkReport{buildReport(&doc, guid)},
		Profiles: make([]SplunkProfile, 0, len(doc.Baselines)),
		Controls: []SplunkControl{},
	}
	for i := range doc.Baselines {
		b := &doc.Baselines[i]
		data.Profiles = append(data.Profiles, buildProfile(b, guid))
		for j := range b.Requirements {
			data.Controls = append(data.Controls, buildControl(&b.Requirements[j], b, &doc, guid))
		}
	}

	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%s: marshal output: %w", generatorName, err)
	}
	return out, nil
}

// ---- builders ----

func buildReport(doc *parsedDoc, guid string) SplunkReport {
	r := SplunkReport{
		Meta:     ReportMeta{CommonMeta: commonMeta(guid, subtypeHeader)},
		Profiles: []interface{}{},
		Platform: Platform{
			Name:    toolName(doc),
			Release: toolVersion(doc),
		},
	}
	if len(doc.Statistics) > 0 {
		var v interface{}
		_ = json.Unmarshal(doc.Statistics, &v)
		r.Statistics = v
	}
	if len(doc.Extensions) > 0 {
		r.Passthrough = doc.Extensions
	}
	if doc.Generator != nil {
		r.Version = doc.Generator.Version
	}
	return r
}

func buildProfile(b *parsedBaseline, guid string) SplunkProfile {
	sha := profileSHA(b)
	p := SplunkProfile{
		Meta: ProfileMeta{
			CommonMeta:    commonMeta(guid, subtypeProfile),
			IsBaseline:    b.ParentBaseline == nil,
			ProfileSHA256: sha,
		},
		SHA256:         sha,
		Name:           b.Name,
		Controls:       []interface{}{},
		Supports:       rawSliceToAny(b.Supports),
		Depends:        rawSliceToAny(b.Depends),
		Attributes:     rawSliceToAny(b.Inputs),
		Groups:         rawSliceToAny(b.Groups),
		Summary:        ptrString(b.Summary),
		Copyright:      ptrString(b.Copyright),
		CopyrightEmail: ptrString(b.CopyrightEmail),
		Maintainer:     ptrString(b.Maintainer),
		Version:        ptrString(b.Version),
		License:        ptrString(b.License),
		Title:          ptrString(b.Title),
		ParentProfile:  ptrString(b.ParentBaseline),
		Status:         ptrString(b.Status),
	}
	return p
}

func buildControl(req *parsedRequirement, b *parsedBaseline, doc *parsedDoc, guid string) SplunkControl {
	return SplunkControl{
		Meta: ControlMeta{
			CommonMeta:    commonMeta(guid, subtypeControl),
			Status:        foldStatus(req.Results),
			ProfileSHA256: profileSHA(b),
			IsBaseline:    b.ParentBaseline == nil,
			IsWaived:      isWaived(req),
			OverlayDepth:  overlayDepth(b, doc),
		},
		Title:          ptrString(req.Title),
		Code:           ptrString(req.Code),
		Desc:           defaultDescription(req.Descriptions),
		Descriptions:   flattenDescriptions(req.Descriptions),
		ID:             req.ID,
		Impact:         req.Impact,
		Refs:           rawSliceToAny(req.Refs),
		SourceLocation: rawToAny(req.SourceLocation),
		Tags:           normalizeTags(req.Tags),
		Results:        rawResultsToAny(req.Results),
	}
}

// ---- helpers ----

func commonMeta(guid, subtype string) CommonMeta {
	return CommonMeta{
		GUID:            guid,
		Filename:        defaultFilename,
		Filetype:        filetypeEvaluation,
		Subtype:         subtype,
		HDFSplunkSchema: hdfSplunkSchemaVersion,
	}
}

func ptrString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func toolName(doc *parsedDoc) string {
	if doc.Tool == nil {
		return ""
	}
	return ptrString(doc.Tool.Name)
}

func toolVersion(doc *parsedDoc) string {
	if doc.Tool == nil {
		return ""
	}
	return ptrString(doc.Tool.Version)
}

// profileSHA prefers ResultsChecksum, falls back to Integrity (which the
// minimal hdf-fixture uses). Either is a stable per-baseline identifier
// for Splunk's profile_sha256 facet.
func profileSHA(b *parsedBaseline) string {
	if h := b.ResultsChecksum.hash(); h != "" {
		return h
	}
	return b.Integrity.hash()
}

// foldStatus collapses one requirement's per-result statuses into the
// worst. Order (worst → best): error > failed > notReviewed > skipped >
// passed > notApplicable. Returns "notReviewed" when the result set is
// empty (shouldn't happen for schema-valid input).
func foldStatus(results []parsedResult) string {
	if len(results) == 0 {
		return "notReviewed"
	}
	rank := map[string]int{
		"error":         5,
		"failed":        4,
		"notReviewed":   3,
		"skipped":       2,
		"passed":        1,
		"notApplicable": 0,
	}
	worst := results[0].Status
	for _, r := range results[1:] {
		if rank[r.Status] > rank[worst] {
			worst = r.Status
		}
	}
	return worst
}

func isWaived(req *parsedRequirement) bool {
	return req.Disposition != nil && *req.Disposition == "waiver"
}

// overlayDepth measures how deep this baseline sits in the dependency
// chain. Root baseline = 1. If ParentBaseline references another baseline
// in the same document, depth increases.
func overlayDepth(b *parsedBaseline, doc *parsedDoc) int {
	depth := 1
	current := b
	visited := map[string]bool{current.Name: true}
	for current.ParentBaseline != nil {
		parentName := *current.ParentBaseline
		if visited[parentName] {
			break
		}
		visited[parentName] = true
		parent := findBaseline(doc, parentName)
		if parent == nil {
			break
		}
		depth++
		current = parent
	}
	return depth
}

func findBaseline(doc *parsedDoc, name string) *parsedBaseline {
	for i := range doc.Baselines {
		if doc.Baselines[i].Name == name {
			return &doc.Baselines[i]
		}
	}
	return nil
}

func defaultDescription(descs []parsedDescription) string {
	for _, d := range descs {
		if d.Label == "default" {
			return d.Data
		}
	}
	return ""
}

func flattenDescriptions(descs []parsedDescription) map[string]string {
	out := map[string]string{}
	for _, d := range descs {
		out[d.Label] = d.Data
	}
	return out
}

func normalizeTags(t map[string]interface{}) map[string]interface{} {
	if t == nil {
		return map[string]interface{}{}
	}
	return t
}

func rawSliceToAny(raws []json.RawMessage) []interface{} {
	out := make([]interface{}, 0, len(raws))
	for _, r := range raws {
		var v interface{}
		if err := json.Unmarshal(r, &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func rawToAny(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func rawResultsToAny(results []parsedResult) []interface{} {
	out := make([]interface{}, 0, len(results))
	for _, r := range results {
		var v interface{}
		if err := json.Unmarshal(r.Raw, &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// newGUID returns a hex-encoded 16-byte random identifier in UUIDv4-shape
// (8-4-4-4-12). Tests verify per-call uniqueness and within-call
// consistency, never the literal value.
func newGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate guid: %w", err)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	groups := []int{8, 4, 4, 4, 12}
	src := 0
	dst := 0
	for gi, g := range groups {
		if gi > 0 {
			out[dst] = '-'
			dst++
		}
		for k := 0; k < g; k += 2 {
			out[dst] = hex[b[src]>>4]
			out[dst+1] = hex[b[src]&0x0f]
			dst += 2
			src++
		}
	}
	return string(out), nil
}
