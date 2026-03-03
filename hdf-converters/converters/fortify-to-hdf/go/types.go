package fortify

import "encoding/xml"

// FVDL represents the root element of a Fortify FVDL XML file.
type FVDL struct {
	XMLName         xml.Name        `xml:"FVDL"`
	CreatedTS       CreatedTS       `xml:"CreatedTS"`
	UUID            string          `xml:"UUID"`
	Build           Build           `xml:"Build"`
	Vulnerabilities Vulnerabilities `xml:"Vulnerabilities"`
	Descriptions    []Description   `xml:"Description"`
	Snippets        Snippets        `xml:"Snippets"`
	EngineData      EngineData      `xml:"EngineData"`
}

// CreatedTS contains the date and time the FVDL was generated.
type CreatedTS struct {
	Date string `xml:"date,attr"`
	Time string `xml:"time,attr"`
}

// Build contains metadata about the scanned project.
type Build struct {
	BuildID        string `xml:"BuildID"`
	NumberFiles    int    `xml:"NumberFiles"`
	SourceBasePath string `xml:"SourceBasePath"`
}

// Vulnerabilities wraps the list of Vulnerability elements.
type Vulnerabilities struct {
	Vulnerability []Vulnerability `xml:"Vulnerability"`
}

// Vulnerability represents a single vulnerability instance found by Fortify.
type Vulnerability struct {
	ClassInfo    ClassInfo    `xml:"ClassInfo"`
	InstanceInfo InstanceInfo `xml:"InstanceInfo"`
	AnalysisInfo AnalysisInfo `xml:"AnalysisInfo"`
}

// ClassInfo describes the vulnerability class.
type ClassInfo struct {
	ClassID         string  `xml:"ClassID"`
	Kingdom         string  `xml:"Kingdom"`
	Type            string  `xml:"Type"`
	Subtype         string  `xml:"Subtype"`
	AnalyzerName    string  `xml:"AnalyzerName"`
	DefaultSeverity float64 `xml:"DefaultSeverity"`
}

// InstanceInfo describes this specific vulnerability instance.
type InstanceInfo struct {
	InstanceID       string  `xml:"InstanceID"`
	InstanceSeverity float64 `xml:"InstanceSeverity"`
	Confidence       float64 `xml:"Confidence"`
}

// AnalysisInfo contains the trace/dataflow analysis results.
type AnalysisInfo struct {
	Unified UnifiedAnalysis `xml:"Unified"`
}

// UnifiedAnalysis contains the unified trace information.
type UnifiedAnalysis struct {
	Trace Trace `xml:"Trace"`
}

// Trace contains the primary trace entries.
type Trace struct {
	Primary PrimaryTrace `xml:"Primary"`
}

// PrimaryTrace contains the primary Entry list.
type PrimaryTrace struct {
	Entries []TraceEntry `xml:"Entry"`
}

// TraceEntry is a single trace step.
type TraceEntry struct {
	NodeRef *NodeRef   `xml:"NodeRef"`
	Node    *TraceNode `xml:"Node"`
}

// NodeRef is a reference to a shared node by ID.
type NodeRef struct {
	ID string `xml:"id,attr"`
}

// TraceNode contains source location and snippet reference.
type TraceNode struct {
	IsDefault      string         `xml:"isDefault,attr"`
	SourceLocation SourceLocation `xml:"SourceLocation"`
}

// SourceLocation points to a file and line, optionally referencing a snippet.
type SourceLocation struct {
	Path      string `xml:"path,attr"`
	Line      string `xml:"line,attr"`
	LineEnd   string `xml:"lineEnd,attr"`
	ColStart  string `xml:"colStart,attr"`
	ColEnd    string `xml:"colEnd,attr"`
	ContextID string `xml:"contextId,attr"`
	Snippet   string `xml:"snippet,attr"`
}

// Description represents a vulnerability class description in FVDL.
type Description struct {
	ContentType     string      `xml:"contentType,attr"`
	ClassID         string      `xml:"classID,attr"`
	Abstract        string      `xml:"Abstract"`
	Explanation     string      `xml:"Explanation"`
	Recommendations string      `xml:"Recommendations"`
	Tips            Tips        `xml:"Tips"`
	References      References  `xml:"References"`
}

// Tips contains Tip elements.
type Tips struct {
	Tip []string `xml:"Tip"`
}

// References contains Reference elements.
type References struct {
	Reference []Reference `xml:"Reference"`
}

// Reference contains standards mapping information.
type Reference struct {
	Title     string `xml:"Title"`
	Author    string `xml:"Author"`
	Publisher string `xml:"Publisher"`
	Source    string `xml:"Source"`
}

// Snippets wraps the list of Snippet elements.
type Snippets struct {
	Snippet []Snippet `xml:"Snippet"`
}

// Snippet contains a code excerpt.
type Snippet struct {
	ID        string `xml:"id,attr"`
	File      string `xml:"File"`
	StartLine string `xml:"StartLine"`
	EndLine   string `xml:"EndLine"`
	Text      string `xml:"Text"`
}

// EngineData contains metadata about the Fortify engine.
type EngineData struct {
	EngineVersion string `xml:"EngineVersion"`
}
