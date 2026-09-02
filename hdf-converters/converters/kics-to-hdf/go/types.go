package kics

// Report is the top-level `kics scan --report-formats json` output. Fields the
// converter does not emit (severity_counters, total_counter — the fingerprint
// probes them from raw JSON) are deliberately not parsed.
type Report struct {
	Queries            []Query `json:"queries"`
	KicsVersion        string  `json:"kics_version"`
	FilesScanned       int     `json:"files_scanned"`
	FilesParsed        int     `json:"files_parsed"`
	FilesFailedToScan  int     `json:"files_failed_to_scan"`
	QueriesTotal       int     `json:"queries_total"`
	QueriesFailedToRun int     `json:"queries_failed_to_execute"`
}

// Query is one KICS query and every place it fired. KICS already groups its
// output this way, so it maps directly onto one requirement.
type Query struct {
	QueryID       string `json:"query_id"`
	QueryName     string `json:"query_name"`
	QueryURL      string `json:"query_url"`
	Severity      string `json:"severity"`
	Platform      string `json:"platform"`
	CWE           string `json:"cwe"`
	RiskScore     any    `json:"risk_score"`
	CloudProvider string `json:"cloud_provider"`
	Category      string `json:"category"`
	Experimental  bool   `json:"experimental"`
	Description   string `json:"description"`
	DescriptionID string `json:"description_id"`
	Files         []File `json:"files"`
}

// File is one occurrence, against a specific file and resource. search_line is
// deliberately not parsed: it duplicates line for every emitted field.
type File struct {
	FileName      string `json:"file_name"`
	SimilarityID  string `json:"similarity_id"`
	Line          int    `json:"line"`
	ResourceType  string `json:"resource_type"`
	ResourceName  string `json:"resource_name"`
	IssueType     string `json:"issue_type"`
	SearchKey     string `json:"search_key"`
	SearchValue   string `json:"search_value"`
	ExpectedValue string `json:"expected_value"`
	ActualValue   string `json:"actual_value"`
}
