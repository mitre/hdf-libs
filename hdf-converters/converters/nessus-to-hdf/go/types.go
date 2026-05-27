package nessus

// NessusXML represents the root structure of a Nessus XML scan file
type NessusXML struct {
	Policy Policy     `xml:"Policy"`
	Report ReportData `xml:"Report"`
}

// Policy contains the scan policy configuration
type Policy struct {
	PolicyName  string      `xml:"policyName"`
	Preferences Preferences `xml:"Preferences"`
}

// Preferences contains server preferences
type Preferences struct {
	ServerPreferences ServerPreferences `xml:"ServerPreferences"`
}

// ServerPreferences contains individual preference settings
type ServerPreferences struct {
	Preference []Preference `xml:"preference"`
}

// Preference represents a single server preference
type Preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// ReportData contains the scan report information
type ReportData struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}

// ReportHost represents a single scanned host
type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

// HostProperties contains host-specific metadata
type HostProperties struct {
	Tags []HostPropertyTag `xml:"tag"`
}

// HostPropertyTag represents a single host property
type HostPropertyTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// ReportItem represents a single vulnerability or compliance finding
type ReportItem struct {
	Port       string `xml:"port,attr"`
	SvcName    string `xml:"svc_name,attr"`
	Protocol   string `xml:"protocol,attr"`
	Severity   string `xml:"severity,attr"`
	PluginID   string `xml:"pluginID,attr"`
	PluginName string `xml:"pluginName,attr"`

	// Basic metadata
	PluginFamily           string `xml:"pluginFamily"`
	Description            string `xml:"description"`
	FName                  string `xml:"fname"`
	PluginModificationDate string `xml:"plugin_modification_date"`
	PluginPublicationDate  string `xml:"plugin_publication_date"`
	PluginType             string `xml:"plugin_type"`
	RiskFactor             string `xml:"risk_factor"`
	ScriptVersion          string `xml:"script_version"`
	SeeAlso                string `xml:"see_also"`
	Solution               string `xml:"solution"`
	Synopsis               string `xml:"synopsis"`
	PluginOutput           string `xml:"plugin_output"`
	CVSSBaseScore          string `xml:"cvss_base_score"`
	CVSS3BaseScore         string `xml:"cvss3_base_score"`
	CVE                    string `xml:"cve"`

	// Structured CVSS data (Wave 2: CVE-ecosystem)
	CVSSVector          string `xml:"cvss_vector"`
	CVSS3Vector         string `xml:"cvss3_vector"`
	CVSSTemporalVector  string `xml:"cvss_temporal_vector"`
	CVSS3TemporalVector string `xml:"cvss3_temporal_vector"`
	CVSSTemporalScore   string `xml:"cvss_temporal_score"`
	CVSS3TemporalScore  string `xml:"cvss3_temporal_score"`
	CVSSScoreSource     string `xml:"cvss_score_source"`

	// EPSS (newer Tenable plugins emit these inline)
	EPSSScore      string `xml:"epss_score"`
	EPSSPercentile string `xml:"epss_percentile"`

	// CWE references (Nessus may emit multiple <cwe> elements)
	CWE []string `xml:"cwe"`

	// Compliance-specific fields (with cm: namespace)
	ComplianceReference   string `xml:"http://www.nessus.org/cm compliance-reference"`
	ComplianceCheckName   string `xml:"http://www.nessus.org/cm compliance-check-name"`
	ComplianceInfo        string `xml:"http://www.nessus.org/cm compliance-info"`
	ComplianceSolution    string `xml:"http://www.nessus.org/cm compliance-solution"`
	ComplianceResult      string `xml:"http://www.nessus.org/cm compliance-result"`
	ComplianceActualValue string `xml:"http://www.nessus.org/cm compliance-actual-value"`
}
