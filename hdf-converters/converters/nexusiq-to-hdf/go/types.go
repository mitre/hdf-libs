package nexusiq

import "encoding/json"

// Report is the policy-evaluation result the Nexus IQ CLI writes with
// `--result-file` (`-r`). prioritiesUrl is not parsed: it links to the IQ
// developer view of the same scan the report URLs already identify.
type Report struct {
	ApplicationID          string                 `json:"applicationId"`
	ScanID                 string                 `json:"scanId"`
	Stage                  string                 `json:"stage"`
	PolicyAction           string                 `json:"policyAction"`
	ReportHTMLURL          string                 `json:"reportHtmlUrl"`
	ReportPDFURL           string                 `json:"reportPdfUrl"`
	ReportDataURL          string                 `json:"reportDataUrl"`
	PolicyEvaluationResult PolicyEvaluationResult `json:"policyEvaluationResult"`
}

// PolicyEvaluationResult holds the alerts and IQ's own summary counters. The
// counters are carried through verbatim, so they are kept as raw numbers.
type PolicyEvaluationResult struct {
	Alerts     []Alert           `json:"alerts"`
	SastAlerts []json.RawMessage `json:"sastAlerts"`
}

// Alert is one policy violation: a policy, the component that violated it, and
// the actions IQ attached.
type Alert struct {
	Trigger Trigger  `json:"trigger"`
	Actions []Action `json:"actions"`

	// raw is the alert exactly as IQ emitted it, for the result's rawSourceRecord.
	raw json.RawMessage
}

func (a *Alert) UnmarshalJSON(data []byte) error {
	type plain Alert
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*a = Alert(p)
	a.raw = append(json.RawMessage(nil), data...)
	return nil
}

type Trigger struct {
	PolicyID          string          `json:"policyId"`
	PolicyName        string          `json:"policyName"`
	ThreatLevel       int             `json:"threatLevel"`
	PolicyViolationID string          `json:"policyViolationId"`
	ComponentFacts    []ComponentFact `json:"componentFacts"`
}

type ComponentFact struct {
	// Null for a component IQ could not identify (the "Unknown Component" policy).
	ComponentIdentifier *ComponentIdentifier `json:"componentIdentifier"`
	Hash                string               `json:"hash"`
	ConstraintFacts     []ConstraintFact     `json:"constraintFacts"`
	Pathnames           []string             `json:"pathnames"`
	DisplayName         *DisplayName         `json:"displayName"`
}

// ComponentIdentifier's coordinate keys depend on the format (pypi carries
// name/version/qualifier/extension; other formats use their own keys).
type ComponentIdentifier struct {
	Format      string         `json:"format"`
	Coordinates map[string]any `json:"coordinates"`
}

type DisplayName struct {
	Name string `json:"name"`
}

type ConstraintFact struct {
	ConstraintID   string          `json:"constraintId"`
	ConstraintName string          `json:"constraintName"`
	OperatorName   string          `json:"operatorName"`
	ConditionFacts []ConditionFact `json:"conditionFacts"`
}

type ConditionFact struct {
	ConditionTypeID string     `json:"conditionTypeId"`
	Summary         string     `json:"summary"`
	Reason          string     `json:"reason"`
	Reference       *Reference `json:"reference"`
}

type Reference struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type Action struct {
	ActionTypeID string `json:"actionTypeId"`
}
