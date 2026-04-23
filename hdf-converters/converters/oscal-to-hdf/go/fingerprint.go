package oscal

import "github.com/mitre/hdf-libs/hdf-converters/registry"

type oscalFingerprintSpec struct {
	key        string
	id         string
	label      string
	outputType registry.OutputType
}

var oscalSpecs = []oscalFingerprintSpec{
	{key: "system-security-plan", id: "oscal-ssp-to-hdf", label: "OSCAL SSP", outputType: registry.OutputRaw},
	{key: "assessment-plan", id: "oscal-sap-to-hdf", label: "OSCAL SAP", outputType: registry.OutputPlan},
	{key: "assessment-results", id: "oscal-sar-to-hdf", label: "OSCAL SAR", outputType: registry.OutputResults},
	{key: "plan-of-action-and-milestones", id: "oscal-poam-to-hdf", label: "OSCAL POA&M", outputType: registry.OutputAmendments},
	{key: "profile", id: "oscal-profile-to-hdf", label: "OSCAL Profile", outputType: registry.OutputBaseline},
	{key: "catalog", id: "oscal-catalog-to-hdf", label: "OSCAL Catalog", outputType: registry.OutputBaseline},
	{key: "component-definition", id: "oscal-component-to-hdf", label: "OSCAL Component", outputType: registry.OutputBaseline},
}

// oscalDetectVersion extracts the OSCAL schema version from
// metadata.oscal-version inside the document's root key.
func oscalDetectVersion(rootKey string, input any) string {
	obj, ok := input.(map[string]any)
	if !ok {
		return ""
	}
	root, ok := obj[rootKey].(map[string]any)
	if !ok {
		return ""
	}
	meta, ok := root["metadata"].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := meta["oscal-version"].(string); ok {
		return v
	}
	return ""
}

func init() {
	for _, spec := range oscalSpecs {
		spec := spec // capture loop variable
		registry.Register(registry.ConverterFingerprint{
			ID:          spec.id,
			Label:       spec.label,
			Direction:   registry.DirectionIngest,
			InputFamily: registry.FamilyJSON,
			OutputType:  spec.outputType,
			Fingerprint: func(input any) float64 {
				obj, ok := input.(map[string]any)
				if !ok {
					return 0
				}
				if _, exists := obj[spec.key]; exists {
					return 1.0
				}
				return 0
			},
			DetectVersion: func(input any) string {
				return oscalDetectVersion(spec.key, input)
			},
		})
	}
}
