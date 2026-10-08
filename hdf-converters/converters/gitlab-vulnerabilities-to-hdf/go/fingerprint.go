package gitlab_vulnerabilities_to_hdf

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "gitlab-vulnerabilities-to-hdf",
		Label:       "GitLab Vulnerability Report",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: fingerprint,
	})
}

// fingerprint recognizes the fetcher envelope: a project block with a
// fullPath and a vulnerabilities array whose nodes carry uuid and state. The
// sibling CI-artifact report also has a vulnerabilities array but no project
// block and no state, so it scores 0 here.
func fingerprint(input any) float64 {
	obj, ok := input.(map[string]any)
	if !ok {
		return 0
	}
	project, ok := obj["project"].(map[string]any)
	if !ok {
		return 0
	}
	if fullPath, ok := project["fullPath"].(string); !ok || fullPath == "" {
		return 0
	}
	vulns, ok := obj["vulnerabilities"].([]any)
	if !ok {
		return 0
	}
	if len(vulns) == 0 {
		return 0.9
	}
	first, ok := vulns[0].(map[string]any)
	if !ok {
		return 0
	}
	_, hasUUID := first["uuid"].(string)
	_, hasState := first["state"].(string)
	if hasUUID && hasState {
		return 1.0
	}
	return 0
}
