//nolint:dupl // CLI converter wrappers are structurally similar by design
package cmd

import (
	"encoding/json"
	"fmt"

	gitlab "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-to-hdf/go"
)

type gitlabConverter struct{}

func (c *gitlabConverter) Name() string {
	return "GitLab Security Report to HDF"
}

func (c *gitlabConverter) Convert(input []byte) ([]byte, error) {
	result, err := gitlab.ConvertGitlabToHDF(input, version)
	if err != nil {
		return nil, fmt.Errorf("gitlab conversion failed: %w", err)
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HDF output: %w", err)
	}

	return output, nil
}

func init() {
	conv := &gitlabConverter{}
	RegisterConverter("gitlab", "hdf", conv)
	RegisterConverter("gitlab-sast", "hdf", conv)
	RegisterConverter("gitlab-dast", "hdf", conv)
}
