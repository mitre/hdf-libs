package convert

import gitlabvulns "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-vulnerabilities-to-hdf/go"

func init() {
	registerHDFConverter("gitlab-vulnerabilities", "GitLab Vulnerability Report to HDF", "gitlab-vulnerabilities", gitlabvulns.ConvertGitlabVulnerabilitiesToHDF, WithExpectedRequirementCount(gitlabvulns.ExpectedRequirementCount))
}
