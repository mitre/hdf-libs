package hadolint

import "strings"

// hadolint's report carries a one-line message per finding and nothing else.
// Each rule's rationale and fix live on a wiki page, and the two rule families
// are documented in different projects, so every requirement links its own.
const (
	hadolintRuleBase   = "https://github.com/hadolint/hadolint/wiki"
	shellcheckRuleBase = "https://github.com/koalaman/shellcheck/wiki"
)

// isShellcheck reports whether a rule code belongs to shellcheck rather than
// hadolint. hadolint surfaces shellcheck's findings in its own report.
func isShellcheck(code string) bool {
	return strings.HasPrefix(code, "SC")
}

// ruleReferenceURL is the published documentation for a rule. The code is
// checked against ruleCodePattern first, so a report carrying a crafted code
// cannot steer the link somewhere of its choosing.
func ruleReferenceURL(code string) string {
	if !ruleCodePattern.MatchString(code) {
		return ""
	}
	if isShellcheck(code) {
		return shellcheckRuleBase + "/" + code
	}
	return hadolintRuleBase + "/" + code
}
