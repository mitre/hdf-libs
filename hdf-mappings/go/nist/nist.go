// Package nist holds the repo-wide NIST SP 800-53 revision default.
//
// The revision is a process-global default that every NIST-emitting mapping
// consults through its default lookups (e.g. awsconfig.NISTControls). Set it
// once at startup — the CLI's --nist-rev flag does this — to switch the catalog
// all converters target. For explicit, concurrency-safe per-call selection,
// use the *ForRevision lookups in each mapping package instead of mutating this.
package nist

import "fmt"

// DefaultRevision is the NIST SP 800-53 revision mappings emit when nothing
// overrides it. Bump it only once every mapping table has rows for the new
// revision (a consumer-visible change that must be release-noted).
const DefaultRevision = 5

// supportedRevisions lists the revisions every NIST-emitting mapping table has
// rows for. Keep in sync with the Rev values present in the mapping JSON.
var supportedRevisions = []int{4, 5}

var currentRevision = DefaultRevision

// strict, when set, asks revision-divergent mappings to treat a rule that has
// no mapping at the current revision (but does at another) as a hard error
// rather than a silent omission. The CLI's --nist-strict flag toggles it.
var strict bool

// Revision returns the process-global default NIST revision.
func Revision() int {
	return currentRevision
}

// Strict reports whether strict NIST revision alignment is enabled.
func Strict() bool {
	return strict
}

// SetStrict toggles strict NIST revision alignment.
func SetStrict(s bool) {
	strict = s
}

// SetRevision sets the process-global default NIST revision. It returns an
// error (without mutating state) if the revision has no mapping data.
func SetRevision(rev int) error {
	for _, r := range supportedRevisions {
		if r == rev {
			currentRevision = rev
			return nil
		}
	}
	return fmt.Errorf("unsupported NIST revision %d (supported: %v)", rev, supportedRevisions)
}

// ResetRevision restores the default revision. Intended for CLI cleanup and tests.
func ResetRevision() {
	currentRevision = DefaultRevision
}

// SupportedRevisions returns a copy of the revisions with mapping data.
func SupportedRevisions() []int {
	out := make([]int, len(supportedRevisions))
	copy(out, supportedRevisions)
	return out
}
