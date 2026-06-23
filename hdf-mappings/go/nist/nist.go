// Package nist holds the repo-wide NIST SP 800-53 revision default.
package nist

// CurrentRevision is the NIST SP 800-53 revision that all mappings emit by
// default. To change the repo-wide default, bump this constant — but only once
// every NIST-emitting mapping table has rows for the new revision. Per-call
// overrides use the *ForRevision lookups in each mapping package.
const CurrentRevision = 4
