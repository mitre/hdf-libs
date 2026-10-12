package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// NewEvidenceCmd creates the evidence command group with info subcommand.
func NewEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Work with HDF evidence package documents",
		Long: `Commands for viewing and managing HDF evidence package documents.

An HDF evidence package bundles references to all HDF documents for audit,
authorization, and compliance review.

Examples:
  hdf evidence info q1-2026.hdf-evidence-package.json
  hdf evidence info q1-2026.hdf-evidence-package.json --json`,
	}

	cmd.AddCommand(newEvidenceInfoCmd())
	cmd.AddCommand(newEvidenceVerifyRemovedCmd())
	cmd.AddCommand(newEvidenceBuildCmd())
	cmd.AddCommand(newEvidenceExportCmd())
	cmd.AddCommand(newEvidenceSetCmd())
	cmd.AddCommand(newEvidenceAddEvidenceCmd())
	cmd.AddCommand(newEvidenceAddReferenceCmd())
	cmd.AddCommand(newEvidenceUpdateCmd())
	cmd.AddCommand(newEvidenceBundleCmd())

	return cmd
}

// newEvidenceVerifyRemovedCmd is a TOMBSTONE, not an alias: it does no verification and
// always fails. `hdf evidence verify` was removed in favour of `hdf evidence info
// --verify`, and simply deleting the command was not enough — measured, cobra answers an
// unknown subcommand by printing the parent's help and exiting ZERO, so every pipeline
// still calling the old name would have gone green on a package nobody checked. A removal
// has to be louder than the thing it removed, so this exits non-zero and names the
// replacement. cobra.NoArgs on the parent does NOT do this; it is inert without a Run.
func newEvidenceVerifyRemovedCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "verify <package-file>",
		Short:  "Removed — use 'hdf evidence info --verify'",
		Hidden: true,
		Args:   cobra.ArbitraryArgs,
		// The flags the removed command took are not declared here, so cobra would
		// reject them before RunE ran — meaning a pipeline calling the old name WITH a
		// flag, which is how CI called it, saw "unknown flag" and never the removal
		// notice. Whitelisting unknown flags lets the message through for exactly the
		// invocation it was written for.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(_ *cobra.Command, args []string) error {
			target := "<package-file>"
			if len(args) > 0 {
				target = args[0]
			}
			// CAREFUL: this message is the one place that must name the OLD command. A
			// blanket sweep of the removed name across the tree rewrote it to say the
			// NEW name had been removed and replaced by itself — and the test passed,
			// because it only checked that the message contained "has been removed" and
			// "info --verify", both of which survived the corruption. The test now pins
			// both names separately.
			return fmt.Errorf("'hdf evidence verify' has been removed; it is now "+
				"'hdf evidence info --verify %s'. Every flag it took still works there "+
				"(--checksums-only, --require-reachable, --require-checksums-match)", target)
		},
	}
}

// strayVerifyFlags names the --verify-only flags the caller actually set, so the refusal
// lists what they typed instead of a fixed pair. Keyed on Changed(), not on the value: a
// flag that defaults true is indistinguishable from an explicit setting by value alone.
func strayVerifyFlags(c *cobra.Command) []string {
	stray := make([]string, 0, 4)
	for _, name := range []string{
		"checksums-only", "require-reachable", "require-checksums", "require-checksums-match",
	} {
		if c.Flags().Changed(name) {
			stray = append(stray, "--"+name)
		}
	}
	return stray
}

func newEvidenceInfoCmd() *cobra.Command {
	var verify, checksumsOnly, requireReachable, requireChecksumsMatch, requireChecksums bool

	cmd := &cobra.Command{
		Use:   "info <file>",
		Short: "Summarize an HDF evidence package, and optionally verify it",
		Long: `Summarize an HDF evidence package: its name, preparer, timestamp and system
reference, what it carries, and what it records about its own completeness.

By default this READS ONE DOCUMENT and opens nothing it references, so it stays
cheap on a package carrying gigabytes of evidence. What it shows is therefore
what the package RECORDS, not what was checked: an entry is reported as
recording a checksum, recording an empty one, or recording none. Nothing is
hashed, so nothing is called verified.

--verify opens every reference and checks it. That is the full crawl, and it is
where a verdict comes from: each entry is reported as matching, MISMATCHING,
carrying no checksum to check, unreadable, unreachable from here, or recorded
under an algorithm this build cannot compute. Completeness is computed against
the plan the package names rather than read from the stored summary, which the
schema itself calls informational and not authoritative. A mismatch fails the
command.

Two narrow opt-ins tighten that, and they answer different questions about the
same entry. --require-checksums fails when a reference records NOTHING to
verify, naming each one. --require-checksums-match, which is ON by default,
fails when a checksum that WAS computed disagrees. An entry recording no
checksum cannot mismatch and one that mismatches is not unchecksummed, so the
two never fire for the same reason, and both can fail at once. Neither is a
default to reach for: --require-checksums is for an assessor who needs every
document checksum-governed, as --require-reachable is for one who needs the
package self-contained.

Examples:
  hdf evidence info q1-2026.hdf-evidence-package.json
  hdf evidence info q1-2026.hdf-evidence-package.json --json
  hdf evidence info q1-2026.hdf-evidence-package.json --verify
  hdf evidence info q1-2026.hdf-evidence-package.json --verify --checksums-only
  hdf evidence info q1-2026.hdf-evidence-package.json --verify --require-reachable
  hdf evidence info q1-2026.hdf-evidence-package.json --verify --require-checksums`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if verify {
				return runEvidenceVerify(args[0], checksumsOnly, requireReachable,
					requireChecksumsMatch, requireChecksums)
			}
			// Refused rather than ignored: a flag that silently does nothing is how an
			// operator comes to believe a check ran. --require-checksums-match is included
			// via Changed() rather than by its value, because it DEFAULTS true — testing
			// the value cannot tell the default apart from an explicit =false, and an
			// operator who typed =false asked for something this path cannot give.
			if stray := strayVerifyFlags(c); len(stray) > 0 {
				return fmt.Errorf("%s only mean(s) something with --verify, which is what opens "+
					"the referenced documents; pass --verify", strings.Join(stray, " and "))
			}
			return runDocInfo(args[0], "hdf evidence info", []string{"evidence-package"}, outputEvidenceInfoHuman)
		},
	}

	cmd.Flags().BoolVar(&verify, "verify", false,
		"Open every referenced document and check it; without this, nothing is read or hashed")
	cmd.Flags().BoolVar(&checksumsOnly, "checksums-only", false,
		"With --verify: check checksums only, skipping the completeness check")
	cmd.Flags().BoolVar(&requireReachable, "require-reachable", false,
		"With --verify: fail if the package records a reference this machine cannot resolve")
	cmd.Flags().BoolVar(&requireChecksums, "require-checksums", false,
		"With --verify: fail if any reference records no checksum to verify, naming each; "+
			"narrow, for an assessor who needs every document checksum-governed")
	// The true here is the real default, and it is the OPPOSITE of the two flags above,
	// deliberately. A contents[] mismatch failed before this flag existed, so defaulting
	// it false would not add a valve: it would quietly stop a tampered document from
	// failing.
	cmd.Flags().BoolVar(&requireChecksumsMatch, "require-checksums-match", true,
		"With --verify: fail if a checksum this run could compute disagrees with the file; "+
			"pass =false to report a mismatch without failing")

	return cmd
}

// recordedChecksumState says what the DOCUMENT records about an entry's checksum, which
// is all the default path can know: it opens nothing and hashes nothing. The tick glyph
// is deliberately absent — it is reserved for a computed match under --verify, and this
// used to print it on the mere PRESENCE of the checksum key, so an entry recording a
// BLANK value and one naming a remote URI nobody fetched both displayed as checked.
//
// A blank value is schema-valid (Checksum.value has no minLength), and the two cases need
// different remedies: one has a checksum to fill in, the other has none to begin with —
// the same distinction `evidence bundle` counts separately.
//
// Defensive on shape because runDocInfo does NOT schema-validate: it checks the document
// type and unmarshals, so a hand-edited package can arrive with a checksum that is not an
// object, or a value that is not a string.
// checksumStateFrom names what a document records about an entry's checksum from the two
// facts every caller already has: whether a checksum object is present, and the value it
// carries. 'hdf evidence bundle' names its unverifiable references through this, so the
// two surfaces cannot drift into describing one entry two ways.
func checksumStateFrom(recorded bool, value string) string {
	switch {
	case !recorded:
		return "no checksum recorded"
	case strings.TrimSpace(value) == "":
		return "checksum recorded but empty"
	default:
		return "checksum recorded"
	}
}

func recordedChecksumState(entry map[string]interface{}) string {
	raw, present := entry["checksum"]
	if !present {
		return checksumStateFrom(false, "")
	}
	cs, ok := raw.(map[string]interface{})
	if !ok {
		return "checksum unreadable"
	}
	value, isString := cs["value"].(string)
	// Shape failure stays here: it is a property of the raw JSON, which the fact-based
	// helper never sees.
	if !isString && cs["value"] != nil {
		return "checksum unreadable"
	}
	return checksumStateFrom(true, value)
}

func outputEvidenceInfoHuman(doc map[string]interface{}) error {
	// Package name
	if name, ok := doc["name"].(string); ok {
		fmt.Printf("Evidence Package: %s\n", sanitizeOutput(name))
	}

	// Prepared by
	if preparedBy, ok := doc["preparedBy"].(map[string]interface{}); ok {
		if id, ok := preparedBy["identifier"].(string); ok {
			fmt.Printf("Prepared by: %s\n", sanitizeOutput(id))
		}
	}

	// Prepared at
	if preparedAt, ok := doc["preparedAt"].(string); ok {
		fmt.Printf("Prepared at: %s\n", sanitizeOutput(preparedAt))
	}

	// System reference
	if sysRef, ok := doc["systemRef"].(string); ok {
		fmt.Printf("System: %s\n", sanitizeOutput(sysRef))
	}

	// Contents
	if contents, ok := doc["contents"].([]interface{}); ok && len(contents) > 0 {
		fmt.Printf("\nContents (%d):\n", len(contents))
		for _, cRaw := range contents {
			entry, ok := cRaw.(map[string]interface{})
			if !ok {
				continue
			}
			docType, _ := entry["type"].(string)
			uri, _ := entry["uri"].(string)

			fmt.Printf("  %-16s %s  %s\n", sanitizeOutput(docType), sanitizeOutput(uri),
				recordedChecksumState(entry))
		}
	}

	// External evidence (native log/telemetry corpora carried by reference)
	if ext, ok := doc["externalEvidence"].([]interface{}); ok && len(ext) > 0 {
		fmt.Printf("\nExternal Evidence (%d):\n", len(ext))
		for _, eRaw := range ext {
			entry, ok := eRaw.(map[string]interface{})
			if !ok {
				continue
			}
			format, _ := entry["format"].(string)
			uri, _ := entry["uri"].(string)

			fmt.Printf("  %-16s %s  %s\n", sanitizeOutput(format), sanitizeOutput(uri),
				recordedChecksumState(entry))
		}
	}

	// Completeness check
	if cc, ok := doc["completenessCheck"].(map[string]interface{}); ok {
		// Attributed to the document, not to this command. The schema calls this block
		// "Not authoritative — tools should compute these from the referenced documents",
		// so printing it under a bare "Completeness:" heading would present a claim this
		// path never established — the same defect as the presence-tick above, one field
		// over. --verify computes it instead of reading it.
		fmt.Printf("\nCompleteness, as recorded by the package (not computed here — use --verify):\n")

		if v, ok := cc["allBaselinesAssessed"].(bool); ok {
			fmt.Printf("  All baselines assessed: %s\n", boolYesNo(v))
		}
		if v, ok := cc["allComponentsCovered"].(bool); ok {
			fmt.Printf("  All components covered: %s\n", boolYesNo(v))
		}
		if v, ok := cc["expiredWaivers"].(float64); ok {
			fmt.Printf("  Expired waivers: %d\n", int64(v))
		}
		if v, ok := cc["unresolvedPoams"].(float64); ok {
			fmt.Printf("  Unresolved POA&Ms: %d\n", int64(v))
		}
		if v, ok := cc["compliancePercent"].(float64); ok {
			fmt.Printf("  Compliance: %.0f%%\n", v)
		}
	}

	return nil
}

// boolYesNo returns "yes" or "no" for a boolean value.
func boolYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
