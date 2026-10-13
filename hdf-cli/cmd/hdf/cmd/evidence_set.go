//nolint:dupl
package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	"github.com/spf13/cobra"
)

func newEvidenceSetCmd() *cobra.Command {
	var (
		name        string
		description string
		packageID   string
		systemRef   string
		planRef     string
		docVersion  string
		outputPath  string
		unsetFields []string
	)

	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Set, update, or unset top-level fields on an HDF evidence package",
		Long: `Set, update, or remove top-level metadata fields on an existing HDF evidence package.
Reads the file, applies the specified changes, and writes it back (or to -o).

Use --unset to remove optional fields. Required fields (name, contents) cannot be unset.

--system-ref and --plan-ref are recorded as references read by whoever opens the package, not as
paths on this machine: an absolute path resolving INSIDE the package's directory is recorded
relative to the package, exactly as 'hdf evidence build' records one. A reference to something
the package does not contain — an absolute path elsewhere, a parent traversal, or a remote URI —
is recorded exactly as given, because rewriting it would claim the artifact is somewhere it is
not.

An ABSOLUTE value is treated as a path on this machine and recorded as a uri-reference, so a
name needing escapes is escaped for you. A RELATIVE value is treated as a reference already
and recorded as you wrote it — so write it the way the format admits ('my%20scans/sys.json',
not 'my scans/sys.json'). Both resolve, but only the escaped spelling is a legal
uri-reference.

Examples:
  hdf evidence set evidence.json --name "Q2 2026 Evidence"
  hdf evidence set evidence.json --package-id "550e8400-..."
  hdf evidence set evidence.json --system-ref portal-prod.hdf-system.json
  hdf evidence set evidence.json --plan-ref quarterly-plan.hdf-plan.json
  hdf evidence set evidence.json --unset description -o updated.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if name == "" && description == "" && packageID == "" && systemRef == "" && planRef == "" && docVersion == "" && len(unsetFields) == 0 {
				return fmt.Errorf("at least one field flag is required (--name, --description, --package-id, --system-ref, --plan-ref, --version, --unset)")
			}
			// Normalized against the INPUT package's directory, which is where the documents
			// sit. Whether -o moving the package should re-base its references is a separate
			// question and belongs to the -o coverage card, not here.
			pkgDir := filepath.Dir(args[0])
			return runGenericDocSet(args[0], outputPath, "evidence-package", unsetFields, requiredEvidenceFields, map[string]string{
				"name":        name,
				"description": description,
				"packageId":   packageID,
				"systemRef":   packageRelativeIfInside(pkgDir, systemRef),
				"planRef":     packageRelativeIfInside(pkgDir, planRef),
				"version":     docVersion,
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Package name")
	cmd.Flags().StringVar(&description, "description", "", "Package description")
	cmd.Flags().StringVar(&packageID, "package-id", "", "Package UUID")
	cmd.Flags().StringVar(&systemRef, "system-ref", "", "URI to the target HDF system document")
	cmd.Flags().StringVar(&planRef, "plan-ref", "", "URI to the assessment plan document")
	cmd.Flags().StringVar(&docVersion, "version", "", "Package version")
	cmd.Flags().StringArrayVar(&unsetFields, "unset", nil, "Remove a field (repeatable)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

var requiredEvidenceFields = map[string]bool{
	"name":     true,
	"contents": true,
}

// packageRelativeIfInside rewrites an ABSOLUTE reference resolving inside the package's
// directory to the package-relative form `build` already records, and returns anything
// else untouched. A reference is data read by whoever opens the package, not a path on the
// machine that wrote it, so a machine-local absolute path does not survive being handed on
// — it bundles into an archive carrying the file under a relative name while the package
// still names the original path. A reference pointing OUTSIDE the package is a legitimate
// external reference by standing decision and is recorded exactly as given: rewriting it
// would claim the artifact is somewhere it is not. Resolution goes through
// packageSubtreeRef, the one predicate bundle and verify already use.
// THE SPLIT IS THE CONTRACT, decided deliberately (maintainer, 2026-10-13): an ABSOLUTE
// value is a path on this machine, so it is resolved, relativized and ENCODED into a
// uri-reference; a RELATIVE value is already a reference and is recorded as given.
//
// Why not encode a relative value too, which would make every recorded reference
// schema-perfect: an operator who correctly passes "my%20scans/sys.json" would get
// "my%2520scans/sys.json", a double-encode and a worse defect than the one it fixes.
// Telling a raw path from an encoded reference requires inferring from whether the value
// contains a %, which 52n0c.31's anti-patterns forbid outright — it would make what is
// recorded depend on the filename. Refusing an unescaped relative value was the third
// option and was declined because it breaks usage that works today: measured, all three
// shapes verify, since decoding leaves a literal space alone.
//
// So the cost accepted here is that a relative value containing a character
// uri-reference does not admit is recorded as the operator wrote it. It RESOLVES
// correctly — that is measured — but it is not a spelling the format admits, and the
// operator owns that because they supplied a reference rather than a path.
func packageRelativeIfInside(pkgDir, ref string) string {
	if ref == "" || isRemoteURI(ref) || !filepath.IsAbs(ref) {
		return ref
	}
	// Decoded before resolving and re-encoded by nothing: what this returns is a
	// reference to RECORD, and recording the decoded form would write a value the schema
	// calls malformed if the name contains a character uri-reference does not admit.
	// So a reference that resolves inside the package is rewritten to its relative form
	// only when that form needs no escaping — otherwise the absolute spelling stands,
	// which the caller already reports.
	decoded, decErr := evidenceref.Decode(ref)
	if decErr != nil {
		return ref
	}
	if resolved, ok := packageSubtreeRef(pkgDir, decoded); ok {
		// RE-ENCODED, because what this returns is a reference to RECORD and the field is
		// a uri-reference: writing the decoded form would store a value the schema calls
		// malformed the moment the name contains a space. Per SEGMENT, since PathEscape
		// escapes a separator too — escaping the whole path turned every ordinary
		// "scans/x.json" into "scans%2Fx.json", which is why the first attempt at this
		// guard silently stopped normalizing anything.
		return evidenceref.Encode(string(resolved))
	}
	return ref
}
