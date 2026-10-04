//nolint:dupl
package cmd

import (
	"fmt"
	"path/filepath"

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
func packageRelativeIfInside(pkgDir, ref string) string {
	if ref == "" || isRemoteURI(ref) || !filepath.IsAbs(ref) {
		return ref
	}
	if resolved, ok := packageSubtreeRef(pkgDir, ref); ok {
		return resolved
	}
	return ref
}
