//nolint:dupl
package cmd

import (
	"fmt"

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
			return runGenericDocSet(args[0], outputPath, unsetFields, requiredEvidenceFields, map[string]string{
				"name":        name,
				"description": description,
				"packageId":   packageID,
				"systemRef":   systemRef,
				"planRef":     planRef,
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
