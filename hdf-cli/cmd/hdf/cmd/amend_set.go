//nolint:dupl
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAmendSetCmd() *cobra.Command {
	var (
		name        string
		description string
		amendmentID string
		systemRef   string
		docVersion  string
		outputPath  string
		unsetFields []string
	)

	cmd := &cobra.Command{
		Use:   "set <file>",
		Short: "Set, update, or unset top-level fields on an HDF amendments document",
		Long: `Set, update, or remove top-level metadata fields on an existing HDF amendments document.
Reads the file, applies the specified changes, and writes it back (or to -o).

Use --unset to remove optional fields. Required fields (name, overrides) cannot be unset.

Examples:
  hdf amend set waivers.json --name "Q2 Waivers"
  hdf amend set waivers.json --amendment-id "550e8400-..."
  hdf amend set waivers.json --system-ref portal-prod.hdf-system.json
  hdf amend set waivers.json --unset description -o updated.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if name == "" && description == "" && amendmentID == "" && systemRef == "" && docVersion == "" && len(unsetFields) == 0 {
				return fmt.Errorf("at least one field flag is required (--name, --description, --amendment-id, --system-ref, --version, --unset)")
			}
			return runGenericDocSet(args[0], outputPath, "amendments", unsetFields, requiredAmendFields, map[string]string{
				"name":        name,
				"description": description,
				"amendmentId": amendmentID,
				"systemRef":   systemRef,
				"version":     docVersion,
			})
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Document name")
	cmd.Flags().StringVar(&description, "description", "", "Document description")
	cmd.Flags().StringVar(&amendmentID, "amendment-id", "", "Amendment UUID")
	cmd.Flags().StringVar(&systemRef, "system-ref", "", "URI to the target HDF system document")
	cmd.Flags().StringVar(&docVersion, "version", "", "Document version")
	cmd.Flags().StringArrayVar(&unsetFields, "unset", nil, "Remove a field (repeatable)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file (default: overwrite input)")

	return cmd
}

var requiredAmendFields = map[string]bool{
	"name":      true,
	"overrides": true,
}
