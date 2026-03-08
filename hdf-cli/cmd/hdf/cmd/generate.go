package cmd

import (
	"github.com/spf13/cobra"
)

// NewGenerateCmd creates the generate parent command.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate <subcommand>",
		Short: "Generate security templates from HDF data",
		Long: `Generate security templates and profile skeletons from HDF data.

Available subcommands:
  inspec-profile    Generate InSpec profile from HDF Baseline`,
	}

	cmd.AddCommand(newGenerateInSpecProfileCmd())

	return cmd
}
