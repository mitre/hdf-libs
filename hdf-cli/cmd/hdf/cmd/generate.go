package cmd

import (
	"github.com/spf13/cobra"
)

// NewGenerateCmd creates the generate parent command.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate <subcommand>",
		Short: "Generate security templates from HDF or XCCDF data",
		Long: `Generate security templates and profile skeletons from HDF Baseline
JSON or XCCDF Benchmark XML.

Available subcommands:
  inspec-profile    Generate InSpec profile from HDF Baseline or XCCDF Benchmark
  threshold         Generate compliance threshold template from HDF results
  upgrade           Upgrade baseline with new upstream metadata, preserving customizations
                    (alias: delta)`,
	}

	cmd.AddCommand(newGenerateInSpecProfileCmd())
	cmd.AddCommand(newGenerateThresholdCmd())
	cmd.AddCommand(newGenerateUpgradeCmd())

	return cmd
}
