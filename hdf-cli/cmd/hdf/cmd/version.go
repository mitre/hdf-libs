package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// NewVersionCmd creates a new version command with fresh state.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print the version, commit hash, build date, and Go version.`,
		Run: func(_ *cobra.Command, _ []string) {
			if jsonOutput {
				info := map[string]string{
					"version":    version,
					"commit":     commit,
					"date":       date,
					"go_version": runtime.Version(),
					"os":         runtime.GOOS,
					"arch":       runtime.GOARCH,
				}
				output, _ := json.MarshalIndent(info, "", "  ")
				fmt.Println(string(output))
				return
			}

			fmt.Printf("hdf version %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", date)
			fmt.Printf("  go:      %s\n", runtime.Version())
			fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
