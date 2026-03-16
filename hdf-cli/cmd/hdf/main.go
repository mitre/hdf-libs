// hdf - A CLI tool for working with Heimdall Data Format (HDF) files
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/mitre/hdf-cli/cmd/hdf/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		// Check if the error carries a specific exit code (e.g., from diff --exit-code
		// or diff --detailed-exitcode).
		var ec cmd.ExitCoder
		if errors.As(err, &ec) {
			os.Exit(ec.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
