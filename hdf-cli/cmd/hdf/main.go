// hdf - A CLI tool for working with Heimdall Data Format (HDF) files
package main

import (
	"fmt"
	"os"

	"github.com/mitre/hdf-libs/hdf-cli/v3/cmd/hdf/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		code, report := cmd.ExitStatus(err)
		if report {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(code)
	}
}
