// hdf - A CLI tool for working with Heimdall Data Format (HDF) files
package main

import (
	"os"

	"github.com/mitre/hdf-cli/cmd/hdf/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
