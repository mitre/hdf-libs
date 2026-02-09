// hdf - A CLI tool for working with Heimdall Data Format (HDF) files
package main

import (
	"fmt"
	"os"

	"github.com/mitre/hdf-cli/cmd/hdf/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
