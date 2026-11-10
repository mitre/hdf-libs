//go:build !windows && !darwin && !linux

package cmd

import (
	"fmt"
	"os"
)

func openPrivateArchive(path string) (*os.File, error) {
	return nil, fmt.Errorf("cannot establish private archive access on this platform; use --output-access inherit only with a trusted destination")
}
