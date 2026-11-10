//go:build linux || darwin

package cmd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func verifyArchiveOwner(file *os.File, stat func(int, *unix.Stat_t) error) error {
	var ownership unix.Stat_t
	if err := stat(int(file.Fd()), &ownership); err != nil {
		return fmt.Errorf("read private archive ownership: %w", err)
	}
	if int64(ownership.Uid) != int64(os.Geteuid()) || ownership.Mode&0o077 != 0 {
		return fmt.Errorf("private archive owner or permissions could not be established")
	}
	return nil
}
