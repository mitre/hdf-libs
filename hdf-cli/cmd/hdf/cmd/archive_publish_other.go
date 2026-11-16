//go:build unix && !linux && !darwin

package cmd

import "golang.org/x/sys/unix"

// renameNoReplace has no exclusive rename to call here, so publication uses the
// hard link, which refuses an existing name.
func renameNoReplace(_, _ string) error { return unix.ENOSYS }

func renameUnsupported(err error) bool { return err == unix.ENOSYS }
