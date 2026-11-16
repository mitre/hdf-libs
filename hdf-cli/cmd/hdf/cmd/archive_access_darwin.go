//go:build darwin

package cmd

import "os"

// platformPrivateCheck has nothing to add on macOS yet beyond the owner and mode
// readback; the macOS ACL check belongs here.
func platformPrivateCheck(*os.File) error { return nil }
