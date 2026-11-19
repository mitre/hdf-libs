//go:build unix

package cmd

import (
	"fmt"
	"os"
	"syscall"
)

func openPrivateArchive(path string) (*os.File, error) {
	return openPrivateArchiveWith(path, fstatOwnerMode)
}

// openPrivateArchiveWith creates the file owner-only and reads the owner and mode back
// from it, then applies the platform's own check; a file that fails either is removed.
func openPrivateArchiveWith(path string,
	ownerMode func(*os.File) (uid, mode uint32, err error)) (*os.File, error) {
	f, err := createPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if err := verifyOwnerOnly(f, ownerMode); err != nil {
		return nil, discardStaged(f, path, err)
	}
	if err := platformPrivateCheck(f); err != nil {
		return nil, discardStaged(f, path, err)
	}
	return f, nil
}

// fstatOwnerMode reads the owner and mode of the open file (File.Stat is fstat on the
// descriptor), so nothing is read by path.
func fstatOwnerMode(f *os.File) (uid, mode uint32, err error) {
	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("the staged archive reports no owner")
	}
	return st.Uid, uint32(info.Mode().Perm()), nil
}

// verifyOwnerOnly reads the owner and mode back from the open file. A filesystem whose
// mode does not show the 0600 it was asked for (a default SMB mount reads back 0755,
// FAT its mount mask) is refused here rather than trusted.
func verifyOwnerOnly(f *os.File, ownerMode func(*os.File) (uid, mode uint32, err error)) error {
	uid, mode, err := ownerMode(f)
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's permissions: %w", err)
	}
	perm := mode & 0o777
	if int64(uid) != int64(os.Geteuid()) || perm&0o077 != 0 {
		return fmt.Errorf("cannot create a private archive here: the file was created with "+
			"mode %04o and owner uid %d (owner-only required); write to local storage, or pass "+
			"--output-access inherit if this location's access policy is trusted", perm, uid)
	}
	return nil
}
