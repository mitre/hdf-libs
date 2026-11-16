//go:build linux

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const nfs4ACLAttr = "system.nfs4_acl"

// createPrivateFile creates the staged archive exclusively with mode 0600; a 0600
// create also sets a POSIX ACL's mask to none, so no inherited entry takes effect.
func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
}

func platformPrivateCheck(f *os.File) error {
	return checkLinuxPrivate(int(f.Fd()), unix.Fgetxattr, unix.Fstatfs, os.Stderr)
}

// checkLinuxPrivate adds what the mode readback cannot see. On NFSv4 the server must
// make OWNER@, GROUP@ and EVERYONE@ match the create mode, but trimming an inherited
// named entry is only recommended (RFC 8881 section 6.4.3), so a 0600 file can still
// be shared; the ACL is read from the open file and such an entry is refused. On
// network or userspace storage, one note says the server also controls access.
func checkLinuxPrivate(fd int, getxattr func(int, string, []byte) (int, error),
	fstatfs func(int, *unix.Statfs_t) error, notes io.Writer) error {
	if err := checkNFS4ACL(fd, getxattr); err != nil {
		return err
	}
	var st unix.Statfs_t
	if fstatfs(fd, &st) == nil {
		if kind := networkStorage(fsMagic(st.Type)); kind != "" {
			_, _ = fmt.Fprintf(notes, "Note: the archive is on %s storage; "+
				"the server and its mount options also control who can read it.\n", kind)
		}
	}
	return nil
}

// checkNFS4ACL reads system.nfs4_acl from the open file. ENODATA and EOPNOTSUPP mean
// there is no NFSv4 ACL, on the size probe or on the read (the attribute can change
// between them); any other failure means the check could not be made.
func checkNFS4ACL(fd int, getxattr func(int, string, []byte) (int, error)) error {
	size, err := getxattr(fd, nfs4ACLAttr, nil)
	if noNFS4ACL(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's NFSv4 ACL: %w", err)
	}
	// A zero-length buffer would make the read a second size query, and no valid ACL
	// is shorter than its four-byte entry count.
	if size < 4 {
		return fmt.Errorf("cannot read the staged archive's NFSv4 ACL: %d bytes is shorter than any ACL", size)
	}
	buf := make([]byte, size)
	n, err := getxattr(fd, nfs4ACLAttr, buf)
	if noNFS4ACL(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's NFSv4 ACL: %w", err)
	}
	if n < 0 || n > len(buf) {
		return fmt.Errorf("cannot read the staged archive's NFSv4 ACL: read %d bytes into %d", n, len(buf))
	}
	aces, err := decodeNFS4ACL(buf[:n])
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's NFSv4 ACL: %w", err)
	}
	if who, ok := grantsAccessToOthers(aces); ok {
		return fmt.Errorf("cannot create a private archive here: an NFSv4 ACL entry gives %s "+
			"access to it; remove that entry from the directory, or pass --output-access inherit "+
			"if that sharing is intended", who)
	}
	return nil
}

func noNFS4ACL(err error) bool {
	return errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP)
}

// fsMagic widens Statfs_t.Type (int64, int32 or uint32 by architecture) to the
// kernel's unsigned 32-bit magic: a 32-bit signed field holds the larger magics as
// negative numbers, so those are folded back.
func fsMagic[T int32 | int64 | uint32](t T) int64 {
	v := int64(t)
	if v < 0 {
		v += 1 << 32
	}
	return v
}

// networkStorage names the storage kinds whose access the server also controls.
func networkStorage(magic int64) string {
	switch magic {
	case unix.NFS_SUPER_MAGIC:
		return "NFS"
	case unix.SMB_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC:
		return "SMB"
	case unix.FUSE_SUPER_MAGIC:
		return "FUSE"
	case unix.V9FS_MAGIC:
		return "9p"
	default:
		return ""
	}
}
