//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is the FA right: every standard and file-specific right.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

var errNotCreatorOnly = errors.New("cannot create a private archive here: the file's access " +
	"list grants more than its creator; pass --output-access inherit if this location's " +
	"access policy is trusted")

func openPrivateArchive(path string) (*os.File, error) {
	return createPrivateWindows(path, volumeACLFlags)
}

// createPrivateWindows creates path with a protected DACL whose one entry grants the
// effective user full access, so none of the directory's inheritable grants apply; a
// mode passed to os.OpenFile only sets the read-only attribute on Windows. Before the
// file is returned, the volume must keep ACLs and the DACL must read back as exactly
// that entry; otherwise the file is closed and removed.
func createPrivateWindows(path string, volumeFlags func(windows.Handle) (uint32, error)) (*os.File, error) {
	return createPrivateWindowsWith(path, effectiveUser, volumeFlags)
}

// createPrivateWindowsWith takes the user lookup so a test can drive its failure.
func createPrivateWindowsWith(path string, currentUser func() (*windows.SID, error),
	volumeFlags func(windows.Handle) (uint32, error)) (*os.File, error) {
	user, err := currentUser()
	if err != nil {
		return nil, fmt.Errorf("cannot read the effective user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("cannot build the archive's access list: %w", err)
	}
	full, err := archiveWindowsName(path, windows.FullPath)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	name, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	if err := checkPrivateWindows(h, user, volumeFlags); err != nil {
		return nil, discardStaged(f, path, err)
	}
	return f, nil
}

// effectiveUser reads the user of the effective token. An impersonation token belongs
// to the OS thread, so the goroutine stays on its thread while reading it.
func effectiveUser() (*windows.SID, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	u, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

func checkPrivateWindows(h windows.Handle, user *windows.SID, volumeFlags func(windows.Handle) (uint32, error)) error {
	flags, err := volumeFlags(h)
	if err != nil {
		return fmt.Errorf("cannot read the volume's capabilities: %w", err)
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return errors.New("cannot create a private archive here: the volume does not keep " +
			"file access lists (FAT or exFAT); write to an ACL-capable volume such as NTFS, or " +
			"pass --output-access inherit if this location's access policy is trusted")
	}
	return verifyPrivateDACL(h, user)
}

func volumeACLFlags(h windows.Handle) (uint32, error) {
	var flags uint32
	err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0)
	return flags, err
}

// verifyPrivateDACL reads the DACL back from the handle and requires what creation
// asked for: protected, one allow entry that is neither inherited nor inheritable,
// full access, for user. It compares the SID and mask themselves, not SDDL text.
func verifyPrivateDACL(h windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's access list: %w", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's access list: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("cannot read the staged archive's access list: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 || dacl == nil || dacl.AceCount != 1 {
		return errNotCreatorOnly
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("cannot read the staged archive's access list: %w", err)
	}
	grantee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 ||
		ace.Mask != fileAllAccess || !grantee.Equals(user) {
		return errNotCreatorOnly
	}
	return nil
}
