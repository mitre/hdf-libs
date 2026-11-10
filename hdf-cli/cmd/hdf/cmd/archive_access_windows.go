package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openPrivateArchive(path string) (*os.File, error) {
	// An impersonation token belongs to the OS thread, not the goroutine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read effective archive identity: %w", err)
	}
	security, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("build private archive security descriptor: %w", err)
	}
	name, err := archiveWindowsPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve private archive path: %w", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: security,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create private archive", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if err := verifyWindowsArchiveAccess(handle, security); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(path))
	}
	return file, nil
}

func archiveWindowsPath(path string) (*uint16, error) {
	full, err := archiveWindowsName(path, windows.FullPath)
	if err != nil {
		return nil, err
	}
	return windows.UTF16PtrFromString(full)
}

func verifyWindowsArchiveAccess(handle windows.Handle, expected *windows.SECURITY_DESCRIPTOR) error {
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return fmt.Errorf("cannot verify private archive filesystem: %w", err)
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return fmt.Errorf("cannot establish private archive access: the filesystem does not enforce ACLs; use an ACL-capable volume such as NTFS")
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read private archive DACL: %w", err)
	}
	if actual == nil || !actual.IsValid() {
		return fmt.Errorf("private archive security descriptor is unavailable or invalid")
	}
	control, _, err := actual.Control()
	if err != nil {
		return fmt.Errorf("read private archive DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private archive DACL permits inheritance")
	}
	// Normalize inheritance history on the readback copy; never modify the file.
	if err := actual.SetControl(windows.SE_DACL_AUTO_INHERIT_REQ|windows.SE_DACL_AUTO_INHERITED, 0); err != nil {
		return fmt.Errorf("normalize private archive DACL readback: %w", err)
	}
	want := expected.String()
	if want == "" || actual.String() != want {
		return fmt.Errorf("private archive DACL does not grant access exclusively to the effective user")
	}
	return nil
}
