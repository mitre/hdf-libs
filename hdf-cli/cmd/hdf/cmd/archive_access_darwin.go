//go:build darwin

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Values from the macOS SDK: sys/fcntl.h (filesec properties) and sys/acl.h.
const (
	filesecMode      = 4
	filesecACL       = 5
	aclFlagNoInherit = 1 << 17
	aclTypeExtended  = 0x100
	aclFirstEntry    = 0
	// A C int comes back in a machine word; only its low 32 bits are the value.
	cIntMask, cIntSign = 0xffff_ffff, 0x8000_0000
)

// darwinSecurity binds the libSystem file-security functions Go does not expose. Release
// builds disable cgo, so they are called through purego.
type darwinSecurity struct {
	lib            uintptr
	openx          uintptr // openx_np, called through SyscallN to capture errno
	aclInit        func(count int32) uintptr
	aclFree        func(obj uintptr) int32
	aclGetFlagset  func(acl uintptr, flags *uintptr) int32
	aclAddFlag     func(flags uintptr, flag uint32) int32
	filesecInit    func() uintptr
	filesecFree    func(fsec uintptr)
	filesecSetMode func(fsec uintptr, property uint32, mode *uint16) int32
	filesecSetACL  func(fsec uintptr, property uint32, acl *uintptr) int32
	aclGetFd       func(fd int) (acl uintptr, errno unix.Errno)
	aclGetEntry    func(acl uintptr, entryID int32, entry *uintptr) int32
}

func loadDarwinSecurity() (*darwinSecurity, error) {
	return loadDarwinSecurityWith(purego.Dlopen, purego.Dlsym, purego.Dlclose)
}

func loadDarwinSecurityWith(dlopen func(string, int) (uintptr, error),
	dlsym func(uintptr, string) (uintptr, error), dlclose func(uintptr) error) (*darwinSecurity, error) {
	lib, err := dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("cannot load the macOS file-security functions: %w", err)
	}
	s := &darwinSecurity{lib: lib}
	if err := s.bind(dlsym); err != nil {
		return nil, errors.Join(err, dlclose(lib))
	}
	return s, nil
}

func (s *darwinSecurity) bind(dlsym func(uintptr, string) (uintptr, error)) error {
	lookup := func(name string) (uintptr, error) {
		addr, err := dlsym(s.lib, name)
		if err != nil {
			return 0, fmt.Errorf("cannot find %s in libSystem: %w", name, err)
		}
		return addr, nil
	}
	var err error
	if s.openx, err = lookup("openx_np"); err != nil {
		return err
	}
	getFd, err := lookup("acl_get_fd_np")
	if err != nil {
		return err
	}
	s.aclGetFd = func(fd int) (uintptr, unix.Errno) {
		acl, _, errno := purego.SyscallN(getFd, uintptr(fd), aclTypeExtended)
		return acl, unix.Errno(errno & cIntMask)
	}
	for _, b := range []struct {
		name string
		fn   any
	}{
		{"acl_init", &s.aclInit}, {"acl_free", &s.aclFree},
		{"acl_get_flagset_np", &s.aclGetFlagset}, {"acl_add_flag_np", &s.aclAddFlag},
		{"filesec_init", &s.filesecInit}, {"filesec_free", &s.filesecFree},
		{"filesec_set_property", &s.filesecSetMode}, {"filesec_set_property", &s.filesecSetACL},
		{"acl_get_entry", &s.aclGetEntry},
	} {
		addr, err := lookup(b.name)
		if err != nil {
			return err
		}
		purego.RegisterFunc(b.fn, addr)
	}
	return nil
}

// createPrivateFile creates the staged archive with mode 0600 and an empty ACL marked
// non-inheriting, in the same call, so no entry inherited from the directory ever
// applies to it; os.OpenFile would let the directory's inheritable entries in.
func createPrivateFile(path string) (*os.File, error) {
	s, err := loadDarwinSecurity()
	if err != nil {
		return nil, err
	}
	defer func() { _ = purego.Dlclose(s.lib) }()
	return s.createPrivate(path)
}

func (s *darwinSecurity) createPrivate(path string) (*os.File, error) {
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	acl := s.aclInit(0)
	if acl == 0 {
		return nil, errors.New("cannot allocate the staged archive's ACL")
	}
	defer s.aclFree(acl)
	var flags uintptr
	if s.aclGetFlagset(acl, &flags) != 0 || s.aclAddFlag(flags, aclFlagNoInherit) != 0 {
		return nil, errors.New("cannot mark the staged archive's ACL as non-inheriting")
	}
	fsec := s.filesecInit()
	if fsec == 0 {
		return nil, errors.New("cannot allocate the staged archive's file security")
	}
	defer s.filesecFree(fsec)
	mode := uint16(0o600)
	if s.filesecSetMode(fsec, filesecMode, &mode) != 0 || s.filesecSetACL(fsec, filesecACL, &acl) != 0 {
		return nil, errors.New("cannot set the staged archive's mode and ACL")
	}
	fd, _, errno := purego.SyscallN(s.openx, uintptr(unsafe.Pointer(name)),
		uintptr(unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC), fsec)
	if fd &= cIntMask; fd&cIntSign != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: darwinErrno(errno)}
	}
	return os.NewFile(fd, path), nil
}

// darwinErrno reads the captured errno, a C int in a machine word.
func darwinErrno(errno uintptr) error {
	if e := unix.Errno(errno & cIntMask); e != 0 {
		return e
	}
	return unix.EIO
}

// platformPrivateCheck reads the ACL from the open file. Any entry is refused: an
// entry grants or denies access whatever the mode bits say.
func platformPrivateCheck(f *os.File) error {
	s, err := loadDarwinSecurity()
	if err != nil {
		return err
	}
	defer func() { _ = purego.Dlclose(s.lib) }()
	if err := checkDarwinVolume(int(f.Fd()), unix.Fstatfs, os.Stderr); err != nil {
		return err
	}
	return s.checkACL(f)
}

func (s *darwinSecurity) checkACL(f *os.File) error {
	acl, errno := s.aclGetFd(int(f.Fd()))
	if acl == 0 {
		if errno == unix.ENOENT {
			return nil
		}
		return fmt.Errorf("cannot read the staged archive's ACL: %w", errno)
	}
	defer s.aclFree(acl)
	var entry uintptr
	if s.aclGetEntry(acl, aclFirstEntry, &entry) == 0 {
		return errors.New("cannot create a private archive here: the file received an ACL " +
			"entry, which grants access whatever its mode says; remove the inheritable entry " +
			"from the directory (ls -le shows it), or pass --output-access inherit if that " +
			"sharing is intended")
	}
	return nil
}

// checkDarwinVolume refuses a volume mounted to ignore ownership: macOS then reports
// every user as the owner and enforces no permissions, so the mode readback proves
// nothing. A network volume is checked like any other, with one note that the server
// and its mount options also control access.
func checkDarwinVolume(fd int, fstatfs func(int, *unix.Statfs_t) error, notes io.Writer) error {
	var st unix.Statfs_t
	if err := fstatfs(fd, &st); err != nil {
		return fmt.Errorf("cannot read the staged archive's volume: %w", err)
	}
	if st.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 {
		return errors.New("cannot create a private archive here: the volume ignores ownership, " +
			"so file permissions are not enforced; write to local storage, or pass " +
			"--output-access inherit if this location's access policy is trusted")
	}
	if st.Flags&unix.MNT_LOCAL == 0 {
		_, _ = fmt.Fprintf(notes, "Note: the archive is on network storage (%s); "+
			"the server and its mount options also control who can read it.\n",
			unix.ByteSliceToString(st.Fstypename[:]))
	}
	return nil
}
