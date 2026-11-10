package cmd

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"runtime"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// Values from the macOS SDK sys/fcntl.h and sys/acl.h.
const (
	archiveFilesecMode  = 4
	archiveFilesecACL   = 5
	archiveACLNoInherit = 1 << 17
)

type archiveDarwinAPI struct {
	filesecGet   func(uintptr, int32, *uintptr) int32
	aclValid     func(uintptr) int32
	aclEntry     uintptr
	calloc       func(uintptr, uintptr) uintptr
	library      uintptr
	statfs       func(int, *unix.Statfs_t) error
	aclInit      func(int32) uintptr
	aclFree      func(uintptr) int32
	aclFlags     func(uintptr, *uintptr) int32
	aclAddFlag   func(uintptr, uint32) int32
	filesecInit  func() uintptr
	filesecFree  func(uintptr)
	filesecMode  func(uintptr, int32, *uint16) int32
	filesecACL   func(uintptr, int32, *uintptr) int32
	filesecQuery func(uintptr, int32, *int32) int32
	duplicate    func(*byte) uintptr
	free         func(uintptr)
	openx        uintptr
	fstatx       func(int32, *unix.Stat_t, uintptr) int32
}

func loadArchiveDarwinAPI() (*archiveDarwinAPI, error) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("load archive security APIs: %w", err)
	}
	api, err := bindArchiveDarwinAPI(lib, purego.Dlsym)
	if err != nil {
		return nil, errors.Join(err, purego.Dlclose(lib))
	}
	return api, nil
}

func bindArchiveDarwinAPI(lib uintptr, resolve func(uintptr, string) (uintptr, error)) (*archiveDarwinAPI, error) {
	lookup := func(handle uintptr, name string) (uintptr, error) {
		address, err := resolve(handle, name)
		if err != nil {
			return 0, fmt.Errorf("resolve archive security symbol %s: %w", name, err)
		}
		if address == 0 {
			return 0, fmt.Errorf("archive security symbol %s is unavailable", name)
		}
		return address, nil
	}
	api := &archiveDarwinAPI{library: lib, statfs: unix.Fstatfs}
	var err error
	api.openx, err = lookup(lib, "openx_np")
	if err != nil {
		return nil, err
	}
	api.aclEntry, err = lookup(lib, "acl_get_entry")
	if err != nil {
		return nil, err
	}
	statSymbol := "fstatx_np"
	if runtime.GOARCH == "amd64" {
		statSymbol += "$INODE64"
	}
	for _, binding := range []struct {
		name   string
		target any
	}{
		{"acl_init", &api.aclInit}, {"acl_free", &api.aclFree},
		{"acl_get_flagset_np", &api.aclFlags}, {"acl_add_flag_np", &api.aclAddFlag},
		{"filesec_init", &api.filesecInit}, {"filesec_free", &api.filesecFree},
		{"filesec_set_property", &api.filesecMode}, {"filesec_set_property", &api.filesecACL},
		{"filesec_query_property", &api.filesecQuery},
		{"filesec_get_property", &api.filesecGet}, {"acl_valid", &api.aclValid}, {"calloc", &api.calloc},
		{"strdup", &api.duplicate}, {"free", &api.free}, {statSymbol, &api.fstatx},
	} {
		address, err := lookup(lib, binding.name)
		if err != nil {
			return nil, err
		}
		purego.RegisterFunc(binding.target, address)
	}
	return api, nil
}

func archiveDarwinInt(result, _ uintptr, errno uintptr) (uintptr, error) {
	if result&0x80000000 != 0 {
		return 0, archiveDarwinError(errno)
	}
	return result & 0x7fffffff, nil
}

func archiveDarwinError(errno uintptr) error {
	// Darwin errno is a C int; purego's captured value occupies a machine word.
	errno &= 0xffffffff
	if errno == 0 {
		return unix.EIO
	}
	return unix.Errno(errno)
}

func openPrivateArchive(path string) (*os.File, error) {
	api, err := loadArchiveDarwinAPI()
	if err != nil {
		return nil, err
	}
	defer purego.Dlclose(api.library)
	return openPrivateArchiveWithDarwinAPI(path, api)
}

func openPrivateArchiveWithDarwinAPI(path string, api *archiveDarwinAPI) (*os.File, error) {
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "create private archive", Path: path, Err: err}
	}
	acl := api.aclInit(0)
	if acl == 0 {
		return nil, fmt.Errorf("allocate private archive ACL")
	}
	defer api.aclFree(acl)
	var flags uintptr
	if api.aclFlags(acl, &flags) < 0 {
		return nil, fmt.Errorf("read private archive ACL flags")
	}
	if api.aclAddFlag(flags, archiveACLNoInherit) < 0 {
		return nil, fmt.Errorf("disable private archive ACL inheritance")
	}
	security := api.filesecInit()
	if security == 0 {
		return nil, fmt.Errorf("allocate private archive security descriptor")
	}
	defer api.filesecFree(security)
	mode := uint16(0o600)
	if api.filesecMode(security, archiveFilesecMode, &mode) < 0 {
		return nil, fmt.Errorf("set private archive mode")
	}
	if api.filesecACL(security, archiveFilesecACL, &acl) < 0 {
		return nil, fmt.Errorf("set private archive ACL")
	}
	copied := api.duplicate(name)
	if copied == 0 {
		return nil, fmt.Errorf("allocate private archive path")
	}
	defer api.free(copied)
	// Native-memory arguments preserve the trampoline's errno without Go pointer casts.
	fd, err := archiveDarwinInt(purego.SyscallN(api.openx, copied, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC, security))
	if err != nil {
		return nil, &os.PathError{Op: "create private archive", Path: path, Err: err}
	}
	file := os.NewFile(fd, path)
	if err := verifyDarwinArchiveACL(file, api); err != nil {
		return nil, errors.Join(err, file.Close(), os.Remove(path))
	}
	return file, nil
}

func verifyDarwinArchiveACL(file *os.File, api *archiveDarwinAPI) error {
	var filesystem unix.Statfs_t
	if err := api.statfs(int(file.Fd()), &filesystem); err != nil {
		return fmt.Errorf("query private archive filesystem: %w", err)
	}
	kind := unix.ByteSliceToString(filesystem.Fstypename[:])
	if (kind != "apfs" && kind != "hfs") || filesystem.Flags&unix.MNT_LOCAL == 0 || filesystem.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 {
		return fmt.Errorf("cannot establish private archive access on this filesystem; use supported local storage or --output-access inherit with a trusted destination")
	}
	if err := verifyArchiveOwner(file, unix.Fstat); err != nil {
		return err
	}
	security := api.filesecInit()
	if security == 0 {
		return fmt.Errorf("allocate private archive security readback")
	}
	defer api.filesecFree(security)
	var stat unix.Stat_t
	fd := file.Fd()
	if fd > math.MaxInt32 {
		return fmt.Errorf("invalid private archive file descriptor")
	}
	if api.fstatx(int32(fd), &stat, security) < 0 {
		return fmt.Errorf("read private archive security descriptor")
	}
	var present int32
	if api.filesecQuery(security, archiveFilesecACL, &present) < 0 {
		return fmt.Errorf("query private archive ACL")
	}
	if present == 0 {
		return nil
	}
	return verifyDarwinEmptyACL(security, api)
}

func verifyDarwinEmptyACL(security uintptr, api *archiveDarwinAPI) error {
	var acl uintptr
	if api.filesecGet(security, archiveFilesecACL, &acl) < 0 {
		return fmt.Errorf("read private archive ACL")
	}
	if acl == 0 {
		return fmt.Errorf("private archive ACL is missing")
	}
	defer api.aclFree(acl)
	if api.aclValid(acl) < 0 {
		return fmt.Errorf("private archive ACL is invalid")
	}
	entry := api.calloc(1, bits.UintSize/8)
	if entry == 0 {
		return fmt.Errorf("allocate private archive ACL entry")
	}
	defer api.free(entry)
	// Darwin reports EINVAL for the first entry of a valid empty ACL.
	_, err := archiveDarwinInt(purego.SyscallN(api.aclEntry, acl, 0, entry))
	if errors.Is(err, unix.EINVAL) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read private archive ACL entry: %w", err)
	}
	return fmt.Errorf("private archive retained an ACL entry")
}
