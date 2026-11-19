//go:build darwin

package cmd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var aclEntryLine = regexp.MustCompile(`(?m)^\s*\d+: `)

// aclEntries lists a file's ACL entries as ls -le prints them, independently of the
// code under test.
func aclEntries(t *testing.T, path string) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "/bin/ls", "-led", path).CombinedOutput()
	require.NoError(t, err, string(out))
	return aclEntryLine.FindAllString(string(out), -1)
}

// shareNewFiles gives everyone read access to every file later created in dir, the way
// a team folder is commonly set up on macOS.
func shareNewFiles(t *testing.T, dir string) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone allow read,file_inherit", dir).CombinedOutput()
	require.NoError(t, err, string(out))
}

// On macOS an inherited ACL entry grants access whatever the mode bits say, so a private
// archive must be created without one; under inherit the directory's sharing applies.
func TestArchiveAccessDarwinPrivateBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	out := filepath.Join(dir, "shared")
	require.NoError(t, os.Mkdir(out, 0o755))
	shareNewFiles(t, out)
	private := filepath.Join(out, "private.zip")
	inherited := filepath.Join(out, "inherited.zip")

	_, _, err := executeCommand("evidence", "bundle", pkgPath, "-o", private)
	require.NoError(t, err)
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", inherited, "--output-access", "inherit")
	require.NoError(t, err)

	info, err := os.Stat(private)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Empty(t, aclEntries(t, private), "private carries no ACL entry")
	assert.Len(t, aclEntries(t, inherited), 1, "inherit takes the directory's sharing")
}

// The check reads the ACL from the open file: any entry is refused, since an entry can
// grant what the mode does not; no ACL, or the empty one private creation sets, passes.
func TestArchiveAccessDarwinReadbackRefusesAnyACLEntry(t *testing.T) {
	shared := t.TempDir()
	shareNewFiles(t, shared)
	withEntry, err := os.OpenFile(filepath.Join(shared, "inherited"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = withEntry.Close() })
	require.Len(t, aclEntries(t, withEntry.Name()), 1, "precondition: the file inherited the entry")

	err = platformPrivateCheck(withEntry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACL")

	plain, err := os.CreateTemp(t.TempDir(), "plain")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	assert.NoError(t, platformPrivateCheck(plain), "a file with no ACL passes")

	created, err := createPrivateFile(filepath.Join(shared, "private"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = created.Close() })
	assert.NoError(t, platformPrivateCheck(created), "the empty non-inheriting ACL passes")
}

// ENOENT is the only "no ACL" answer; any other failure means the check was not made.
func TestArchiveAccessDarwinACLReadFailureFails(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "staged")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	reading := func(errno unix.Errno) *darwinSecurity {
		return &darwinSecurity{aclGetFd: func(int) (uintptr, unix.Errno) { return 0, errno }}
	}

	assert.NoError(t, reading(unix.ENOENT).checkACL(f))
	assert.NoError(t, reading(unix.ENOTSUP).checkACL(f))
	for _, errno := range []unix.Errno{unix.EIO, unix.EBADF, unix.EACCES} {
		err := reading(errno).checkACL(f)
		require.Error(t, err, errno.Error())
		assert.ErrorIs(t, err, errno)
	}
}

func fakeVolume(flags uint32, fstype string) func(int, *unix.Statfs_t) error {
	return func(_ int, st *unix.Statfs_t) error {
		st.Flags = flags
		copy(st.Fstypename[:], fstype)
		return nil
	}
}

// A volume mounted to ignore ownership (an external drive, typically) shows every user
// as the owner and enforces nothing, so it is refused. A network volume is checked like
// any other and gets one note; it is not refused for its type.
func TestArchiveAccessDarwinVolume(t *testing.T) {
	var notes bytes.Buffer
	require.NoError(t, checkDarwinVolume(3, fakeVolume(unix.MNT_LOCAL, "apfs"), &notes))
	assert.Empty(t, notes.String(), "local storage gets no note")

	err := checkDarwinVolume(3, fakeVolume(unix.MNT_LOCAL|unix.MNT_IGNORE_OWNERSHIP, "msdos"), &notes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ignores ownership")

	require.NoError(t, checkDarwinVolume(3, fakeVolume(0, "smbfs"), &notes))
	var want bytes.Buffer
	noteNetworkStorage(&want, "smbfs")
	assert.Equal(t, want.String(), notes.String(), "the shared note, naming the volume's filesystem")

	failing := func(int, *unix.Statfs_t) error { return unix.EIO }
	assert.ErrorIs(t, checkDarwinVolume(3, failing, &notes), unix.EIO, "an unreadable volume fails")
}

// A libSystem without one of the functions gives an error naming it, never a crash or a
// fallback to ordinary creation, and the library handle is released.
func TestArchiveAccessDarwinMissingFunction(t *testing.T) {
	const lib = uintptr(0x1000)
	for _, missing := range []string{"openx_np", "acl_get_fd_np", "acl_get_entry"} {
		t.Run(missing, func(t *testing.T) {
			closed := 0
			dlopen := func(string, int) (uintptr, error) { return lib, nil }
			dlsym := func(_ uintptr, name string) (uintptr, error) {
				if name == missing {
					return 0, errors.New("symbol not found")
				}
				return 0x2000, nil
			}
			dlclose := func(h uintptr) error {
				assert.Equal(t, lib, h)
				closed++
				return nil
			}
			s, err := loadDarwinSecurityWith(dlopen, dlsym, dlclose)
			require.Error(t, err)
			assert.Nil(t, s)
			assert.Contains(t, err.Error(), missing)
			assert.Equal(t, 1, closed, "the library is released")
		})
	}
}

// An existing name fails as a path error that callers recognize as fs.ErrExist (the
// staging retry depends on it), and nothing is overwritten; a NUL in the path is refused.
func TestArchiveAccessDarwinCreateErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taken")
	require.NoError(t, os.WriteFile(path, []byte("kept"), 0o600))

	_, err := createPrivateFile(path)
	var pathErr *os.PathError
	require.ErrorAs(t, err, &pathErr)
	assert.ErrorIs(t, err, fs.ErrExist)
	kept, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "kept", string(kept))

	_, err = createPrivateFile(path + "\x00x")
	require.ErrorAs(t, err, &pathErr)

	assert.ErrorIs(t, darwinErrno(0), unix.EIO, "a failure reported without errno is still an error")
	assert.ErrorIs(t, darwinErrno(uintptr(unix.EEXIST)|0xffff_ffff_0000_0000), unix.EEXIST,
		"only the C int's 32 bits are the errno")
}

// Each native allocation or setter that fails stops creation with an error before any
// file exists, and whatever was allocated is freed.
func TestArchiveAccessDarwinCreateNativeFailures(t *testing.T) {
	type fails struct{ init, flags, filesec, setMode, setACL bool }
	for name, f := range map[string]fails{
		"acl_init":             {init: true},
		"acl_get_flagset_np":   {flags: true},
		"filesec_init":         {filesec: true},
		"filesec_set_property": {setMode: true},
		"filesec ACL property": {setACL: true},
	} {
		t.Run(name, func(t *testing.T) {
			allocated, freed := 0, 0
			result := func(fail bool) int32 {
				if fail {
					return -1
				}
				return 0
			}
			s := &darwinSecurity{
				aclInit: func(int32) uintptr {
					if f.init {
						return 0
					}
					allocated++
					return 0x10
				},
				aclFree:       func(uintptr) int32 { freed++; return 0 },
				aclGetFlagset: func(uintptr, *uintptr) int32 { return result(f.flags) },
				aclAddFlag:    func(uintptr, uint32) int32 { return 0 },
				filesecInit: func() uintptr {
					if f.filesec {
						return 0
					}
					allocated++
					return 0x20
				},
				filesecFree:    func(uintptr) { freed++ },
				filesecSetMode: func(uintptr, uint32, *uint16) int32 { return result(f.setMode) },
				filesecSetACL:  func(uintptr, uint32, *uintptr) int32 { return result(f.setACL) },
			}
			path := filepath.Join(t.TempDir(), "staged")
			_, err := s.createPrivate(path)
			require.Error(t, err)
			assert.NoFileExists(t, path)
			assert.Equal(t, allocated, freed, "every native allocation is freed")
		})
	}
}

// The binding is made once for the process and kept: libSystem is opened once, each
// symbol is looked up once (filesec_set_property serves both properties), and nothing
// is closed on success.
func TestArchiveAccessDarwinBindsLibSystemOnce(t *testing.T) {
	opened, closed := 0, 0
	lookups := map[string]int{}
	dlopen := func(string, int) (uintptr, error) { opened++; return 0x1000, nil }
	dlsym := func(_ uintptr, name string) (uintptr, error) { lookups[name]++; return 0x2000, nil }
	dlclose := func(uintptr) error { closed++; return nil }

	s, err := loadDarwinSecurityWith(dlopen, dlsym, dlclose)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, 1, opened)
	assert.Equal(t, 0, closed, "the library stays loaded")
	for name, n := range lookups {
		assert.Equal(t, 1, n, name)
	}
	assert.Equal(t, 1, lookups["filesec_set_property"])
	assert.NotNil(t, s.filesecSetMode)
	assert.NotNil(t, s.filesecSetACL)

	first, err := darwinSecurityOnce()
	require.NoError(t, err)
	second, err := darwinSecurityOnce()
	require.NoError(t, err)
	assert.Same(t, first, second, "one binding for the process")
}
