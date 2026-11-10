package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ebitengine/purego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestArchiveAccessDarwinPrivateBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a",
		"group:everyone allow read,readattr,readextattr,readsecurity,file_inherit", dir).CombinedOutput()
	require.NoError(t, err, "%s", out)
	readACL := func(path string) string {
		t.Helper()
		listing, listErr := exec.CommandContext(t.Context(), "/bin/ls", "-le", path).CombinedOutput()
		require.NoError(t, listErr, "%s", listing)
		return strings.TrimSpace(string(listing))
	}
	control, err := os.CreateTemp(dir, "inherited-control-*")
	require.NoError(t, err)
	controlACL := readACL(control.Name())
	require.Len(t, strings.Split(controlACL, "\n"), 2)
	require.Contains(t, controlACL, "inherited allow read")
	require.NoError(t, control.Close())
	require.NoError(t, os.Remove(control.Name()))
	output := filepath.Join(dir, "private.zip")
	writerCalled := false
	err = runEvidenceBundle(pkgPath, output, false, archivePrivate, func(file *os.File) archiveWriter {
		writerCalled = true
		stat, statErr := file.Stat()
		require.NoError(t, statErr)
		assert.Zero(t, stat.Size(), "protection must exist before archive bytes are written")
		assert.Equal(t, os.FileMode(0o600), stat.Mode().Perm())
		assert.Len(t, strings.Split(readACL(file.Name()), "\n"), 1, "private staged archive must have no ACL entries")
		return newArchiveWriter(file)
	})
	require.NoError(t, err)
	require.True(t, writerCalled)
	assert.Len(t, strings.Split(readACL(output), "\n"), 1, "publication must preserve private access")
	require.Contains(t, zipEntries(t, output), "pkg.json")
}

func TestArchiveAccessDarwinRejectsBroadMode(t *testing.T) {
	file, err := openPrivateArchive(filepath.Join(t.TempDir(), "broad.zip"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.NoError(t, file.Chmod(0o644))
	api, err := loadArchiveDarwinAPI()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, purego.Dlclose(api.library)) })
	require.Error(t, verifyDarwinArchiveACL(file, api), "a mode readback must reject access granted to other accounts")
}

func TestArchiveAccessDarwinExclusiveCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.zip")
	sentinel := []byte("existing archive")
	require.NoError(t, os.WriteFile(path, sentinel, 0o600))
	file, err := openPrivateArchive(path)
	require.Nil(t, file)
	require.ErrorIs(t, err, unix.EEXIST)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, sentinel, contents)
}

func TestArchiveAccessDarwinRejectsUnverifiableFilesystem(t *testing.T) {
	for _, name := range []string{"ignore-ownership", "remote", "unknown", "query-error"} {
		t.Run(name, func(t *testing.T) {
			api, err := loadArchiveDarwinAPI()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, purego.Dlclose(api.library)) })
			api.statfs = func(_ int, stat *unix.Statfs_t) error {
				copy(stat.Fstypename[:], "apfs")
				stat.Flags = unix.MNT_LOCAL
				switch name {
				case "ignore-ownership":
					stat.Flags |= unix.MNT_IGNORE_OWNERSHIP
				case "remote":
					stat.Flags = 0
				case "unknown":
					copy(stat.Fstypename[:], "fuse")
				case "query-error":
					return unix.EIO
				}
				return nil
			}
			path := filepath.Join(t.TempDir(), "unsupported.zip")
			file, err := openPrivateArchiveWithDarwinAPI(path, api)
			if file != nil {
				t.Cleanup(func() { require.NoError(t, file.Close()) })
			}
			assert.Error(t, err)
			assert.Nil(t, file)
			_, statErr := os.Stat(path)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "an unverifiable staged file must be removed")
		})
	}
}

func TestArchiveAccessDarwinEmptyACL(t *testing.T) {
	api, err := loadArchiveDarwinAPI()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, purego.Dlclose(api.library)) })
	file, err := openPrivateArchive(filepath.Join(t.TempDir(), "empty-acl.zip"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	api.filesecQuery = func(_ uintptr, _ int32, present *int32) int32 { *present = 1; return 0 }
	api.filesecGet = func(_ uintptr, _ int32, acl *uintptr) int32 {
		*acl = api.aclInit(0)
		require.NotZero(t, *acl)
		return 0
	}
	require.NoError(t, verifyDarwinArchiveACL(file, api), "a valid ACL with no entries grants no access")
}

func TestArchiveAccessDarwinMissingSymbols(t *testing.T) {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	require.NoError(t, err)
	defer purego.Dlclose(lib)
	for _, symbol := range []string{"openx_np", "acl_get_entry", "acl_init", "filesec_get_property", "calloc"} {
		for _, nullAddress := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/null=%t", symbol, nullAddress), func(t *testing.T) {
				lookup := func(handle uintptr, name string) (uintptr, error) {
					if name == symbol {
						if nullAddress {
							return 0, nil
						}
						return 0, errors.New("symbol unavailable")
					}
					return purego.Dlsym(handle, name)
				}
				require.NotPanics(t, func() {
					api, err := bindArchiveDarwinAPI(lib, lookup)
					assert.Error(t, err)
					assert.Nil(t, api)
				})
			})
		}
	}
}

func TestArchiveAccessDarwinSecurityFailures(t *testing.T) {
	for _, name := range []string{"acl-allocation", "acl-flags", "acl-inherit", "security-allocation", "mode", "acl", "path-allocation", "readback-allocation", "readback", "query", "get-acl", "null-acl", "invalid-acl", "entry-allocation"} {
		t.Run(name, func(t *testing.T) {
			api, err := loadArchiveDarwinAPI()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, purego.Dlclose(api.library)) })
			aclInit, aclFree := api.aclInit, api.aclFree
			securityInit, securityFree := api.filesecInit, api.filesecFree
			duplicate, free := api.duplicate, api.free
			var aclCount, securityCount, pathCount int
			api.aclInit = func(n int32) uintptr {
				p := aclInit(n)
				if p != 0 {
					aclCount++
				}
				return p
			}
			api.aclFree = func(p uintptr) int32 { aclCount--; return aclFree(p) }
			api.filesecInit = func() uintptr {
				p := securityInit()
				if p != 0 {
					securityCount++
				}
				return p
			}
			api.filesecFree = func(p uintptr) { securityCount--; securityFree(p) }
			api.duplicate = func(s *byte) uintptr {
				p := duplicate(s)
				if p != 0 {
					pathCount++
				}
				return p
			}
			api.free = func(p uintptr) { pathCount--; free(p) }
			switch name {
			case "acl-allocation":
				api.aclInit = func(int32) uintptr { return 0 }
			case "acl-flags":
				api.aclFlags = func(uintptr, *uintptr) int32 { return -1 }
			case "acl-inherit":
				api.aclAddFlag = func(uintptr, uint32) int32 { return -1 }
			case "security-allocation":
				api.filesecInit = func() uintptr { return 0 }
			case "mode":
				api.filesecMode = func(uintptr, int32, *uint16) int32 { return -1 }
			case "acl":
				api.filesecACL = func(uintptr, int32, *uintptr) int32 { return -1 }
			case "path-allocation":
				api.duplicate = func(*byte) uintptr { return 0 }
			case "readback-allocation":
				init := api.filesecInit
				api.filesecInit = func() uintptr {
					if securityCount > 0 {
						return 0
					}
					return init()
				}
			case "readback":
				api.fstatx = func(int32, *unix.Stat_t, uintptr) int32 { return -1 }
			case "query":
				api.filesecQuery = func(uintptr, int32, *int32) int32 { return -1 }
			default:
				api.filesecQuery = func(_ uintptr, _ int32, present *int32) int32 { *present = 1; return 0 }
				api.filesecGet = func(_ uintptr, _ int32, acl *uintptr) int32 { *acl = api.aclInit(0); return 0 }
				switch name {
				case "get-acl":
					api.filesecGet = func(uintptr, int32, *uintptr) int32 { return -1 }
				case "null-acl":
					api.filesecGet = func(uintptr, int32, *uintptr) int32 { return 0 }
				case "invalid-acl":
					api.aclValid = func(uintptr) int32 { return -1 }
				case "entry-allocation":
					api.calloc = func(uintptr, uintptr) uintptr { return 0 }
				}
			}
			path := filepath.Join(t.TempDir(), "failed.zip")
			file, err := openPrivateArchiveWithDarwinAPI(path, api)
			require.Error(t, err)
			require.Nil(t, file)
			_, statErr := os.Stat(path)
			assert.ErrorIs(t, statErr, os.ErrNotExist)
			assert.Zero(t, aclCount, "every allocated ACL must be freed")
			assert.Zero(t, securityCount, "every security descriptor must be freed")
			assert.Zero(t, pathCount, "every native path must be freed")
		})
	}
}

func TestArchiveAccessDarwinInheritedBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a",
		"group:everyone allow read,readattr,readextattr,readsecurity,file_inherit", dir).CombinedOutput()
	require.NoError(t, err, "%s", out)
	assertInherited := func(path string) {
		t.Helper()
		listing, err := exec.CommandContext(t.Context(), "/bin/ls", "-le", path).CombinedOutput()
		require.NoError(t, err, "%s", listing)
		assert.Contains(t, string(listing), "inherited allow read")
	}
	output := filepath.Join(dir, "inherited.zip")
	called := false
	err = runEvidenceBundle(pkgPath, output, false, archiveInherit, func(file *os.File) archiveWriter {
		called = true
		stat, err := file.Stat()
		require.NoError(t, err)
		assert.Zero(t, stat.Size())
		assertInherited(file.Name())
		return newArchiveWriter(file)
	})
	require.NoError(t, err)
	require.True(t, called)
	assertInherited(output)
	require.Contains(t, zipEntries(t, output), "pkg.json")
	file, err := os.Open(output)
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, file.Chmod(0o600))
	api, err := loadArchiveDarwinAPI()
	require.NoError(t, err)
	defer purego.Dlclose(api.library)
	require.ErrorContains(t, verifyDarwinArchiveACL(file, api), "retained an ACL entry", "mode 0600 cannot erase an inherited macOS ACL grant")
}

func TestArchiveAccessDarwinInvalidPaths(t *testing.T) {
	for _, path := range []string{filepath.Join(t.TempDir(), "missing", "out.zip"), filepath.Join(t.TempDir(), "out.zip") + "\x00suffix"} {
		file, err := openPrivateArchive(path)
		require.Nil(t, file)
		require.Error(t, err)
		if strings.ContainsRune(path, 0) {
			assert.ErrorIs(t, err, unix.EINVAL)
			_, statErr := os.Stat(strings.Split(path, "\x00")[0])
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		} else {
			assert.ErrorIs(t, err, os.ErrNotExist)
		}
	}
}

func TestArchiveAccessDarwinCapturedError(t *testing.T) {
	assert.ErrorIs(t, archiveDarwinError(0), unix.EIO)
	assert.ErrorIs(t, archiveDarwinError(1<<32|uintptr(unix.EEXIST)), unix.EEXIST)
}
