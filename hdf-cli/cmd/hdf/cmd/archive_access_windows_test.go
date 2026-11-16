//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileAllAccess is the FA right: every standard and file-specific right.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

func effectiveUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	require.NoError(t, err)
	return user.User.Sid
}

// shareWithEveryone gives dir a protected DACL that grants the current user full
// access and Everyone read access, both inherited by every file created in it.
func shareWithEveryone(t *testing.T, dir string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;" + effectiveUserSID(t).String() + ")(A;OICI;GR;;;WD)")
	require.NoError(t, err)
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))
}

type aceView struct {
	sid   *windows.SID
	typ   byte
	flags byte
	mask  windows.ACCESS_MASK
}

func daclOf(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) (protected bool, aces []aceView) {
	t.Helper()
	require.NotNil(t, sd)
	control, _, err := sd.Control()
	require.NoError(t, err)
	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		aces = append(aces, aceView{
			sid:   (*windows.SID)(unsafe.Pointer(&ace.SidStart)),
			typ:   ace.Header.AceType,
			flags: ace.Header.AceFlags,
			mask:  ace.Mask,
		})
	}
	return control&windows.SE_DACL_PROTECTED != 0, aces
}

// assertCreatorOnly checks the DACL by SID and access mask, not by SDDL text.
func assertCreatorOnly(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	protected, aces := daclOf(t, sd)
	assert.True(t, protected, "the DACL takes nothing from the directory")
	require.Len(t, aces, 1, "one grant only")
	assert.Equal(t, byte(windows.ACCESS_ALLOWED_ACE_TYPE), aces[0].typ)
	assert.Zero(t, aces[0].flags, "neither inherited nor inheritable")
	assert.Equal(t, windows.ACCESS_MASK(fileAllAccess), aces[0].mask)
	assert.True(t, aces[0].sid.Equals(effectiveUserSID(t)), "the grant is to the effective user")
}

// On Windows a 0600 mode is only the read-only bit, so an archive takes the
// directory's inheritable grants unless it is created with its own DACL.
func TestArchiveAccessWindowsPrivateBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	shareWithEveryone(t, dir)
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	require.NoError(t, err)

	private := filepath.Join(dir, "private.zip")
	err = runEvidenceBundle(pkgPath, private, false, archivePrivate, func(f *os.File) archiveWriter {
		info, statErr := f.Stat()
		require.NoError(t, statErr)
		require.Zero(t, info.Size(), "checked before any byte is written")
		staged, sdErr := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION)
		require.NoError(t, sdErr)
		assertCreatorOnly(t, staged)
		return newArchiveWriter(f)
	})
	require.NoError(t, err)
	published, err := windows.GetNamedSecurityInfo(private, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	assertCreatorOnly(t, published)

	inherited := filepath.Join(dir, "inherited.zip")
	_, _, err = executeCommand("evidence", "bundle", pkgPath, "-o", inherited, "--output-access", "inherit")
	require.NoError(t, err)
	shared, err := windows.GetNamedSecurityInfo(inherited, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	_, aces := daclOf(t, shared)
	found := false
	for _, a := range aces {
		if a.sid.Equals(everyone) && a.flags&windows.INHERITED_ACE != 0 {
			found = true
		}
	}
	assert.True(t, found, "inherit takes the directory's Everyone grant")
}

// The readback refuses any DACL but the creator-only one: a file that inherited the
// directory's grants fails it, and one created private passes.
func TestArchiveAccessWindowsReadbackRefusesOtherGrants(t *testing.T) {
	dir := t.TempDir()
	shareWithEveryone(t, dir)
	me := effectiveUserSID(t)

	plain, err := os.CreateTemp(dir, "inherited")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plain.Close() })
	assert.Error(t, verifyPrivateDACL(windows.Handle(plain.Fd()), me))

	created, err := createPrivateWindows(filepath.Join(dir, "private"), volumeACLFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = created.Close() })
	assert.NoError(t, verifyPrivateDACL(windows.Handle(created.Fd()), me))
}

// A volume without persistent ACLs (FAT, exFAT) cannot keep a DACL, so private fails
// there and leaves nothing behind; so does a volume whose flags cannot be read.
func TestArchiveAccessWindowsRequiresPersistentACLs(t *testing.T) {
	for name, flags := range map[string]func(windows.Handle) (uint32, error){
		"no persistent ACLs": func(windows.Handle) (uint32, error) { return 0, nil },
		"unreadable volume":  func(windows.Handle) (uint32, error) { return 0, windows.ERROR_ACCESS_DENIED },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "staged")
			_, err := createPrivateWindows(path, flags)
			require.Error(t, err)
			if name == "no persistent ACLs" {
				assert.Contains(t, err.Error(), "NTFS")
			}
			assert.NoFileExists(t, path)
		})
	}
}

// Raw CreateFileW gets no long-path handling from Go, so a path past MAX_PATH is
// created through its \\?\ form; a NUL inside a path is refused.
func TestArchiveAccessWindowsPathForms(t *testing.T) {
	deep := filepath.Join(t.TempDir(), strings.Repeat("d", 120), strings.Repeat("e", 120))
	require.NoError(t, os.MkdirAll(deep, 0o700))
	long := filepath.Join(deep, "staged")
	require.GreaterOrEqual(t, len(long), 260)
	f, err := createPrivateWindows(long, volumeACLFlags)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	assertCreatorOnly(t, sd)

	nul := filepath.Join(t.TempDir(), "bad\x00name")
	_, err = createPrivateWindows(nul, volumeACLFlags)
	assert.Error(t, err)
}
