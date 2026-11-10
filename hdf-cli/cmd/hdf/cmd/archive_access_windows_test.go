package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func sharedArchiveDirectory(t *testing.T, dir string) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	require.NoError(t, err)
	sid := user.User.Sid.String()
	parent, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;GR;;;BU)")
	require.NoError(t, err)
	dacl, _, err := parent.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))

	return user.User.Sid
}

// Compare native SIDs instead of SDDL text, which may use aliases such as LA.
func assertArchiveAccessGrant(t *testing.T, acl *windows.ACL, sid *windows.SID, mask windows.ACCESS_MASK, flags uint8) {
	t.Helper()
	matches := 0
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		require.NotNil(t, ace)
		require.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType)
		grantee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if grantee.Equals(sid) {
			matches++
			assert.Equal(t, mask, ace.Mask)
			assert.Equal(t, flags, ace.Header.AceFlags)
		}
	}
	require.Equal(t, 1, matches, "expected exactly one grant to %s", sid.String())
}

func TestArchiveAccessWindowsPrivateBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
	userSID := sharedArchiveDirectory(t, dir)

	// Confirm this directory really grants inherited read access to other users.
	control, err := os.CreateTemp(dir, "inherited-control-*")
	require.NoError(t, err)
	controlSD, err := windows.GetSecurityInfo(windows.Handle(control.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, controlSD)
	controlACL, _, err := controlSD.DACL()
	require.NoError(t, err)
	require.NotNil(t, controlACL)
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	assertArchiveAccessGrant(t, controlACL, users, windows.FILE_GENERIC_READ, windows.INHERITED_ACE)
	require.NoError(t, control.Close())
	require.NoError(t, os.Remove(control.Name()))

	assertPrivate := func(descriptor *windows.SECURITY_DESCRIPTOR) {
		t.Helper()
		control, _, controlErr := descriptor.Control()
		require.NoError(t, controlErr)
		assert.NotZero(t, control&windows.SE_DACL_PROTECTED)
		acl, _, aclErr := descriptor.DACL()
		require.NoError(t, aclErr)
		require.NotNil(t, acl)
		require.Equal(t, uint16(1), acl.AceCount, "only the creating identity may receive an access grant")
		assertArchiveAccessGrant(t, acl, userSID,
			windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff), 0)
	}
	output := filepath.Join(dir, "private.zip")
	writerCalled := false
	err = runEvidenceBundle(pkgPath, output, false, archivePrivate, func(file *os.File) archiveWriter {
		writerCalled = true
		stat, statErr := file.Stat()
		require.NoError(t, statErr)
		assert.Zero(t, stat.Size(), "protection must exist before archive bytes are written")
		staged, queryErr := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		require.NoError(t, queryErr)
		require.NotNil(t, staged)
		assertPrivate(staged)
		return newArchiveWriter(file)
	})
	require.NoError(t, err)
	require.True(t, writerCalled)
	published, err := windows.GetNamedSecurityInfo(output, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, published)
	assertPrivate(published)
	entries := zipEntries(t, output)
	require.Contains(t, entries, "pkg.json")
	leftovers, err := filepath.Glob(filepath.Join(dir, ".hdf-bundle-*"))
	require.NoError(t, err)
	assert.Empty(t, leftovers)
}

func TestArchiveAccessWindowsInheritedBeforeWrite(t *testing.T) {
	dir, pkg := bundleTree(t)
	sid := sharedArchiveDirectory(t, dir)
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	require.NoError(t, err)
	output := filepath.Join(dir, "shared.zip")
	assertInherited := func(sd *windows.SECURITY_DESCRIPTOR) {
		t.Helper()
		control, _, err := sd.Control()
		require.NoError(t, err)
		require.Zero(t, control&windows.SE_DACL_PROTECTED)
		acl, _, err := sd.DACL()
		require.NoError(t, err)
		require.NotNil(t, acl)
		require.Equal(t, uint16(2), acl.AceCount)
		assertArchiveAccessGrant(t, acl, sid,
			windows.ACCESS_MASK(windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff), windows.INHERITED_ACE)
		assertArchiveAccessGrant(t, acl, users, windows.FILE_GENERIC_READ, windows.INHERITED_ACE)
	}
	called := false
	err = runEvidenceBundle(pkg, output, false, archiveInherit, func(file *os.File) archiveWriter {
		called = true
		info, err := file.Stat()
		require.NoError(t, err)
		require.Zero(t, info.Size())
		sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		require.NoError(t, err)
		require.NotNil(t, sd)
		assertInherited(sd)
		return newArchiveWriter(file)
	})
	require.NoError(t, err)
	require.True(t, called)
	sd, err := windows.GetNamedSecurityInfo(output, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, sd)
	assertInherited(sd)
	require.Contains(t, zipEntries(t, output), "pkg.json")
}

func TestArchiveAccessWindowsReadbackRejectsOtherGrants(t *testing.T) {
	dir := t.TempDir()
	sid := sharedArchiveDirectory(t, dir)
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")")
	require.NoError(t, err)
	path := filepath.Join(dir, "readback.zip")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.ErrorContains(t, verifyWindowsArchiveAccess(windows.Handle(file.Fd()), expected), "permits inheritance")
	broad, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")(A;;GR;;;BU)")
	require.NoError(t, err)
	dacl, _, err := broad.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))
	require.ErrorContains(t, verifyWindowsArchiveAccess(windows.Handle(file.Fd()), expected), "exclusively to the effective user")
	require.ErrorContains(t, verifyWindowsArchiveAccess(windows.InvalidHandle, expected), "cannot verify private archive filesystem")
}

func TestArchiveAccessWindowsCreationErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.zip")
	sentinel := []byte("existing archive")
	require.NoError(t, os.WriteFile(path, sentinel, 0o600))
	file, err := openPrivateArchive(path)
	require.Nil(t, file)
	require.ErrorIs(t, err, os.ErrExist)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, sentinel, contents)
	file, err = openPrivateArchive(filepath.Join(dir, "missing", "archive.zip"))
	require.Nil(t, file)
	require.ErrorIs(t, err, os.ErrNotExist)
	invalidPath := filepath.Join(dir, "invalid.zip")
	file, err = openPrivateArchive(invalidPath + "\x00suffix")
	require.Nil(t, file)
	require.Error(t, err)
	require.NoFileExists(t, invalidPath)
}
