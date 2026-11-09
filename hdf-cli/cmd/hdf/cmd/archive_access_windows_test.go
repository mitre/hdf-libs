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

func TestArchiveAccessWindowsPrivateBeforeWrite(t *testing.T) {
	dir, pkgPath := bundleTree(t)
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

	// Confirm this directory really grants inherited read access to other users.
	control, err := os.CreateTemp(dir, "inherited-control-*")
	require.NoError(t, err)
	controlSD, err := windows.GetSecurityInfo(windows.Handle(control.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, controlSD)
	require.Contains(t, controlSD.String(), ";;;BU)")
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
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, 0, &ace))
		require.NotNil(t, ace)
		require.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType)
		assert.Zero(t, ace.Header.AceFlags&windows.INHERIT_ONLY_ACE)
		assert.Equal(t, uint32(windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff), ace.Mask)
		grantee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		assert.True(t, grantee.Equals(user.User.Sid), "the sole access grant must belong to the effective user")
	}
	output := filepath.Join(dir, "private.zip")
	writerCalled := false
	err = runEvidenceBundle(pkgPath, output, false, func(file *os.File) archiveWriter {
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
