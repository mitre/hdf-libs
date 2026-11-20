//go:build linux

package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// xattrReturning serves one system.nfs4_acl value, or an error, the way Fgetxattr does:
// a nil buffer asks for the size.
func xattrReturning(value []byte, err error) func(int, string, []byte) (int, error) {
	return func(_ int, attr string, dest []byte) (int, error) {
		if err != nil {
			return 0, err
		}
		if attr != "system.nfs4_acl" {
			return 0, unix.ENODATA
		}
		if dest == nil {
			return len(value), nil
		}
		return copy(dest, value), nil
	}
}

// testOwner is the owner the Linux checks are run as: uid 1000, named alice.
var testOwner = nfs4Owner{uid: "1000", name: "alice"}

func statfsOf(magic int64) func(int, *unix.Statfs_t) error {
	return func(_ int, st *unix.Statfs_t) error {
		st.Type = typeOf(st.Type, magic)
		return nil
	}
}

// An inherited NFSv4 entry can grant another principal read after a 0600 create; the
// mode readback cannot see it, so the ACL is read from the open file and refused.
func TestLinuxPrivate_RefusesAnNFS4ACLThatSharesTheArchive(t *testing.T) {
	acl := encodeNFS4ACL(
		nfs4ACE{aceType: aceAllow, mask: readData | writeData, who: "OWNER@"},
		nfs4ACE{aceType: aceAllow, flag: inheritedACE, mask: readData, who: "auditors@example.org"},
	)
	err := checkLinuxPrivate(3, testOwner, xattrReturning(acl, nil), statfsOf(unix.EXT4_SUPER_MAGIC), &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auditors@example.org", "the refusal names who the entry shares it with")
	assert.Contains(t, err.Error(), "--output-access inherit")

	owner := encodeNFS4ACL(nfs4ACE{aceType: aceAllow, mask: readData | writeData, who: "OWNER@"})
	assert.NoError(t, checkLinuxPrivate(3, testOwner, xattrReturning(owner, nil), statfsOf(unix.EXT4_SUPER_MAGIC), &bytes.Buffer{}))
}

// No NFSv4 ACL (a local filesystem, or a server without ACL support) is not a failure;
// any other error reading it is, since the check could not be made.
func TestLinuxPrivate_ACLReadErrors(t *testing.T) {
	ext4 := statfsOf(unix.EXT4_SUPER_MAGIC)
	assert.NoError(t, checkLinuxPrivate(3, testOwner, xattrReturning(nil, unix.ENODATA), ext4, &bytes.Buffer{}))
	assert.NoError(t, checkLinuxPrivate(3, testOwner, xattrReturning(nil, unix.EOPNOTSUPP), ext4, &bytes.Buffer{}))
	assert.Error(t, checkLinuxPrivate(3, testOwner, xattrReturning(nil, unix.EIO), ext4, &bytes.Buffer{}))
	assert.Error(t, checkLinuxPrivate(3, testOwner, xattrReturning([]byte{0, 0, 0, 9}, nil), ext4, &bytes.Buffer{}),
		"an ACL that cannot be decoded is not trusted")
}

// Network and userspace storage gets one note, never a refusal; local storage gets none.
func TestLinuxPrivate_NotesNetworkStorage(t *testing.T) {
	none := xattrReturning(nil, unix.ENODATA)
	for name, magic := range map[string]int64{
		"nfs": unix.NFS_SUPER_MAGIC, "smb": unix.SMB_SUPER_MAGIC, "smb2": unix.SMB2_SUPER_MAGIC,
		"cifs": unix.CIFS_SUPER_MAGIC, "fuse": unix.FUSE_SUPER_MAGIC, "9p": unix.V9FS_MAGIC,
		"ceph": unix.CEPH_SUPER_MAGIC, "ocfs2": unix.OCFS2_SUPER_MAGIC, "afs": unix.AFS_SUPER_MAGIC,
		"afs (kafs)": unix.AFS_FS_MAGIC, "gfs2": gfs2SuperMagic, "lustre": lustreSuperMagic,
	} {
		t.Run(name, func(t *testing.T) {
			var notes, want bytes.Buffer
			require.NoError(t, checkLinuxPrivate(3, testOwner, none, statfsOf(magic), &notes))
			noteNetworkStorage(&want, networkStorage(magic))
			assert.Equal(t, want.String(), notes.String(), "the shared note, naming the storage kind")
		})
	}
	for name, magic := range map[string]int64{"ext4": unix.EXT4_SUPER_MAGIC, "tmpfs": unix.TMPFS_MAGIC,
		"overlay": unix.OVERLAYFS_SUPER_MAGIC, "xfs": unix.XFS_SUPER_MAGIC} {
		t.Run(name, func(t *testing.T) {
			var notes bytes.Buffer
			require.NoError(t, checkLinuxPrivate(3, testOwner, none, statfsOf(magic), &notes))
			assert.Empty(t, notes.String())
		})
	}
}

// typeOf converts a filesystem magic to Statfs_t.Type's width on this architecture
// (int64, int32 or uint32), wrapping as the kernel's value does.
func typeOf[T int32 | int64 | uint32](_ T, magic int64) T { return T(magic) }

// Statfs_t.Type is int32 on 386 and arm, where the kernel's larger magics arrive as
// negative numbers; they must still be recognized.
func TestFsMagicFoldsSignedThirtyTwoBitTypes(t *testing.T) {
	var asInt32 int32
	cifs := int64(unix.CIFS_SUPER_MAGIC)
	asInt32 = int32(uint32(cifs))
	assert.Equal(t, cifs, fsMagic(asInt32), "int32 (386, arm)")
	assert.Equal(t, cifs, fsMagic(uint32(cifs)), "uint32 (s390x)")
	assert.Equal(t, cifs, fsMagic(cifs), "int64 (amd64, arm64)")
	assert.Equal(t, "SMB", networkStorage(fsMagic(asInt32)))
}

// xattrSequence answers successive Fgetxattr calls in order, as an attribute that
// changes between the size probe and the read would.
func xattrSequence(steps ...struct {
	n   int
	err error
}) func(int, string, []byte) (int, error) {
	i := 0
	return func(int, string, []byte) (int, error) {
		s := steps[i]
		i++
		return s.n, s.err
	}
}

type step = struct {
	n   int
	err error
}

// The attribute can change between the size probe and the read; neither ordering may
// panic, and an ACL removed in between means there is none.
func TestLinuxPrivate_ACLChangingBetweenProbeAndRead(t *testing.T) {
	ext4 := statfsOf(unix.EXT4_SUPER_MAGIC)
	assert.NoError(t, checkLinuxPrivate(3, testOwner, xattrSequence(step{16, nil}, step{0, unix.ENODATA}), ext4, &bytes.Buffer{}),
		"removed before the read: no ACL")
	assert.NotPanics(t, func() {
		assert.Error(t, checkLinuxPrivate(3, testOwner, xattrSequence(step{0, nil}, step{16, nil}), ext4, &bytes.Buffer{}),
			"an empty ACL is not a valid one")
	})
	assert.NotPanics(t, func() {
		assert.Error(t, checkLinuxPrivate(3, testOwner, xattrSequence(step{8, nil}, step{64, nil}), ext4, &bytes.Buffer{}),
			"a read longer than the buffer is refused")
	})
}

// xattrScript answers successive Fgetxattr calls in order, copying each response's
// value into the buffer offered, as an attribute that changes between calls would.
func xattrScript(responses ...xattrResponse) func(int, string, []byte) (int, error) {
	i := 0
	return func(_ int, _ string, dest []byte) (int, error) {
		r := responses[i]
		i++
		if r.err != nil {
			return 0, r.err
		}
		if dest == nil {
			return r.n, nil
		}
		return copy(dest, r.value), nil
	}
}

type xattrResponse struct {
	n     int
	err   error
	value []byte
}

// An ACL that grows between the size probe and the read answers ERANGE; the probe and
// read are made once more and judged, and a second ERANGE is a failure.
func TestLinuxPrivate_ACLGrowingBetweenProbeAndRead(t *testing.T) {
	ext4 := statfsOf(unix.EXT4_SUPER_MAGIC)
	owner := encodeNFS4ACL(nfs4ACE{aceType: aceAllow, mask: readData | writeData, who: "OWNER@"})
	shared := encodeNFS4ACL(
		nfs4ACE{aceType: aceAllow, mask: readData | writeData, who: "OWNER@"},
		nfs4ACE{aceType: aceAllow, flag: inheritedACE, mask: readData, who: "auditors@example.org"},
	)
	grown := func(final []byte) func(int, string, []byte) (int, error) {
		return xattrScript(xattrResponse{n: len(owner)}, xattrResponse{err: unix.ERANGE},
			xattrResponse{n: len(final)}, xattrResponse{n: len(final), value: final})
	}

	assert.NoError(t, checkLinuxPrivate(3, testOwner, grown(owner), ext4, &bytes.Buffer{}), "owner-only after the retry")
	err := checkLinuxPrivate(3, testOwner, grown(shared), ext4, &bytes.Buffer{})
	require.Error(t, err, "the retried read is judged")
	assert.Contains(t, err.Error(), "auditors@example.org")

	twice := xattrScript(xattrResponse{n: len(owner)}, xattrResponse{err: unix.ERANGE},
		xattrResponse{n: len(owner)}, xattrResponse{err: unix.ERANGE})
	err = checkLinuxPrivate(3, testOwner, twice, ext4, &bytes.Buffer{})
	require.ErrorIs(t, err, unix.ERANGE, "one retry only")
	assert.Contains(t, err.Error(), "cannot read the staged archive's NFSv4 ACL")
}
