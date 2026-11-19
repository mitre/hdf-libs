package cmd

import (
	"encoding/binary"
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeNFS4ACL builds the XDR form of an nfsace4 list from RFC 8881's definitions
// (section 6.2.1): a count, then type, flag, access_mask and a length-prefixed who
// padded to four bytes. Schema-confirmed test input, not captured server output.
func encodeNFS4ACL(aces ...nfs4ACE) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(aces)))
	for _, a := range aces {
		b = binary.BigEndian.AppendUint32(b, a.aceType)
		b = binary.BigEndian.AppendUint32(b, a.flag)
		b = binary.BigEndian.AppendUint32(b, a.mask)
		b = binary.BigEndian.AppendUint32(b, uint32(len(a.who)))
		b = append(b, a.who...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	return b
}

const (
	aceAllow, aceDeny          = 0, 1
	readData, writeData        = 0x1, 0x2
	appendData, readAttributes = 0x4, 0x80
	execute                    = 0x20
	writeACL, writeOwner       = 0x40000, 0x80000
	inheritOnly, inheritedACE  = 0x8, 0x80
)

// An inherited named entry can still grant read after a 0600 create; that is the
// case the check exists for.
func TestNFS4ACLGrantsOthers(t *testing.T) {
	owner := nfs4ACE{aceType: aceAllow, mask: readData | writeData | appendData, who: "OWNER@"}
	cases := []struct {
		name string
		aces []nfs4ACE
		who  string
	}{
		{"owner only", []nfs4ACE{owner}, ""},
		{"inherited named reader", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritedACE, mask: readData, who: "auditor@example.org"}}, "auditor@example.org"},
		{"everyone may append", []nfs4ACE{owner, {aceType: aceAllow, mask: appendData, who: "EVERYONE@"}}, "EVERYONE@"},
		{"inherit-only entry does not apply to the file", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritOnly, mask: readData, who: "bob@example.org"}}, ""},
		{"a deny entry grants nothing", []nfs4ACE{owner, {aceType: aceDeny, mask: readData, who: "EVERYONE@"}}, ""},
		{"attribute access is not data access", []nfs4ACE{owner, {aceType: aceAllow, mask: readAttributes, who: "EVERYONE@"}}, ""},
		{"a principal that may rewrite the ACL can grant itself read", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritedACE, mask: writeACL, who: "carol@example.org"}}, "carol@example.org"},
		{"a principal that may take ownership can grant itself read", []nfs4ACE{owner, {aceType: aceAllow, mask: writeOwner, who: "GROUP@"}}, "GROUP@"},
		{"inherit-only control entry does not apply to the file", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritOnly, mask: writeACL | writeOwner, who: "bob@example.org"}}, ""},
		{"execute does not expose an archive's contents", []nfs4ACE{owner, {aceType: aceAllow, mask: execute, who: "EVERYONE@"}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			aces, err := decodeNFS4ACL(encodeNFS4ACL(c.aces...))
			require.NoError(t, err)
			require.Equal(t, c.aces, aces, "decoded entries match what was encoded")
			who, grants := grantsAccessToOthers(aces, nfs4Owner{uid: "1000", name: "alice"})
			assert.Equal(t, c.who != "", grants)
			assert.Equal(t, c.who, who)
		})
	}
}

// Truncated or over-long input is an error, never a panic or a silent partial list.
func TestNFS4ACLRejectsMalformedInput(t *testing.T) {
	good := encodeNFS4ACL(nfs4ACE{aceType: aceAllow, mask: readData, who: "OWNER@"})
	for name, b := range map[string][]byte{
		"empty":            {},
		"truncated count":  good[:2],
		"truncated entry":  good[:len(good)-3],
		"count overstates": append([]byte{0, 0, 0, 2}, good[4:]...),
		"trailing bytes":   append(append([]byte{}, good...), 0, 0, 0, 0),
		"huge who length":  append(append([]byte{}, good[:16]...), 0xff, 0xff, 0xff, 0xff),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeNFS4ACL(b)
			assert.Error(t, err)
		})
	}
}

func FuzzNFS4ACL(f *testing.F) {
	f.Add(encodeNFS4ACL(nfs4ACE{aceType: aceAllow, mask: readData, who: "OWNER@"}))
	f.Add([]byte{0, 0, 0, 1})
	f.Fuzz(func(_ *testing.T, b []byte) {
		if aces, err := decodeNFS4ACL(b); err == nil {
			_, _ = grantsAccessToOthers(aces, nfs4Owner{uid: "1000", name: "alice"})
		}
	})
}

// A server names the owner in its own way: OWNER@, the numeric uid when it maps no
// names, or user@domain. Each is the owner; anyone else, and an account that merely
// shares the owner's name with a special principal, is not.
func TestNFS4ACLOwnerIdentities(t *testing.T) {
	owner := nfs4Owner{uid: "1000", name: "alice"}
	for who, isOwner := range map[string]bool{
		"OWNER@": true, "1000": true, "alice@example.org": true, "alice@EXAMPLE": true,
		"1001": false, "bob@example.org": false, "alice": false, "alice@": false,
		"EVERYONE@": false, "GROUP@": false, "aliceb@example.org": false, "": false,
	} {
		t.Run(who, func(t *testing.T) {
			aces := []nfs4ACE{{aceType: aceAllow, mask: readData | writeData, who: who}}
			shared, grants := grantsAccessToOthers(aces, owner)
			assert.Equal(t, !isOwner, grants)
			if !isOwner {
				assert.Equal(t, who, shared)
			}
		})
	}
	nameless := nfs4Owner{uid: "1000"}
	assert.True(t, nameless.is("1000"), "a uid with no account name still matches by number")
	assert.False(t, nameless.is("@example.org"), "and matches no user@domain at all")
}

// The owner resolves from the uid: the number always, the name when the account exists.
func TestNFS4OwnerOfResolvesTheCurrentUser(t *testing.T) {
	uid := os.Geteuid()
	owner := nfs4OwnerOf(uint32(uid))
	assert.Equal(t, strconv.Itoa(uid), owner.uid)
	if u, err := user.LookupId(owner.uid); err == nil {
		assert.Equal(t, u.Username, owner.name)
	} else {
		assert.Empty(t, owner.name)
	}
}
