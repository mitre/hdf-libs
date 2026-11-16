package cmd

import (
	"encoding/binary"
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
		{"inherited named reader", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritedACE, mask: readData, who: "alice@example.org"}}, "alice@example.org"},
		{"everyone may append", []nfs4ACE{owner, {aceType: aceAllow, mask: appendData, who: "EVERYONE@"}}, "EVERYONE@"},
		{"inherit-only entry does not apply to the file", []nfs4ACE{owner, {aceType: aceAllow, flag: inheritOnly, mask: readData, who: "bob@example.org"}}, ""},
		{"a deny entry grants nothing", []nfs4ACE{owner, {aceType: aceDeny, mask: readData, who: "EVERYONE@"}}, ""},
		{"attribute access is not data access", []nfs4ACE{owner, {aceType: aceAllow, mask: readAttributes, who: "EVERYONE@"}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			aces, err := decodeNFS4ACL(encodeNFS4ACL(c.aces...))
			require.NoError(t, err)
			require.Equal(t, c.aces, aces, "decoded entries match what was encoded")
			who, grants := grantsDataToOthers(aces)
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
			_, _ = grantsDataToOthers(aces)
		}
	})
}
