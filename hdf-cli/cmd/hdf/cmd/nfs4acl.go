package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// nfs4ACE is one access control entry of an NFSv4 ACL (RFC 8881 section 6.2.1).
type nfs4ACE struct {
	aceType uint32
	flag    uint32
	mask    uint32
	who     string
}

// The RFC 8881 section 6.2.1 values this check reads.
const (
	nfs4ACEAllowed     = 0
	nfs4ACEInheritOnly = 0x8
	nfs4ACEDataAccess  = 0x1 | 0x2 | 0x4   // READ_DATA, WRITE_DATA, APPEND_DATA
	nfs4ACEControl     = 0x40000 | 0x80000 // WRITE_ACL, WRITE_OWNER: the holder can grant itself data access
	nfs4OwnerPrincipal = "OWNER@"
)

var errNFS4ACLTruncated = errors.New("NFSv4 ACL is truncated")

// decodeNFS4ACL decodes the XDR nfsace4 list the kernel returns for system.nfs4_acl:
// a count, then type, flag, access_mask and a length-prefixed who padded to four bytes.
// Every length is checked against what remains, so malformed input is an error.
func decodeNFS4ACL(b []byte) ([]nfs4ACE, error) {
	if len(b) < 4 {
		return nil, errNFS4ACLTruncated
	}
	count := binary.BigEndian.Uint32(b)
	b = b[4:]
	// Each entry takes at least 16 bytes, which bounds the count before allocating.
	if uint64(count)*16 > uint64(len(b)) {
		return nil, errNFS4ACLTruncated
	}
	aces := make([]nfs4ACE, 0, count)
	for range count {
		if len(b) < 16 {
			return nil, errNFS4ACLTruncated
		}
		ace := nfs4ACE{
			aceType: binary.BigEndian.Uint32(b),
			flag:    binary.BigEndian.Uint32(b[4:]),
			mask:    binary.BigEndian.Uint32(b[8:]),
		}
		n := uint64(binary.BigEndian.Uint32(b[12:]))
		padded := (n + 3) &^ 3
		b = b[16:]
		if padded > uint64(len(b)) {
			return nil, errNFS4ACLTruncated
		}
		ace.who = string(b[:n])
		b = b[padded:]
		aces = append(aces, ace)
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("NFSv4 ACL has %d trailing bytes", len(b))
	}
	return aces, nil
}

// nfs4Owner is the file owner's identities as an ACL entry may name them: the numeric
// uid a server sends when it maps no names, and the account name for user@domain.
type nfs4Owner struct {
	uid, name string
}

// nfs4OwnerOf resolves uid; a uid with no account name matches by number and OWNER@ only.
func nfs4OwnerOf(uid uint32) nfs4Owner {
	o := nfs4Owner{uid: strconv.FormatUint(uint64(uid), 10)}
	if u, err := user.LookupId(o.uid); err == nil {
		o.name = u.Username
	}
	return o
}

// is reports whether who names the owner: OWNER@, the uid, or the owner's account name
// with a domain. The special principals have no domain, so an account named like one
// does not pass as it.
func (o nfs4Owner) is(who string) bool {
	if who == nfs4OwnerPrincipal || who == o.uid {
		return true
	}
	name, domain, ok := strings.Cut(who, "@")
	return ok && domain != "" && o.name != "" && name == o.name
}

// grantsAccessToOthers reports the first principal other than the file's owner that an
// ALLOW entry applying to the file gives read, write or append access, or the right to
// rewrite its ACL or owner. Inherit-only entries apply to children, not the file, and
// deny entries grant nothing. EXECUTE is not counted: it does not expose the contents.
func grantsAccessToOthers(aces []nfs4ACE, owner nfs4Owner) (string, bool) {
	for _, a := range aces {
		if a.aceType != nfs4ACEAllowed || a.flag&nfs4ACEInheritOnly != 0 ||
			a.mask&(nfs4ACEDataAccess|nfs4ACEControl) == 0 || owner.is(a.who) {
			continue
		}
		return a.who, true
	}
	return "", false
}
