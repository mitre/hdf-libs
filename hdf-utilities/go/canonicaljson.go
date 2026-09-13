package hdfutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CanonicalJSON returns the canonical JSON encoding HDF uses for
// content-addressed checksums, such as the amendment chain's previousChecksum.
//
// The form is Go's encoding/json object encoding of the value's JSON shape:
// object keys sorted by byte order, and <, > and & escaped as <, >
// and &. Keys whose value is null are removed, so a document that spells
// an absent optional field as an explicit null hashes the same as one that
// omits it.
//
// The escaping is part of the contract, not an implementation detail: a
// non-Go implementation that emits those three characters literally will
// produce a different checksum for any string containing them ("vendor A & B",
// "version < 3"), and the two will disagree about whether a chain is intact.
// The TypeScript counterpart is canonicalJson in @mitre/hdf-utilities, and the
// two are pinned against shared vectors.
//
// The value is round-tripped through JSON first, so a struct and an equivalent
// map produce identical bytes.
func CanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("value is not JSON-encodable: %w", err)
	}

	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, fmt.Errorf("value did not round-trip through JSON: %w", err)
	}

	canonical, err := json.Marshal(withoutNullValues(normalized))
	if err != nil {
		return nil, fmt.Errorf("canonical form is not encodable: %w", err)
	}
	return canonical, nil
}

// ChecksumJSON returns the hex-encoded SHA-256 of a value's CanonicalJSON form.
func ChecksumJSON(value any) (string, error) {
	canonical, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return SHA256Hex(canonical), nil
}

// SHA256Hex returns the lowercase hex-encoded SHA-256 digest of b — the form
// every HDF checksum, integrity and content-address field carries.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// withoutNullValues returns a copy of a decoded JSON value with every
// null-valued object key removed. A null inside an array is preserved: array
// position is significant, so dropping an element would change the shape.
func withoutNullValues(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			if nested == nil {
				continue
			}
			out[key] = withoutNullValues(nested)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, nested := range typed {
			out[i] = withoutNullValues(nested)
		}
		return out
	default:
		return value
	}
}
