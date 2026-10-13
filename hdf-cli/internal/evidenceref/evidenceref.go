// Package evidenceref resolves a reference recorded in an evidence package to a path
// inside that package.
//
// It exists because a recorded reference is a uri-reference — the schema declares that on
// both contents[].uri and externalEvidence[].uri — while every consumer used to hand the
// raw value to a path join. So the legal spelling of a filename containing a space failed
// while the illegal spelling worked, and a producer following the declared format wrote a
// package this toolchain could not read.
package evidenceref

import (
	"net/url"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Decoded is a reference whose percent-escapes have been resolved exactly once.
//
// A DISTINCT TYPE, not a string, because decoding twice is silently destructive and
// convention did not prevent it: "100%25done.json" is the only legal way to write a
// filename containing a percent, it decodes to "100%done.json", and decoding THAT again
// is an error. While resolving was a matter of calling the right helper on the right
// string, a value that had already been decoded by one hop got decoded again by the next
// — which I did while writing this very card, and no comment would have stopped it.
//
// The type does not make a second decode IMPOSSIBLE — Go permits the conversion, and
// packageSubtreeRef performs it twice, legitimately, because it takes a Decoded and
// returns a path derived from it. What the type does is make the second decode VISIBLE:
// a caller holding a Decoded cannot pass it to Decode without writing a conversion that
// says, in the code, that it believes the value is still raw. That is the claim, and it
// is weaker than "not expressible" — which is what an earlier version of this comment
// said before a prose pass caught it.
type Decoded string

// Decode resolves a RAW recorded reference's percent-escapes, once.
//
// A value whose percent introduces no valid escape is reported rather than guessed at:
// falling back to the raw bytes would make resolution depend on whether a filename
// happens to contain a %. Through the CLI such a package is already refused by schema
// validation, which enforces format: uri-reference and says so — this error is the
// boundary for callers that do not validate first.
func Decode(raw string) (Decoded, error) {
	d, err := hdfengine.DecodeReference(raw)
	if err != nil {
		return "", err
	}
	return Decoded(d), nil
}

// Path confines an already-decoded reference to the package directory.
//
// DECODE FIRST, CONFINE SECOND, and the type is what guarantees the order. Decoding can
// CREATE a traversal — "%2e%2e/x" becomes "../x", "a%2Fb" gains a separator — so the
// containment check must see the decoded form. Confining the raw value and decoding after
// would hand a caller a path that passed a check the bytes it finally used never took.
//
// Deliberately NOT inside hdfutil.SafePath, even though that is where containment lives:
// SafePath also resolves values that are not references — a generated control's filename,
// an MCP tool's --path argument — and percent-decoding those would corrupt a literal %
// that an operator typed. Decoding belongs to the evidence-reference contract.
func Path(pkgDir string, ref Decoded) (string, error) {
	return hdfutil.SafePath(pkgDir, string(ref))
}

// PathFromRecorded is Decode followed by Path, for a caller holding a raw reference that
// has not been through the shared enumeration — an operator's --uri, or a root reference
// field read straight off the document.
func PathFromRecorded(pkgDir, raw string) (string, error) {
	d, err := Decode(raw)
	if err != nil {
		return "", err
	}
	return Path(pkgDir, d)
}

// Encode writes a filesystem path back as a uri-reference, which is what a command
// RECORDING a reference must store: the field is declared uri-reference, so a name
// containing a space or a percent has to be escaped or the package it writes is
// off-schema. The inverse of Decode, and the reason a file named "bad%zzname.json" is
// expressible at all — as "bad%25zzname.json".
//
// net/url does this: EscapedPath escapes a path per RFC 3986, leaving the separators
// alone. A hand-rolled version — splitting on "/" and url.PathEscape-ing each segment —
// was the first implementation, and it was both a reinvention and slightly WRONG: it
// escaped ";" to "%3B", which RFC 3986 admits unescaped in a segment, so it wrote a
// different reference than a standards-conforming producer would for the same filename.
// That is an interop defect in a card whose whole premise is interop.
//
// url.PathEscape alone is the wrong call here — it escapes the separator too, turning
// "scans/x.json" into "scans%2Fx.json".
func Encode(path string) string {
	return (&url.URL{Path: path}).EscapedPath()
}
