// Package cvss40data holds the CVSS v4.0 scoring tables and nothing else.
//
// The data lives apart from the scoring code that reads it, so it exists once
// and both languages read that one copy: Go through the var below, TypeScript
// by importing the same file. It sits in a Go package because an embed pattern
// cannot reach outside the package directory that declares it.
package cvss40data

import _ "embed"

// Raw is the FIRST MacroVector lookup and max tables, verbatim. A var rather
// than an embed.FS behind a lookup: a filename typo is then a compile error and
// the bytes are the image rather than a heap copy.

//go:embed cvss40-data.json
var Raw []byte
