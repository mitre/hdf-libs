package hdftohtml

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
)

// The stylesheet and script are files under assets/, embedded here and generated
// into the TypeScript peer's module from the same bytes. No document text ever
// reaches them. assets/provenance.txt records where the vendored stylesheet came
// from and why the files live beside this package.

//go:embed assets/blades.min.css
var bladesCSS string

//go:embed assets/report.css
var reportCSS string

//go:embed assets/report.js
var script string

// The vendored file carries no trailing newline, so one separates it from the
// report layer that overrides it.
var stylesheet = bladesCSS + "\n" + reportCSS

// scriptHash is the CSP source expression for the one script the report carries,
// taken from the embedded bytes so the policy cannot name a stale script. The
// element's content is the newline after <script> plus the script itself. The
// policy admits this script and nothing else, so text that slipped past escaping
// still could not run.
var scriptHash = computeScriptHash()

func computeScriptHash() string {
	sum := sha256.Sum256([]byte("\n" + script))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}
