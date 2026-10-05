package hdftohtml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assetFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("assets", name))
	require.NoError(t, err, "missing asset %s", name)
	return string(data)
}

// tsConstant reads one string constant out of the generated TypeScript module.
// The generator writes each one as a single JSON-quoted line, so the exact bytes
// can be read back without a TypeScript toolchain.
func tsConstant(t *testing.T, module, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^export const ` + name + ` = (".*");$`)
	m := pattern.FindStringSubmatch(module)
	require.NotNil(t, m, "the generated module must export %s as one quoted string", name)
	var value string
	require.NoError(t, json.Unmarshal([]byte(m[1]), &value))
	return value
}

func generatedTypeScriptAssets(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "typescript", "assets.ts"))
	require.NoError(t, err)
	return string(data)
}

// The stylesheet and the script are files. Go embeds them and the TypeScript
// module is generated from the same files, so an edit cannot land in one
// language only.
func TestAssets_GoAndTypeScriptEmbedTheSameBytes(t *testing.T) {
	blades := assetFile(t, "blades.min.css")
	report := assetFile(t, "report.css")
	reportScript := assetFile(t, "report.js")

	assert.Equal(t, blades, bladesCSS, "Go must embed the vendored stylesheet verbatim")
	assert.Equal(t, report, reportCSS, "Go must embed the report layer verbatim")
	assert.Equal(t, reportScript, script, "Go must embed the script verbatim")
	assert.Equal(t, blades+"\n"+report, stylesheet, "the inline stylesheet is the vendored file then the report layer")

	module := generatedTypeScriptAssets(t)
	assert.Equal(t, blades, tsConstant(t, module, "BLADES_CSS"))
	assert.Equal(t, report, tsConstant(t, module, "REPORT_CSS"))
	assert.Equal(t, reportScript, tsConstant(t, module, "SCRIPT"))
	assert.Equal(t, scriptHash, tsConstant(t, module, "SCRIPT_HASH"),
		"regenerate the module with: pnpm --filter @mitre/hdf-converters run generate")
}

// The hash in the content security policy is derived from the embedded script,
// so a script edit cannot leave the policy pointing at the previous bytes.
func TestAssets_ScriptHashIsDerivedFromTheEmbeddedScript(t *testing.T) {
	sum := sha256.Sum256([]byte("\n" + assetFile(t, "report.js")))
	assert.Equal(t, "sha256-"+base64.StdEncoding.EncodeToString(sum[:]), scriptHash)
}

// The vendored stylesheet is a third-party artifact: its digest is recorded in
// the provenance note beside it, and the file must still be that artifact.
func TestAssets_VendoredStylesheetMatchesItsProvenance(t *testing.T) {
	sum := sha256.Sum256([]byte(assetFile(t, "blades.min.css")))
	digest := hex.EncodeToString(sum[:])

	provenance := assetFile(t, "provenance.txt")
	assert.Contains(t, provenance, digest, "the recorded sha256 must be the digest of the vendored file")
	for _, want := range []string{"@anyblades/pico", "2.5.0", "MIT"} {
		assert.Contains(t, provenance, want)
	}
}

// Nothing in the report may reach the network, so the vendored stylesheet may
// only name resources it carries itself.
func TestAssets_StylesheetFetchesNothing(t *testing.T) {
	for _, css := range []string{bladesCSS, reportCSS} {
		assert.NotContains(t, css, "@import")
		assert.NotContains(t, css, "image-set(")
		for _, m := range regexp.MustCompile(`url\(\s*["']?([^"')]*)`).FindAllStringSubmatch(css, -1) {
			assert.True(t, strings.HasPrefix(m[1], "data:"), "url(%s) must be a data URI", m[1])
		}
	}
}

// Pico scales the root type up on wide screens and lets grid rows size each
// panel to its own content; the report layer pins both back, and the goldens
// alone would only detect a change, not guard it across a regeneration.
func TestAssets_ReportLayerPinsDensityAndDashboardLayout(t *testing.T) {
	assert.Contains(t, reportCSS, "--pico-font-size: 100%", "the report renders at the original 16px base, not Pico's wide-screen scale")
	assert.Regexp(t, `\.dashboard \{[^}]*align-items: stretch`, reportCSS, "the three dashboard panels must stretch to one height")
}
