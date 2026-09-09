package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A document-controlled field path reaches the terminal through validate's
// human output. The root `labels` object on hdf-amendments is an open key
// space (additionalProperties: {type: string}), so a key carrying a CSI
// sequence rides into the error message verbatim while a non-string value is
// what raises the error. `hdf amend verify` already routes the same strings
// through sanitizeOutput, so the two commands must not disagree.
const csi = "\x1b[31m"

func writeEvilAmendments(t *testing.T) string {
	t.Helper()
	doc := map[string]interface{}{
		"amendmentId":      "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"amendmentVersion": "1.0.0",
		"labels":           map[string]interface{}{"evil" + csi + "key": 123},
		"overrides":        []interface{}{},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "evil-amendments.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestValidate_SanitizesUntrustedFieldPaths(t *testing.T) {
	path := writeEvilAmendments(t)

	_, stderr, err := executeCommand("validate", "--type", "amendments", path)
	require.Error(t, err)

	// Assert the message is actually rendered, so the escape assertion below
	// cannot pass vacuously on empty output.
	assert.Contains(t, stderr, "Invalid type. Expected: string, given: integer")
	assert.Contains(t, stderr, "labels.evil", "the offending key must stay visible")
	assert.Contains(t, stderr, "key:", "the key's visible characters must survive sanitizing")
	assert.NotContains(t, stderr, "\x1b", "an escape sequence from the document reached the terminal")
}

// validate and amend verify must render the same document identically with
// respect to escapes; they disagreed before this fix.
func TestValidate_AgreesWithAmendVerifyOnEscapes(t *testing.T) {
	path := writeEvilAmendments(t)

	_, validateErr, err := executeCommand("validate", "--type", "amendments", path)
	require.Error(t, err)
	verifyOut, verifyErr, err := executeCommand("amend", "verify", path)
	require.Error(t, err)

	assert.NotContains(t, validateErr, "\x1b")
	assert.NotContains(t, verifyOut+verifyErr, "\x1b")
}

// Every branch of the print switch renders document-derived text, so each one
// is exercised: with a line number, without one, and the field-less default
// where only the description is printed.
func TestOutputValidationHuman_SanitizesEveryBranch(t *testing.T) {
	cases := []struct {
		name    string
		lineMap map[string]int
		errs    []validators.ValidationError
		visible string
		// wantLine pins that the line-number branch was actually taken, so a
		// lookup keyed on the SANITIZED field — which misses the map and
		// silently drops to the no-line branch — cannot pass this case.
		wantLine string
	}{
		{
			name:     "with line number",
			lineMap:  map[string]int{"labels.evil" + csi + "key": 5},
			errs:     []validators.ValidationError{{Field: "labels.evil" + csi + "key", Description: "Invalid type"}},
			visible:  "labels.evil",
			wantLine: "line 5:",
		},
		{
			name:    "without line number",
			errs:    []validators.ValidationError{{Field: "labels.evil" + csi + "key", Description: "Invalid type"}},
			visible: "labels.evil",
		},
		{
			name:    "field-less default",
			errs:    []validators.ValidationError{{Description: "bad value " + csi + "here"}},
			visible: "bad value ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStderr(t, func() {
				outputValidationHuman("doc.json", "amendments",
					&validators.ValidationResult{Errors: tc.errs}, tc.lineMap)
			})
			assert.Contains(t, out, tc.visible, "the offending text must stay visible")
			assert.NotContains(t, out, "\x1b", "branch %q leaked an escape", tc.name)
			if tc.wantLine != "" {
				assert.Contains(t, out, tc.wantLine, "the line-number branch must be the one taken")
			}
		})
	}
}

// firstValidationError composes the message the enrich and events commands
// return, which main renders to stderr, so it carries the same exposure.
func TestFirstValidationError_Sanitizes(t *testing.T) {
	withField := firstValidationError(validators.ValidationResult{
		Errors: []validators.ValidationError{{Field: "labels.evil" + csi + "key", Description: "Invalid type"}},
	})
	assert.Contains(t, withField, "labels.evil")
	assert.Contains(t, withField, "Invalid type")
	assert.NotContains(t, withField, "\x1b")

	fieldless := firstValidationError(validators.ValidationResult{
		Errors: []validators.ValidationError{{Description: "bad value " + csi + "here"}},
	})
	assert.Contains(t, fieldless, "bad value ")
	assert.NotContains(t, fieldless, "\x1b")
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = buf.ReadFrom(r)
		close(done)
	}()

	fn()
	require.NoError(t, w.Close())
	os.Stderr = old
	<-done
	return strings.TrimRight(buf.String(), "\n")
}
