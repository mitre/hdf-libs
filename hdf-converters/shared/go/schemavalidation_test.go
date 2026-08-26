package shared

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileURL covers the platform-independent path→file-URL shapes. The Windows
// drive case is the regression that motivated this helper: "file://"+`D:\...`
// parses as host "d" with an invalid port, making the schema compiler reject it
// on Windows CI. Detection is pure string-shape (never runtime.GOOS), so every
// shape is exercised on any OS.
func TestFileURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"windows drive backslash", `D:\a\schemas\poam.json`, "file:///D:/a/schemas/poam.json"},
		{"windows drive forward slash", "C:/Users/x/poam.json", "file:///C:/Users/x/poam.json"},
		{"windows drive with space", `C:\Users\x\a b.json`, "file:///C:/Users/x/a%20b.json"},
		{"unc path", `\\server\share\poam.json`, "file://server/share/poam.json"},
		{"posix absolute", "/Users/x/poam.json", "file:///Users/x/poam.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fileURL(tc.in)
			assert.Equal(t, tc.want, got)
			// Every result must parse as a URL with no spurious port — the exact
			// failure mode on Windows was "invalid port" from an unescaped drive.
			parsed, err := url.Parse(got)
			require.NoError(t, err, "result must be a parseable URL")
			assert.Empty(t, parsed.Port(), "no port component")
			assert.Equal(t, "file", parsed.Scheme)
		})
	}
}

// formatCase is one row of the cross-language table in
// ../testdata/format-assertion-cases.json. The TypeScript peer reads the same
// file, so the two validators cannot drift apart on `format` unnoticed.
// A case states Valid when both libraries agree, or Go and TS when they do not.
// A pointer distinguishes "recorded as false" from "not stated", so a
// half-specified row fails loudly instead of defaulting to reject.
type formatCase struct {
	Format    string `json:"format"`
	Valid     *bool  `json:"valid"`
	Go        *bool  `json:"go"`
	TS        *bool  `json:"ts"`
	GoDraft07 *bool  `json:"goDraft07"`
	Value     string `json:"value"`
	Why       string `json:"why"`
}

// want reports the verdict this case records for Go in the given dialect. The
// draft-07 path is served by a different library, so a case may override it.
func (c formatCase) want(t *testing.T, dialect string) bool {
	t.Helper()
	if c.GoDraft07 != nil && strings.Contains(dialect, "draft-07") {
		return *c.GoDraft07
	}
	switch {
	case c.Valid != nil:
		require.Nil(t, c.Go, "a case states valid or go/ts, never both")
		return *c.Valid
	case c.Go != nil && c.TS != nil:
		return *c.Go
	}
	t.Fatalf("case %s %q states neither valid nor both of go/ts", c.Format, c.Value)
	return false
}

func loadFormatCases(t *testing.T) ([]formatCase, []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "format-assertion-cases.json"))
	require.NoError(t, err, "read the shared format table")
	var table struct {
		Formats []string     `json:"formats"`
		Cases   []formatCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &table))
	require.NotEmpty(t, table.Cases)
	covered := map[string]bool{}
	for _, c := range table.Cases {
		covered[c.Format] = true
	}
	for _, f := range table.Formats {
		require.True(t, covered[f], "format %q is declared but has no cases", f)
	}
	return table.Cases, table.Formats
}

// formatSchema writes a one-property schema asserting a single format, in the
// requested dialect, and returns a validator for it. Both validator paths are
// exercised: the HDF schemas are 2020-12, but the same helper validates
// draft-07 target schemas through a different library.
func formatSchema(t *testing.T, format, dialect string) *SchemaValidator {
	t.Helper()
	schema := map[string]any{
		"$schema":    dialect,
		"type":       "object",
		"properties": map[string]any{"v": map[string]any{"type": "string", "format": format}},
	}
	raw, err := json.Marshal(schema)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "format.schema.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return NewSchemaValidator(t, path)
}

// A test that asserts "this input is valid HDF" before converting is only worth
// the line it occupies if the validator behind it actually checks the schema.
// JSON Schema 2020-12 makes format an annotation by default, so until the
// compiler opts in, every uuid, date-time and uri violation slipped through here
// while the ajv-backed TypeScript peer rejected it.
func TestSchemaValidator_AssertsFormat(t *testing.T) {
	cases, _ := loadFormatCases(t)
	for _, dialect := range []string{
		"https://json-schema.org/draft/2020-12/schema",
		"http://json-schema.org/draft-07/schema#",
	} {
		t.Run(dialect, func(t *testing.T) {
			for _, tc := range cases {
				name := tc.Format + "/" + tc.Value
				if tc.Value == "" {
					name = tc.Format + "/(empty)"
				}
				t.Run(name, func(t *testing.T) {
					doc, err := json.Marshal(map[string]string{"v": tc.Value})
					require.NoError(t, err)
					err = formatSchema(t, tc.Format, dialect).Validate(doc)
					if tc.want(t, dialect) {
						assert.NoError(t, err, "%s must accept %q. %s", tc.Format, tc.Value, tc.Why)
					} else {
						assert.Error(t, err, "%s must reject %q. %s", tc.Format, tc.Value, tc.Why)
					}
				})
			}
		})
	}
}
