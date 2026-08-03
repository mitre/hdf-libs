package shared

import (
	"net/url"
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
