package hdfutil

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCpe_WellFormed(t *testing.T) {
	t.Run("standard well-formed CPE 2.3 URI", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", result.Raw)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "openssl", result.Vendor)
		assert.Equal(t, "openssl", result.Product)
		assert.Equal(t, "1.1.1k", result.Version)
		assert.Equal(t, "*", result.Update)
		assert.Equal(t, "*", result.Edition)
		assert.Equal(t, "*", result.Language)
		assert.Equal(t, "*", result.SwEdition)
		assert.Equal(t, "*", result.TargetSw)
		assert.Equal(t, "*", result.TargetHw)
		assert.Equal(t, "*", result.Other)
		assert.Empty(t, result.Warnings)
	})

	t.Run("real grype-style CPE (ca-certificates)", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:ca-certificates:ca-certificates:2023.2.64-1.amzn2.0.1:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "ca-certificates", result.Vendor)
		assert.Equal(t, "ca-certificates", result.Product)
		assert.Equal(t, "2023.2.64-1.amzn2.0.1", result.Version)
		assert.Empty(t, result.Warnings)
	})

	t.Run("operating system part (o)", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "o", result.Part)
		assert.Equal(t, "microsoft", result.Vendor)
		assert.Equal(t, "windows_10", result.Product)
		assert.Empty(t, result.Warnings)
	})

	t.Run("hardware part (h)", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:h:cisco:asr_1000:*:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "h", result.Part)
		assert.Empty(t, result.Warnings)
	})

	t.Run("any-part wildcard (*)", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:*:vendor:product:1.0:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "*", result.Part)
		assert.Empty(t, result.Warnings)
	})

	t.Run("all twelve product fields populated", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:vend:prod:1.0:beta:pro:en-us:enterprise:linux:x86_64:custom")
		require.NotNil(t, result)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "vend", result.Vendor)
		assert.Equal(t, "prod", result.Product)
		assert.Equal(t, "1.0", result.Version)
		assert.Equal(t, "beta", result.Update)
		assert.Equal(t, "pro", result.Edition)
		assert.Equal(t, "en-us", result.Language)
		assert.Equal(t, "enterprise", result.SwEdition)
		assert.Equal(t, "linux", result.TargetSw)
		assert.Equal(t, "x86_64", result.TargetHw)
		assert.Equal(t, "custom", result.Other)
		assert.Empty(t, result.Warnings)
	})
}

func TestParseCpe_MissingPrefixReturnsNil(t *testing.T) {
	t.Run("input without cpe:2.3: prefix", func(t *testing.T) {
		assert.Nil(t, ParseCpe("openssl:1.1.1k"))
	})

	t.Run("empty string", func(t *testing.T) {
		assert.Nil(t, ParseCpe(""))
	})

	t.Run("unrelated string", func(t *testing.T) {
		assert.Nil(t, ParseCpe("not a cpe at all"))
	})

	t.Run("CPE 2.2 URI binding form", func(t *testing.T) {
		assert.Nil(t, ParseCpe("cpe:/a:openssl:openssl:1.1.1k"))
	})

	t.Run("incorrect prefix version", func(t *testing.T) {
		assert.Nil(t, ParseCpe("cpe:2.4:a:openssl:openssl:1.1.1k"))
	})
}

func TestParseCpe_TruncatedPadsWithWarning(t *testing.T) {
	truncRe := regexp.MustCompile(`truncated: expected 13 colon-separated fields, got \d+`)

	t.Run("5-field truncated CPE padded with * defaults", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:openssl:openssl:1.1.1k")
		require.NotNil(t, result)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "openssl", result.Vendor)
		assert.Equal(t, "openssl", result.Product)
		assert.Equal(t, "1.1.1k", result.Version)
		assert.Equal(t, "*", result.Update)
		assert.Equal(t, "*", result.Edition)
		assert.Equal(t, "*", result.Language)
		assert.Equal(t, "*", result.SwEdition)
		assert.Equal(t, "*", result.TargetSw)
		assert.Equal(t, "*", result.TargetHw)
		assert.Equal(t, "*", result.Other)
		require.Len(t, result.Warnings, 1)
		assert.Regexp(t, truncRe, result.Warnings[0])
	})

	t.Run("bare prefix cpe:2.3: yields all-empty fields with warning", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:")
		require.NotNil(t, result)
		assert.Equal(t, "", result.Part)
		assert.Equal(t, "", result.Vendor)
		assert.Equal(t, "", result.Product)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "", result.Update)
		assert.Equal(t, "", result.Edition)
		assert.Equal(t, "", result.Language)
		assert.Equal(t, "", result.SwEdition)
		assert.Equal(t, "", result.TargetSw)
		assert.Equal(t, "", result.TargetHw)
		assert.Equal(t, "", result.Other)
		joined := strings.Join(result.Warnings, " | ")
		assert.Contains(t, joined, "truncated")
	})

	t.Run("2-field truncated CPE", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:openssl")
		require.NotNil(t, result)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "openssl", result.Vendor)
		assert.Equal(t, "*", result.Product)
		var found bool
		for _, w := range result.Warnings {
			if truncRe.MatchString(w) {
				found = true
				break
			}
		}
		assert.True(t, found, "expected a truncated: warning, got %v", result.Warnings)
	})
}

func TestParseCpe_ExtraFieldsIgnored(t *testing.T) {
	t.Run("keeps 12 fields and warns when extras are present", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:a:vend:prod:1.0:*:*:*:*:*:*:*:extra1:extra2")
		require.NotNil(t, result)
		assert.Equal(t, "a", result.Part)
		assert.Equal(t, "vend", result.Vendor)
		assert.Equal(t, "prod", result.Product)
		assert.Equal(t, "*", result.Other)
		assert.Contains(t, result.Warnings, "extra fields ignored")
	})
}

func TestParseCpe_InvalidPartAcceptedWithWarning(t *testing.T) {
	t.Run("unknown part letter", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "x", result.Part)
		assert.Contains(t, result.Warnings, "unknown part: x")
	})

	t.Run("multi-character part", func(t *testing.T) {
		result := ParseCpe("cpe:2.3:app:vendor:product:1.0:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "app", result.Part)
		assert.Contains(t, result.Warnings, "unknown part: app")
	})

	t.Run("empty part field", func(t *testing.T) {
		result := ParseCpe("cpe:2.3::vendor:product:1.0:*:*:*:*:*:*:*")
		require.NotNil(t, result)
		assert.Equal(t, "", result.Part)
		assert.Contains(t, result.Warnings, "unknown part: ")
	})
}

func TestParseCpe_EscapeHandling(t *testing.T) {
	t.Run("unescapes backslash-colon in a field value", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:my\:vendor:product:1.0:*:*:*:*:*:*:*`)
		require.NotNil(t, result)
		assert.Equal(t, "my:vendor", result.Vendor)
		assert.Equal(t, "product", result.Product)
		assert.Equal(t, "1.0", result.Version)
	})

	t.Run("unescapes double-backslash", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:my\\vendor:product:1.0:*:*:*:*:*:*:*`)
		require.NotNil(t, result)
		assert.Equal(t, `my\vendor`, result.Vendor)
	})

	t.Run("does not split on escaped colon spanning fields", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:foo\:bar\:baz:product:1.0:*:*:*:*:*:*:*`)
		require.NotNil(t, result)
		assert.Equal(t, "foo:bar:baz", result.Vendor)
		assert.Equal(t, "product", result.Product)
	})

	t.Run("unescapes mixed escapes", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:a\\b\:c:product:1.0:*:*:*:*:*:*:*`)
		require.NotNil(t, result)
		assert.Equal(t, `a\b:c`, result.Vendor)
	})

	t.Run("preserves unknown backslash escapes verbatim", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:foo\nbar:product:1.0:*:*:*:*:*:*:*`)
		require.NotNil(t, result)
		assert.Equal(t, `foo\nbar`, result.Vendor)
	})

	t.Run("keeps a trailing lone backslash verbatim", func(t *testing.T) {
		result := ParseCpe(`cpe:2.3:a:vendor\`)
		require.NotNil(t, result)
		assert.Equal(t, `vendor\`, result.Vendor)
	})
}

func TestParseCpe_PreservesRawInput(t *testing.T) {
	inputs := []string{
		"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
		"cpe:2.3:a:openssl:openssl:1.1.1k",
		"cpe:2.3:",
		"cpe:2.3:a:vend:prod:1.0:*:*:*:*:*:*:*:extra",
	}
	for _, in := range inputs {
		result := ParseCpe(in)
		require.NotNil(t, result, "input: %q", in)
		assert.Equal(t, in, result.Raw, "input: %q", in)
	}
}
