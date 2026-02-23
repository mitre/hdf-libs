package testing

import (
	"testing"
	"time"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInputChecksum(t *testing.T) {
	t.Run("produces sha256 checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte("hello"))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", checksum.Value)
	})

	t.Run("empty input produces valid checksum", func(t *testing.T) {
		checksum := InputChecksum([]byte(""))
		require.NotNil(t, checksum)
		assert.Equal(t, hdf.Sha256, checksum.Algorithm)
		assert.Len(t, checksum.Value, 64)
	})

	t.Run("different input produces different checksum", func(t *testing.T) {
		c1 := InputChecksum([]byte("hello"))
		c2 := InputChecksum([]byte("world"))
		assert.NotEqual(t, c1.Value, c2.Value)
	})
}

func TestPtr(t *testing.T) {
	t.Run("string pointer", func(t *testing.T) {
		p := Ptr("hello")
		require.NotNil(t, p)
		assert.Equal(t, "hello", *p)
	})

	t.Run("float64 pointer", func(t *testing.T) {
		p := Ptr(3.14)
		require.NotNil(t, p)
		assert.Equal(t, 3.14, *p)
	})

	t.Run("int pointer", func(t *testing.T) {
		p := Ptr(42)
		require.NotNil(t, p)
		assert.Equal(t, 42, *p)
	})

	t.Run("bool pointer", func(t *testing.T) {
		p := Ptr(true)
		require.NotNil(t, p)
		assert.True(t, *p)
	})

	t.Run("returns independent pointer", func(t *testing.T) {
		p1 := Ptr("same")
		p2 := Ptr("same")
		assert.NotSame(t, p1, p2) // different pointers
		assert.Equal(t, *p1, *p2) // same value
	})
}

func TestStripHTML(t *testing.T) {
	t.Run("strips simple tags", func(t *testing.T) {
		assert.Equal(t, "hello world", StripHTML("<p>hello</p> <b>world</b>"))
	})

	t.Run("strips nested tags", func(t *testing.T) {
		assert.Equal(t, "text", StripHTML("<div><span>text</span></div>"))
	})

	t.Run("normalizes whitespace", func(t *testing.T) {
		assert.Equal(t, "a b c", StripHTML("  a   b   c  "))
	})

	t.Run("handles self-closing tags", func(t *testing.T) {
		assert.Equal(t, "before after", StripHTML("before<br/>after"))
	})

	t.Run("returns empty string for empty input", func(t *testing.T) {
		assert.Equal(t, "", StripHTML(""))
	})

	t.Run("returns plain text unchanged", func(t *testing.T) {
		assert.Equal(t, "no tags here", StripHTML("no tags here"))
	})

	t.Run("handles tags with attributes", func(t *testing.T) {
		assert.Equal(t, "link text", StripHTML(`<a href="http://example.com">link text</a>`))
	})
}

func TestParseTimestamp(t *testing.T) {
	t.Run("parses RFC3339", func(t *testing.T) {
		result := ParseTimestamp("2024-01-15T10:30:00Z")
		expected := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		assert.True(t, result.Equal(expected))
	})

	t.Run("parses RFC3339Nano", func(t *testing.T) {
		result := ParseTimestamp("2024-01-15T10:30:00.123456789Z")
		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("parses RFC1123", func(t *testing.T) {
		result := ParseTimestamp("Mon, 15 Jan 2024 10:30:00 UTC")
		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("parses Nessus format", func(t *testing.T) {
		result := ParseTimestamp("Mon Jan 15 10:30:00 2024")
		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("returns zero time for empty string", func(t *testing.T) {
		assert.True(t, ParseTimestamp("").IsZero())
	})

	t.Run("returns zero time for unparseable string", func(t *testing.T) {
		assert.True(t, ParseTimestamp("not a timestamp").IsZero())
	})

	t.Run("parses RFC3339 with timezone offset", func(t *testing.T) {
		result := ParseTimestamp("2024-01-15T10:30:00+05:00")
		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})
}

func TestStringsToInterfaces(t *testing.T) {
	t.Run("converts string slice to interface slice", func(t *testing.T) {
		input := []string{"SA-11", "RA-5"}
		result := StringsToInterfaces(input)
		require.Len(t, result, 2)
		assert.Equal(t, "SA-11", result[0])
		assert.Equal(t, "RA-5", result[1])
	})

	t.Run("handles empty slice", func(t *testing.T) {
		result := StringsToInterfaces([]string{})
		assert.Empty(t, result)
		assert.NotNil(t, result) // should be empty slice, not nil
	})

	t.Run("handles nil slice", func(t *testing.T) {
		result := StringsToInterfaces(nil)
		assert.Empty(t, result)
	})

	t.Run("preserves order", func(t *testing.T) {
		input := []string{"c", "a", "b"}
		result := StringsToInterfaces(input)
		assert.Equal(t, "c", result[0])
		assert.Equal(t, "a", result[1])
		assert.Equal(t, "b", result[2])
	})
}

func TestSafeString(t *testing.T) {
	t.Run("extracts string value", func(t *testing.T) {
		assert.Equal(t, "hello", SafeString("hello"))
	})

	t.Run("returns empty for nil", func(t *testing.T) {
		assert.Equal(t, "", SafeString(nil))
	})

	t.Run("returns empty for non-string", func(t *testing.T) {
		assert.Equal(t, "", SafeString(42))
		assert.Equal(t, "", SafeString(true))
		assert.Equal(t, "", SafeString([]string{"a"}))
	})
}

func TestSafeStringSlice(t *testing.T) {
	t.Run("extracts string slice from interface slice", func(t *testing.T) {
		input := []interface{}{"SA-11", "RA-5"}
		result := SafeStringSlice(input)
		assert.Equal(t, []string{"SA-11", "RA-5"}, result)
	})

	t.Run("returns nil for nil input", func(t *testing.T) {
		assert.Nil(t, SafeStringSlice(nil))
	})

	t.Run("returns nil for non-slice input", func(t *testing.T) {
		assert.Nil(t, SafeStringSlice("not a slice"))
	})

	t.Run("skips non-string elements", func(t *testing.T) {
		input := []interface{}{"SA-11", 42, "RA-5", true}
		result := SafeStringSlice(input)
		assert.Equal(t, []string{"SA-11", "RA-5"}, result)
	})

	t.Run("handles empty interface slice", func(t *testing.T) {
		input := []interface{}{}
		result := SafeStringSlice(input)
		assert.Empty(t, result)
	})
}
