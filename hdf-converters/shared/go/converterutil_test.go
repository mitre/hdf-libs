package shared

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

func TestLimitSlice(t *testing.T) {
	t.Run("returns full slice when under limit", func(t *testing.T) {
		items := []string{"a", "b", "c"}
		result, truncated := LimitSlice(items, 10)
		assert.Equal(t, items, result)
		assert.False(t, truncated)
	})

	t.Run("truncates when over limit", func(t *testing.T) {
		items := []int{1, 2, 3, 4, 5}
		result, truncated := LimitSlice(items, 3)
		assert.Equal(t, []int{1, 2, 3}, result)
		assert.True(t, truncated)
	})

	t.Run("uses default when maxItems is zero", func(t *testing.T) {
		items := []string{"a"}
		result, truncated := LimitSlice(items, 0)
		assert.Equal(t, items, result)
		assert.False(t, truncated)
	})

	t.Run("uses default when maxItems is negative", func(t *testing.T) {
		items := []string{"a"}
		result, truncated := LimitSlice(items, -1)
		assert.Equal(t, items, result)
		assert.False(t, truncated)
	})

	t.Run("handles empty slice", func(t *testing.T) {
		result, truncated := LimitSlice([]string{}, 10)
		assert.Empty(t, result)
		assert.False(t, truncated)
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var items []string
		result, truncated := LimitSlice(items, 10)
		assert.Empty(t, result)
		assert.False(t, truncated)
	})

	t.Run("handles exact limit boundary", func(t *testing.T) {
		items := []string{"a", "b", "c"}
		result, truncated := LimitSlice(items, 3)
		assert.Equal(t, items, result)
		assert.False(t, truncated)
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

func TestBuildNISTCCITags(t *testing.T) {
	t.Run("builds tags with nist only", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11", "RA-5"}, nil)
		assert.Len(t, tags, 1)
		nist, ok := tags["nist"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "SA-11", nist[0])
		assert.Equal(t, "RA-5", nist[1])
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})

	t.Run("builds tags with nist and cci", func(t *testing.T) {
		tags := BuildNISTCCITags(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
		)
		assert.Len(t, tags, 2)
		cci, ok := tags["cci"].([]interface{})
		require.True(t, ok)
		assert.Equal(t, "CCI-001453", cci[0])
	})

	t.Run("omits cci when empty slice", func(t *testing.T) {
		tags := BuildNISTCCITags([]string{"SA-11"}, []string{})
		_, hasCCI := tags["cci"]
		assert.False(t, hasCCI)
	})
}

func TestBuildNISTCCITagsWithExtras(t *testing.T) {
	t.Run("adds extra keys", func(t *testing.T) {
		extras := map[string]interface{}{
			"cveid": "CVE-2024-1234",
		}
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			[]string{"CCI-001453"},
			extras,
		)
		assert.Len(t, tags, 3)
		assert.Equal(t, "CVE-2024-1234", tags["cveid"])
	})

	t.Run("handles nil extras", func(t *testing.T) {
		tags := BuildNISTCCITagsWithExtras(
			[]string{"SA-11"},
			nil,
			nil,
		)
		assert.Len(t, tags, 1)
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

func TestExtractCWEIDs(t *testing.T) {
	t.Run("extracts single CWE-NNN", func(t *testing.T) {
		result := ExtractCWEIDs("CWE-79")
		assert.Equal(t, []string{"79"}, result)
	})

	t.Run("extracts multiple CWEs sorted", func(t *testing.T) {
		result := ExtractCWEIDs("CWE 89 and CWE-79")
		assert.Equal(t, []string{"79", "89"}, result)
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := ExtractCWEIDs("cwe22")
		assert.Equal(t, []string{"22"}, result)
	})

	t.Run("returns nil for no matches", func(t *testing.T) {
		result := ExtractCWEIDs("no cwe here")
		assert.Nil(t, result)
	})

	t.Run("returns nil for empty string", func(t *testing.T) {
		result := ExtractCWEIDs("")
		assert.Nil(t, result)
	})

	t.Run("deduplicates CWE IDs", func(t *testing.T) {
		result := ExtractCWEIDs("CWE-79, CWE-79")
		assert.Equal(t, []string{"79"}, result)
	})

	t.Run("handles mixed formats", func(t *testing.T) {
		result := ExtractCWEIDs("CWE-79, cwe 89, CWE22")
		assert.Equal(t, []string{"22", "79", "89"}, result)
	})
}

func TestCWEPattern(t *testing.T) {
	t.Run("matches CWE-NNN format", func(t *testing.T) {
		matches := CWEPattern.FindAllStringSubmatch("CWE-79", -1)
		require.Len(t, matches, 1)
		assert.Equal(t, "79", matches[0][1])
	})

	t.Run("matches CWE NNN format", func(t *testing.T) {
		matches := CWEPattern.FindAllStringSubmatch("CWE 89", -1)
		require.Len(t, matches, 1)
		assert.Equal(t, "89", matches[0][1])
	})

	t.Run("matches cweNNN format", func(t *testing.T) {
		matches := CWEPattern.FindAllStringSubmatch("cwe22", -1)
		require.Len(t, matches, 1)
		assert.Equal(t, "22", matches[0][1])
	})
}

func TestSeverityToImpact(t *testing.T) {
	t.Run("standard severity levels", func(t *testing.T) {
		assert.Equal(t, 0.9, SeverityToImpact("critical", 0.5))
		assert.Equal(t, 0.7, SeverityToImpact("high", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("medium", 0.5))
		assert.Equal(t, 0.3, SeverityToImpact("low", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("info", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("none", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("informational", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("information", 0.5))
	})

	t.Run("case insensitive", func(t *testing.T) {
		assert.Equal(t, 0.9, SeverityToImpact("Critical", 0.5))
		assert.Equal(t, 0.9, SeverityToImpact("CRITICAL", 0.5))
		assert.Equal(t, 0.7, SeverityToImpact("HIGH", 0.5))
		assert.Equal(t, 0.7, SeverityToImpact("High", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("MEDIUM", 0.5))
		assert.Equal(t, 0.3, SeverityToImpact("LOW", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("INFO", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("Info", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("INFORMATIONAL", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("Informational", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("INFORMATION", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("Information", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("NONE", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("None", 0.5))
	})

	t.Run("unknown severity returns defaultVal", func(t *testing.T) {
		assert.Equal(t, 0.5, SeverityToImpact("unknown", 0.5))
		assert.Equal(t, 0.3, SeverityToImpact("unknown", 0.3))
		assert.Equal(t, 0.0, SeverityToImpact("unknown", 0.0))
		assert.Equal(t, 1.0, SeverityToImpact("unknown", 1.0))
	})

	t.Run("empty string returns defaultVal", func(t *testing.T) {
		assert.Equal(t, 0.5, SeverityToImpact("", 0.5))
		assert.Equal(t, 0.3, SeverityToImpact("", 0.3))
	})

	t.Run("unrecognized strings return defaultVal", func(t *testing.T) {
		assert.Equal(t, 0.5, SeverityToImpact("blocker", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("important", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("moderate", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("negligible", 0.5))
		assert.Equal(t, 0.5, SeverityToImpact("5", 0.5))
	})
}

func TestSeverityToImpactWithAliases(t *testing.T) {
	t.Run("aliases override standard mappings", func(t *testing.T) {
		aliases := map[string]float64{
			"critical": 0.9, // matches standard (was override when standard was 1.0)
		}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("Critical", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("CRITICAL", aliases, 0.5))
	})

	t.Run("falls back to standard mappings", func(t *testing.T) {
		aliases := map[string]float64{
			"negligible": 0.0,
		}
		// These should fall through aliases to standard map
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", aliases, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("high", aliases, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("medium", aliases, 0.5))
		assert.Equal(t, 0.3, SeverityToImpactWithAliases("low", aliases, 0.5))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("info", aliases, 0.5))
		// Alias value
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("negligible", aliases, 0.5))
	})

	t.Run("returns defaultVal when not in aliases or standard", func(t *testing.T) {
		aliases := map[string]float64{
			"blocker": 1.0,
		}
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("unknown", aliases, 0.5))
		assert.Equal(t, 0.1, SeverityToImpactWithAliases("unknown", aliases, 0.1))
	})

	t.Run("empty aliases map falls back to standard", func(t *testing.T) {
		aliases := map[string]float64{}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", aliases, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("high", aliases, 0.5))
	})

	t.Run("nil aliases map falls back to standard", func(t *testing.T) {
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", nil, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("high", nil, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("unknown", nil, 0.5))
	})

	t.Run("sonarqube-style aliases", func(t *testing.T) {
		aliases := map[string]float64{
			"blocker":  1.0,
			"critical": 0.7, // SonarQube "critical" maps to 0.7, not standard 1.0
			"major":    0.5,
			"minor":    0.3,
		}
		assert.Equal(t, 1.0, SeverityToImpactWithAliases("BLOCKER", aliases, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("CRITICAL", aliases, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("MAJOR", aliases, 0.5))
		assert.Equal(t, 0.3, SeverityToImpactWithAliases("MINOR", aliases, 0.5))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("INFO", aliases, 0.5)) // falls through to standard
	})

	t.Run("veracode-style numeric aliases", func(t *testing.T) {
		aliases := map[string]float64{
			"5": 0.9,
			"4": 0.7,
			"3": 0.5,
			"2": 0.3,
			"1": 0.1,
			"0": 0.0,
		}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("5", aliases, 0.1))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("4", aliases, 0.1))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("3", aliases, 0.1))
		assert.Equal(t, 0.3, SeverityToImpactWithAliases("2", aliases, 0.1))
		assert.Equal(t, 0.1, SeverityToImpactWithAliases("1", aliases, 0.1))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("0", aliases, 0.1))
		assert.Equal(t, 0.1, SeverityToImpactWithAliases("99", aliases, 0.1))
	})

	t.Run("case insensitive alias keys", func(t *testing.T) {
		aliases := map[string]float64{
			"important": 0.9,
		}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("Important", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("IMPORTANT", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("important", aliases, 0.5))
	})

	t.Run("empty string returns defaultVal", func(t *testing.T) {
		aliases := map[string]float64{"blocker": 1.0}
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("", aliases, 0.5))
	})
}

func TestValidateXMLSize_Normal(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 0)
	assert.NoError(t, err)
}

func TestValidateXMLSize_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLSize(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLSize_CustomLimit(t *testing.T) {
	err := ValidateXMLSize([]byte("<root/>"), 5)
	assert.Error(t, err)
}

func TestContainsXMLEntityDeclarations_True(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	assert.True(t, ContainsXMLEntityDeclarations(xml))
}

func TestContainsXMLEntityDeclarations_False(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><foo>bar</foo>`)
	assert.False(t, ContainsXMLEntityDeclarations(xml))
}

func TestContainsXMLEntityDeclarations_CaseInsensitive(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!entity xxe "test">]><foo/>`)
	assert.True(t, ContainsXMLEntityDeclarations(xml))
}

func TestContainsXMLEntityDeclarations_EmptyInput(t *testing.T) {
	assert.False(t, ContainsXMLEntityDeclarations([]byte{}))
}

func TestValidateXMLInput_Clean(t *testing.T) {
	assert.NoError(t, ValidateXMLInput([]byte("<root/>"), 0))
}

func TestValidateXMLInput_WithEntities(t *testing.T) {
	xml := []byte(`<!DOCTYPE foo [<!ENTITY x "y">]><foo/>`)
	err := ValidateXMLInput(xml, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestValidateXMLInput_TooLarge(t *testing.T) {
	big := make([]byte, 51*1024*1024)
	err := ValidateXMLInput(big, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestValidateXMLInput_CustomSizeLimit(t *testing.T) {
	err := ValidateXMLInput([]byte("<root/>"), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestBuildHDFResults_MinimalFields(t *testing.T) {
	baseline := hdf.EvaluatedBaseline{Name: "test-baseline"}
	now := time.Now().UTC()

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Timestamp:        &now,
	})

	require.NotNil(t, result)
	assert.Equal(t, []hdf.EvaluatedBaseline{baseline}, result.Baselines)
	require.NotNil(t, result.Generator)
	assert.Equal(t, "test-to-hdf", result.Generator.Name)
	assert.Equal(t, "1.0.0", result.Generator.Version)
	assert.Equal(t, &now, result.Timestamp)
	assert.Nil(t, result.Tool)
	assert.Nil(t, result.Components)
	assert.Nil(t, result.Statistics)
}

func TestBuildHDFResults_WithToolName(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "grype-to-hdf",
		ConverterVersion: "1.0.0",
		ToolName:   "Grype",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Grype", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestBuildHDFResults_WithAllToolFields(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:     "sarif-to-hdf",
		ConverterVersion:  "1.0.0",
		ToolName:    "Semgrep",
		ToolVersion: "1.5.0",
		ToolFormat:  "SARIF",
		Baselines:         []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Equal(t, "Semgrep", *result.Tool.Name)
	assert.Equal(t, "1.5.0", *result.Tool.Version)
	assert.Equal(t, "SARIF", *result.Tool.Format)
}

func TestBuildHDFResults_EmptyToolStringsOmitted(t *testing.T) {
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	assert.Nil(t, result.Tool)
}

func TestBuildHDFResults_WithTargetsAndStatistics(t *testing.T) {
	targets := []hdf.Component{{Name: "web-server"}}
	dur := 42.5
	stats := &hdf.Statistics{Duration: &dur}

	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "nessus-to-hdf",
		ConverterVersion: "1.0.0",
		Baselines:        []hdf.EvaluatedBaseline{},
		Components:          targets,
		Statistics:       stats,
	})

	assert.Equal(t, targets, result.Components)
	assert.Equal(t, stats, result.Statistics)
}

func TestBuildHDFResults_ToolPartialFields(t *testing.T) {
	// Only format set, no name/version
	result := BuildHDFResults(HDFResultsOptions{
		GeneratorName:    "test-to-hdf",
		ConverterVersion: "1.0.0",
		ToolFormat: "XML",
		Baselines:        []hdf.EvaluatedBaseline{},
	})

	require.NotNil(t, result.Tool)
	assert.Nil(t, result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Equal(t, "XML", *result.Tool.Format)
}

func TestExtractXMLRootElement(t *testing.T) {
	t.Run("extracts root from simple XML", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("<root/>"))
	})

	t.Run("extracts root after XML declaration", func(t *testing.T) {
		assert.Equal(t, "Benchmark", ExtractXMLRootElement(`<?xml version="1.0"?><Benchmark/>`))
	})

	t.Run("strips namespace prefix", func(t *testing.T) {
		assert.Equal(t, "Benchmark", ExtractXMLRootElement("<xccdf:Benchmark/>"))
	})

	t.Run("extracts root after simple DOCTYPE", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("<?xml?>\n<!DOCTYPE root>\n<root/>"))
	})

	t.Run("extracts root after DOCTYPE with internal subset", func(t *testing.T) {
		input := `<?xml version="1.0"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "">
<!ELEMENT issue (name, severity)>
]>
<issues burpVersion="2024.1"><issue/></issues>`
		assert.Equal(t, "issues", ExtractXMLRootElement(input))
	})

	t.Run("extracts root after comments", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("<!-- comment --><root/>"))
	})

	t.Run("returns empty for plain text", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement("plain text"))
	})

	t.Run("returns empty for empty string", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement(""))
	})

	t.Run("handles whitespace before declarations", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("  \n\t <?xml version=\"1.0\"?> <root/>"))
	})

	t.Run("handles multiple comments", func(t *testing.T) {
		assert.Equal(t, "data", ExtractXMLRootElement("<!-- a --><!-- b --><data/>"))
	})

	t.Run("handles element with attributes", func(t *testing.T) {
		assert.Equal(t, "NessusClientData_v2", ExtractXMLRootElement(`<NessusClientData_v2 xmlns="http://nessus.org">`))
	})

	t.Run("handles unterminated processing instruction", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement("<?xml version"))
	})

	t.Run("handles unterminated comment", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement("<!-- unterminated"))
	})

	t.Run("handles unterminated DOCTYPE", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement("<!DOCTYPE foo"))
	})

	t.Run("handles DOCTYPE with internal subset but no closing bracket", func(t *testing.T) {
		assert.Equal(t, "", ExtractXMLRootElement("<!DOCTYPE foo [<!ENTITY x \"y\">"))
	})

	t.Run("handles other markup declarations", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("<!NOTATION foo SYSTEM \"bar\">\n<root/>"))
	})
}

func TestValidateJSONSize(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("exceeds custom limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte(`{"key":"value"}`), "test-converter", 5)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-converter")
		assert.Contains(t, err.Error(), "exceeds maximum allowed size")
	})

	t.Run("empty input within limit", func(t *testing.T) {
		err := ValidateJSONSize([]byte{}, "test-converter", 0)
		assert.NoError(t, err)
	})

	t.Run("uses default max size", func(t *testing.T) {
		err := ValidateJSONSize([]byte("small"), "test-converter", 0)
		assert.NoError(t, err)
	})
}
