package hdfutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		assert.Equal(t, 0.0, SeverityToImpact("INFORMATIONAL", 0.5))
		assert.Equal(t, 0.0, SeverityToImpact("NONE", 0.5))
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
	})
}

func TestSeverityToImpactWithAliases(t *testing.T) {
	t.Run("aliases checked first", func(t *testing.T) {
		aliases := map[string]float64{
			"critical": 0.9,
		}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("Critical", aliases, 0.5))
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("CRITICAL", aliases, 0.5))
	})

	t.Run("falls back to standard mappings", func(t *testing.T) {
		aliases := map[string]float64{
			"negligible": 0.0,
		}
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", aliases, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("high", aliases, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("medium", aliases, 0.5))
		assert.Equal(t, 0.3, SeverityToImpactWithAliases("low", aliases, 0.5))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("info", aliases, 0.5))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("negligible", aliases, 0.5))
	})

	t.Run("returns defaultVal when not in aliases or standard", func(t *testing.T) {
		aliases := map[string]float64{
			"blocker": 1.0,
		}
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("unknown", aliases, 0.5))
		assert.Equal(t, 0.1, SeverityToImpactWithAliases("unknown", aliases, 0.1))
	})

	t.Run("nil aliases map falls back to standard", func(t *testing.T) {
		assert.Equal(t, 0.9, SeverityToImpactWithAliases("critical", nil, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("high", nil, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("unknown", nil, 0.5))
	})

	t.Run("sonarqube-style aliases", func(t *testing.T) {
		aliases := map[string]float64{
			"blocker":  1.0,
			"critical": 0.7,
			"major":    0.5,
			"minor":    0.3,
		}
		assert.Equal(t, 1.0, SeverityToImpactWithAliases("BLOCKER", aliases, 0.5))
		assert.Equal(t, 0.7, SeverityToImpactWithAliases("CRITICAL", aliases, 0.5))
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("MAJOR", aliases, 0.5))
		assert.Equal(t, 0.3, SeverityToImpactWithAliases("MINOR", aliases, 0.5))
		assert.Equal(t, 0.0, SeverityToImpactWithAliases("INFO", aliases, 0.5))
	})

	t.Run("empty string returns defaultVal", func(t *testing.T) {
		aliases := map[string]float64{"blocker": 1.0}
		assert.Equal(t, 0.5, SeverityToImpactWithAliases("", aliases, 0.5))
	})
}

func TestImpactToSeverity(t *testing.T) {
	tests := []struct {
		impact   float64
		expected string
	}{
		{1.0, "critical"},
		{0.9, "critical"},
		{0.89, "high"},
		{0.7, "high"},
		{0.69, "medium"},
		{0.5, "medium"},
		{0.4, "medium"},
		{0.39, "low"},
		{0.1, "low"},
		{0.01, "low"},
		{0.0, "informational"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, ImpactToSeverity(tt.impact), "ImpactToSeverity(%v)", tt.impact)
	}
}

func TestImpactToSeverity_RoundTrip(t *testing.T) {
	// SeverityToImpact -> ImpactToSeverity should return the original label
	for _, sev := range []string{"critical", "high", "medium", "low", "informational"} {
		impact := SeverityToImpact(sev, 0.5)
		got := ImpactToSeverity(impact)
		assert.Equal(t, sev, got, "round-trip for %q (impact=%v)", sev, impact)
	}
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
		assert.NotNil(t, result)
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
		assert.NotSame(t, p1, p2)
		assert.Equal(t, *p1, *p2)
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

	t.Run("parses RFC1123Z", func(t *testing.T) {
		result := ParseTimestamp("Mon, 15 Jan 2024 10:30:00 +0000")

		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("parses ISO 8601 without timezone", func(t *testing.T) {
		result := ParseTimestamp("2024-01-15T10:30:00")

		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("parses Nessus format", func(t *testing.T) {
		result := ParseTimestamp("Mon Jan 15 10:30:00 2024")

		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})

	t.Run("returns zero time for empty string", func(t *testing.T) {
		result := ParseTimestamp("")

		assert.True(t, result.IsZero())
	})

	t.Run("returns zero time for unparseable string", func(t *testing.T) {
		result := ParseTimestamp("not a timestamp")

		assert.True(t, result.IsZero())
	})

	t.Run("parses RFC3339 with timezone offset", func(t *testing.T) {
		result := ParseTimestamp("2024-01-15T10:30:00+05:00")

		assert.False(t, result.IsZero())
		assert.Equal(t, 2024, result.Year())
	})
}

func TestContainsXMLEntityDeclarations(t *testing.T) {
	t.Run("detects entity declarations", func(t *testing.T) {
		xml := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
		assert.True(t, ContainsXMLEntityDeclarations(xml))
	})

	t.Run("returns false for clean XML", func(t *testing.T) {
		xml := []byte(`<?xml version="1.0"?><foo>bar</foo>`)
		assert.False(t, ContainsXMLEntityDeclarations(xml))
	})

	t.Run("case insensitive", func(t *testing.T) {
		xml := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!entity xxe "test">]><foo/>`)
		assert.True(t, ContainsXMLEntityDeclarations(xml))
	})

	t.Run("returns false for empty input", func(t *testing.T) {
		assert.False(t, ContainsXMLEntityDeclarations([]byte{}))
	})
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

	t.Run("handles mixed-case DOCTYPE", func(t *testing.T) {
		assert.Equal(t, "root", ExtractXMLRootElement("<!DocType root>\n<root/>"))
	})

	t.Run("handles mixed-case DOCTYPE with internal subset", func(t *testing.T) {
		input := `<!Doctype issues [
<!ELEMENT issues (issue*)>
]>
<issues/>`
		assert.Equal(t, "issues", ExtractXMLRootElement(input))
	})
}
