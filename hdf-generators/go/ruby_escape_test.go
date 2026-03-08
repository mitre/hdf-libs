package generators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeQuotes_PlainText(t *testing.T) {
	assert.Equal(t, "'hello world'", EscapeQuotes("hello world"))
}

func TestEscapeQuotes_EmptyString(t *testing.T) {
	assert.Equal(t, "''", EscapeQuotes(""))
}

func TestEscapeQuotes_SingleQuotes(t *testing.T) {
	// String with single quotes → double-quoted
	assert.Equal(t, `"it's a test"`, EscapeQuotes("it's a test"))
}

func TestEscapeQuotes_DoubleQuotes(t *testing.T) {
	// String with double quotes → single-quoted
	assert.Equal(t, `'say "hello"'`, EscapeQuotes(`say "hello"`))
}

func TestEscapeQuotes_BothQuoteTypes(t *testing.T) {
	assert.Equal(t, `%q(it's a "test")`, EscapeQuotes(`it's a "test"`))
}

func TestEscapeQuotes_BackslashesInSingleQuoted(t *testing.T) {
	assert.Equal(t, `'path\\to\\file'`, EscapeQuotes(`path\to\file`))
}

func TestEscapeQuotes_BackslashesInDoubleQuoted(t *testing.T) {
	assert.Equal(t, `"it's a path\\to\\file"`, EscapeQuotes(`it's a path\to\file`))
}

func TestEscapeQuotes_BackslashBeforeParenInPercentQ(t *testing.T) {
	// \) → \\) in %q mode so Ruby sees literal backslash, then ) closes %q()
	assert.Equal(t, `%q(it's a "test" with \\))`, EscapeQuotes(`it's a "test" with \)`))
}

func TestEscapeQuotes_OnlyBackslashes(t *testing.T) {
	assert.Equal(t, `'\\'`, EscapeQuotes(`\`))
}

func TestEscapeQuotes_MultilineContent(t *testing.T) {
	result := EscapeQuotes("line one\nline two")
	assert.Contains(t, result, "line one")
	assert.Contains(t, result, "line two")
}
