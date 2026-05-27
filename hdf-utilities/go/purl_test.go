package hdfutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePurl_NullCases(t *testing.T) {
	t.Run("missing pkg prefix", func(t *testing.T) {
		assert.Nil(t, ParsePurl("npm/lodash@4.17.21"))
	})

	t.Run("empty string", func(t *testing.T) {
		assert.Nil(t, ParsePurl(""))
	})

	t.Run("only pkg prefix", func(t *testing.T) {
		assert.Nil(t, ParsePurl("pkg:"))
	})

	t.Run("pkg with only slash", func(t *testing.T) {
		assert.Nil(t, ParsePurl("pkg:/"))
	})
}

func TestParsePurl_Standard(t *testing.T) {
	t.Run("npm lodash", func(t *testing.T) {
		r := ParsePurl("pkg:npm/lodash@4.17.21")
		require.NotNil(t, r)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", r.Raw)
		assert.Equal(t, "npm", r.Type)
		assert.Nil(t, r.Namespace)
		assert.Equal(t, "lodash", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "4.17.21", *r.Version)
		assert.Empty(t, r.Qualifiers)
		assert.Nil(t, r.Subpath)
		assert.Empty(t, r.Warnings)
	})

	t.Run("pypi django", func(t *testing.T) {
		r := ParsePurl("pkg:pypi/django@4.2.1")
		require.NotNil(t, r)
		assert.Equal(t, "pypi", r.Type)
		assert.Nil(t, r.Namespace)
		assert.Equal(t, "django", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "4.2.1", *r.Version)
	})
}

func TestParsePurl_Namespaces(t *testing.T) {
	t.Run("rpm with namespace and qualifier", func(t *testing.T) {
		r := ParsePurl("pkg:rpm/redhat/openssl@1.1.1k-7.el8_4?arch=x86_64")
		require.NotNil(t, r)
		assert.Equal(t, "rpm", r.Type)
		require.NotNil(t, r.Namespace)
		assert.Equal(t, "redhat", *r.Namespace)
		assert.Equal(t, "openssl", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.1.1k-7.el8_4", *r.Version)
		assert.Equal(t, "x86_64", r.Qualifiers["arch"])
		assert.Len(t, r.Qualifiers, 1)
	})

	t.Run("maven multi-segment namespace", func(t *testing.T) {
		r := ParsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
		require.NotNil(t, r)
		assert.Equal(t, "maven", r.Type)
		require.NotNil(t, r.Namespace)
		assert.Equal(t, "org.apache.logging.log4j", *r.Namespace)
		assert.Equal(t, "log4j-core", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "2.14.1", *r.Version)
	})

	t.Run("golang with embedded slashes", func(t *testing.T) {
		r := ParsePurl("pkg:golang/github.com/spf13/cobra@v1.7.0")
		require.NotNil(t, r)
		assert.Equal(t, "golang", r.Type)
		require.NotNil(t, r.Namespace)
		assert.Equal(t, "github.com/spf13", *r.Namespace)
		assert.Equal(t, "cobra", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "v1.7.0", *r.Version)
	})
}

func TestParsePurl_Subpath(t *testing.T) {
	t.Run("bitbucket with subpath", func(t *testing.T) {
		r := ParsePurl("pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c#ui/templates/")
		require.NotNil(t, r)
		assert.Equal(t, "bitbucket", r.Type)
		require.NotNil(t, r.Namespace)
		assert.Equal(t, "birkenfeld", *r.Namespace)
		assert.Equal(t, "pygments-main", r.Name)
		require.NotNil(t, r.Subpath)
		assert.Equal(t, "ui/templates/", *r.Subpath)
	})

	t.Run("subpath with no version", func(t *testing.T) {
		r := ParsePurl("pkg:generic/foo#sub/path")
		require.NotNil(t, r)
		assert.Equal(t, "foo", r.Name)
		assert.Nil(t, r.Version)
		require.NotNil(t, r.Subpath)
		assert.Equal(t, "sub/path", *r.Subpath)
	})

	t.Run("empty fragment normalizes to nil subpath", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0.0#")
		require.NotNil(t, r)
		assert.Nil(t, r.Subpath)
	})
}

func TestParsePurl_Qualifiers(t *testing.T) {
	t.Run("multiple qualifiers", func(t *testing.T) {
		r := ParsePurl("pkg:deb/debian/curl@7.50.3?arch=amd64&distro=stretch")
		require.NotNil(t, r)
		assert.Equal(t, "amd64", r.Qualifiers["arch"])
		assert.Equal(t, "stretch", r.Qualifiers["distro"])
		assert.Len(t, r.Qualifiers, 2)
	})

	t.Run("qualifier with no equals warns", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0.0?arch")
		require.NotNil(t, r)
		assert.Equal(t, "", r.Qualifiers["arch"])
		assert.NotEmpty(t, r.Warnings)
		found := false
		for _, w := range r.Warnings {
			if assert.Contains(t, w, "arch") {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("URL-encoded qualifier value decoded", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0.0?path=%2Fusr%2Flocal")
		require.NotNil(t, r)
		assert.Equal(t, "/usr/local", r.Qualifiers["path"])
	})

	t.Run("empty qualifier segments skipped", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0.0?arch=amd64&&distro=stretch")
		require.NotNil(t, r)
		assert.Len(t, r.Qualifiers, 2)
	})
}

func TestParsePurl_Version(t *testing.T) {
	t.Run("URL-encoded version decoded", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0%2B0")
		require.NotNil(t, r)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0+0", *r.Version)
	})

	t.Run("percent-40 in version", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0%40beta")
		require.NotNil(t, r)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0@beta", *r.Version)
	})

	t.Run("multiple at signs uses last", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@bar@1.0.0")
		require.NotNil(t, r)
		assert.Equal(t, "foo@bar", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0.0", *r.Version)
	})

	t.Run("missing version", func(t *testing.T) {
		r := ParsePurl("pkg:npm/lodash")
		require.NotNil(t, r)
		assert.Equal(t, "lodash", r.Name)
		assert.Nil(t, r.Version)
	})

	t.Run("trailing at sign normalized to nil", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@")
		require.NotNil(t, r)
		assert.Nil(t, r.Version)
	})

	t.Run("malformed percent-encoding preserved", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0%ZZ")
		require.NotNil(t, r)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0%ZZ", *r.Version)
	})
}

func TestParsePurl_EdgeCases(t *testing.T) {
	t.Run("trailing slash stripped silently", func(t *testing.T) {
		r := ParsePurl("pkg:npm/lodash@4.17.21/")
		require.NotNil(t, r)
		assert.Equal(t, "lodash", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "4.17.21", *r.Version)
		assert.Empty(t, r.Warnings)
	})

	t.Run("empty name warns", func(t *testing.T) {
		r := ParsePurl("pkg:npm/")
		require.NotNil(t, r)
		assert.Equal(t, "npm", r.Type)
		assert.Equal(t, "", r.Name)
		assert.NotEmpty(t, r.Warnings)
	})

	t.Run("empty name with version warns", func(t *testing.T) {
		r := ParsePurl("pkg:npm/@1.0.0")
		require.NotNil(t, r)
		assert.Equal(t, "npm", r.Type)
		assert.Equal(t, "", r.Name)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0.0", *r.Version)
		assert.NotEmpty(t, r.Warnings)
	})

	t.Run("unknown type has no warning", func(t *testing.T) {
		r := ParsePurl("pkg:made-up-ecosystem/foo@1.0.0")
		require.NotNil(t, r)
		assert.Equal(t, "made-up-ecosystem", r.Type)
		assert.Empty(t, r.Warnings)
	})

	t.Run("type lowercased", func(t *testing.T) {
		r := ParsePurl("pkg:NPM/lodash@4.17.21")
		require.NotNil(t, r)
		assert.Equal(t, "npm", r.Type)
	})

	t.Run("raw preserved verbatim", func(t *testing.T) {
		input := "pkg:NPM/lodash@4.17.21"
		r := ParsePurl(input)
		require.NotNil(t, r)
		assert.Equal(t, input, r.Raw)
	})

	t.Run("qualifiers without version", func(t *testing.T) {
		r := ParsePurl("pkg:npm/lodash?arch=x86_64")
		require.NotNil(t, r)
		assert.Equal(t, "lodash", r.Name)
		assert.Nil(t, r.Version)
		assert.Equal(t, "x86_64", r.Qualifiers["arch"])
	})

	t.Run("qualifiers and subpath together", func(t *testing.T) {
		r := ParsePurl("pkg:npm/foo@1.0.0?arch=x86#sub")
		require.NotNil(t, r)
		require.NotNil(t, r.Version)
		assert.Equal(t, "1.0.0", *r.Version)
		assert.Equal(t, "x86", r.Qualifiers["arch"])
		require.NotNil(t, r.Subpath)
		assert.Equal(t, "sub", *r.Subpath)
	})

	t.Run("URL-encoded namespace decoded", func(t *testing.T) {
		r := ParsePurl("pkg:npm/%40scope/pkg@1.0.0")
		require.NotNil(t, r)
		require.NotNil(t, r.Namespace)
		assert.Equal(t, "@scope", *r.Namespace)
		assert.Equal(t, "pkg", r.Name)
	})
}
