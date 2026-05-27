// Package purl parses Package URL (PURL) strings for SBOM and CVE-scanner
// ingestion.
//
// PURL is the canonical package identifier used by CycloneDX, SPDX, OSV, the
// GitHub Advisory Database, and most modern scanners. See:
// https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst
//
// Grammar: pkg:type/namespace/name@version?qualifiers#subpath
//
// The parser is intentionally accept-and-warn. Scanners occasionally emit
// slightly malformed PURLs (qualifier with no `=`, missing name, etc.) and
// we'd rather record a warning than fail ingestion.
package hdfutil

import (
	"fmt"
	"net/url"
	"strings"
)

// ParsedPurl is the structured result of parsing a PURL string.
type ParsedPurl struct {
	// Raw is the original input string, unmodified.
	Raw string
	// Type is the package type (e.g. "npm", "rpm", "pypi", "maven"). Lowercased.
	Type string
	// Namespace is the namespace segment, or nil if the input has none.
	Namespace *string
	// Name is the package name. Empty string (with a warning) when absent.
	Name string
	// Version is the version after the `@` separator, URL-decoded.
	Version *string
	// Qualifiers are the key-value pairs from the `?` segment.
	Qualifiers map[string]string
	// Subpath is the fragment after `#`.
	Subpath *string
	// Warnings records deviations or oddities encountered during parsing.
	Warnings []string
}

const purlPrefix = "pkg:"

// ParsePurl parses a Package URL string.
//
// It returns nil only when the input is missing the mandatory `pkg:` prefix
// or the type segment. Other deviations are surfaced via the Warnings field
// on the returned value.
func ParsePurl(purlStr string) *ParsedPurl {
	if purlStr == "" || !strings.HasPrefix(purlStr, purlPrefix) {
		return nil
	}

	raw := purlStr
	warnings := []string{}

	remainder := strings.TrimPrefix(purlStr, purlPrefix)

	// Per spec, leading slashes after the scheme are stripped.
	remainder = strings.TrimLeft(remainder, "/")

	if remainder == "" {
		return nil
	}

	// Extract subpath (fragment). Everything after the first `#`.
	var subpath *string
	if i := strings.Index(remainder, "#"); i != -1 {
		s := remainder[i+1:]
		remainder = remainder[:i]
		if s != "" {
			subpath = &s
		}
	}

	// Extract qualifiers (query string). Everything after the first `?`.
	qualifiers := map[string]string{}
	if i := strings.Index(remainder, "?"); i != -1 {
		qStr := remainder[i+1:]
		remainder = remainder[:i]
		parseQualifiers(qStr, qualifiers, &warnings)
	}

	// Strip trailing slashes from the path portion.
	remainder = strings.TrimRight(remainder, "/")

	// Type is everything up to the first `/`.
	var typeStr, pathPart string
	if i := strings.Index(remainder, "/"); i == -1 {
		typeStr = remainder
		pathPart = ""
	} else {
		typeStr = remainder[:i]
		pathPart = remainder[i+1:]
	}

	if typeStr == "" {
		return nil
	}
	typeStr = strings.ToLower(typeStr)

	// Split version off the path part using the LAST `@`.
	var version *string
	nameAndNs := pathPart
	if i := strings.LastIndex(pathPart, "@"); i != -1 {
		v := safeDecode(pathPart[i+1:])
		nameAndNs = pathPart[:i]
		if v != "" {
			version = &v
		}
	}

	// Namespace is everything before the last `/` in the name+namespace
	// section; the final segment is the name.
	var namespace *string
	var name string
	if i := strings.LastIndex(nameAndNs, "/"); i == -1 {
		name = nameAndNs
	} else {
		nsRaw := nameAndNs[:i]
		name = nameAndNs[i+1:]
		// Decode each path segment independently to preserve embedded `/`.
		segs := strings.Split(nsRaw, "/")
		for j, s := range segs {
			segs[j] = safeDecode(s)
		}
		ns := strings.Join(segs, "/")
		if ns != "" {
			namespace = &ns
		}
	}

	name = safeDecode(name)

	if name == "" {
		warnings = append(warnings, "PURL is missing the name segment")
	}

	return &ParsedPurl{
		Raw:        raw,
		Type:       typeStr,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: qualifiers,
		Subpath:    subpath,
		Warnings:   warnings,
	}
}

// parseQualifiers parses the `?key=value&key=value` qualifier segment.
// Empty segments are skipped silently; segments with no `=` are recorded
// with an empty value and a warning. Values are URL-decoded.
func parseQualifiers(qStr string, out map[string]string, warnings *[]string) {
	for _, part := range strings.Split(qStr, "&") {
		if part == "" {
			continue
		}
		eq := strings.Index(part, "=")
		if eq == -1 {
			out[part] = ""
			*warnings = append(*warnings, fmt.Sprintf("qualifier %q has no value", part))
			continue
		}
		key := part[:eq]
		value := part[eq+1:]
		out[key] = safeDecode(value)
	}
}

// safeDecode returns url.QueryUnescape's result on success and the original
// string on failure. PURLs in the wild occasionally contain stray `%`
// characters that aren't legitimate percent-encoding, and we never want a
// scanner-supplied malformed string to halt ingestion.
func safeDecode(s string) string {
	// PathUnescape leaves `+` alone (correct for PURL path segments and
	// version values), unlike QueryUnescape which converts `+` to space.
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}
