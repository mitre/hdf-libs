package generators

import (
	"fmt"
	"path/filepath"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// GeneratorOptions configures InSpec profile generation.
type GeneratorOptions struct {
	// Put all controls in a single controls.rb file instead of one file per control.
	SingleFile bool
	// Override baseline metadata in the generated inspec.yml.
	Metadata *ProfileMetadata
	// InSpec version constraint for inspec.yml. Default: "~>6.0".
	InSpecVersion string
}

// ProfileMetadata provides metadata overrides for the generated inspec.yml.
type ProfileMetadata struct {
	Maintainer string
	Copyright  string
	License    string
	Version    string
}

// InSpecProfile is an in-memory InSpec profile. No file I/O.
type InSpecProfile struct {
	// The inspec.yml content as a YAML string.
	InSpecYml string
	// Map of filename (e.g. "controls/SV-238196.rb") to Ruby source code.
	Controls map[string]string
}

// GenerateInSpecYml generates an inspec.yml YAML string from an HDF Baseline and options.
func GenerateInSpecYml(baseline hdf.HDFBaseline, opts *GeneratorOptions) string {
	var lines []string

	lines = append(lines, fmt.Sprintf("name: %s", yamlScalar(baseline.Name)))

	if baseline.Title != nil {
		lines = append(lines, fmt.Sprintf("title: %s", yamlScalar(*baseline.Title)))
	}

	maintainer := ptrOr(baseline.Maintainer, "")
	if opts != nil && opts.Metadata != nil && opts.Metadata.Maintainer != "" {
		maintainer = opts.Metadata.Maintainer
	}
	if maintainer != "" {
		lines = append(lines, fmt.Sprintf("maintainer: %s", yamlScalar(maintainer)))
	}

	copyright := ptrOr(baseline.Copyright, "")
	if opts != nil && opts.Metadata != nil && opts.Metadata.Copyright != "" {
		copyright = opts.Metadata.Copyright
	}
	if copyright != "" {
		lines = append(lines, fmt.Sprintf("copyright: %s", yamlScalar(copyright)))
	}

	license := ptrOr(baseline.License, "")
	if opts != nil && opts.Metadata != nil && opts.Metadata.License != "" {
		license = opts.Metadata.License
	}
	if license != "" {
		lines = append(lines, fmt.Sprintf("license: %s", yamlScalar(license)))
	}

	if baseline.Summary != nil {
		lines = append(lines, fmt.Sprintf("summary: %s", yamlScalar(*baseline.Summary)))
	}

	version := ptrOr(baseline.Version, "")
	if opts != nil && opts.Metadata != nil && opts.Metadata.Version != "" {
		version = opts.Metadata.Version
	}
	if version != "" {
		lines = append(lines, fmt.Sprintf("version: '%s'", version))
	}

	inspecVersion := ">=6.0"
	if opts != nil && opts.InSpecVersion != "" {
		inspecVersion = opts.InSpecVersion
	}
	lines = append(lines, fmt.Sprintf("inspec_version: '%s'", inspecVersion))

	// Supports
	if len(baseline.Supports) > 0 {
		lines = append(lines, "supports:")
		for _, s := range baseline.Supports {
			var entries []string
			if s.PlatformName != nil {
				entries = append(entries, fmt.Sprintf("platform-name: %s", yamlScalar(*s.PlatformName)))
			}
			if s.PlatformFamily != nil {
				entries = append(entries, fmt.Sprintf("platform-family: %s", yamlScalar(*s.PlatformFamily)))
			}
			if s.Platform != nil {
				entries = append(entries, fmt.Sprintf("platform: %s", yamlScalar(*s.Platform)))
			}
			if s.Release != nil {
				entries = append(entries, fmt.Sprintf("release: %s", yamlScalar(*s.Release)))
			}
			if len(entries) > 0 {
				lines = append(lines, fmt.Sprintf("- %s", entries[0]))
				for _, e := range entries[1:] {
					lines = append(lines, fmt.Sprintf("  %s", e))
				}
			}
		}
	}

	// Depends
	if len(baseline.Depends) > 0 {
		lines = append(lines, "depends:")
		for _, dep := range baseline.Depends {
			var entries []string
			if dep.Name != nil {
				entries = append(entries, fmt.Sprintf("name: %s", yamlScalar(*dep.Name)))
			}
			if dep.Git != nil {
				entries = append(entries, fmt.Sprintf("git: %s", yamlScalar(*dep.Git)))
			}
			if dep.URL != nil {
				entries = append(entries, fmt.Sprintf("url: %s", yamlScalar(*dep.URL)))
			}
			if dep.Path != nil {
				entries = append(entries, fmt.Sprintf("path: %s", yamlScalar(*dep.Path)))
			}
			if dep.Branch != nil {
				entries = append(entries, fmt.Sprintf("branch: %s", yamlScalar(*dep.Branch)))
			}
			if dep.Compliance != nil {
				entries = append(entries, fmt.Sprintf("compliance: %s", yamlScalar(*dep.Compliance)))
			}
			if dep.Supermarket != nil {
				entries = append(entries, fmt.Sprintf("supermarket: %s", yamlScalar(*dep.Supermarket)))
			}
			if len(entries) > 0 {
				lines = append(lines, fmt.Sprintf("- %s", entries[0]))
				for _, e := range entries[1:] {
					lines = append(lines, fmt.Sprintf("  %s", e))
				}
			}
		}
	}

	// Inputs
	if len(baseline.Inputs) > 0 {
		lines = append(lines, "inputs:")
		for _, input := range baseline.Inputs {
			val := ""
			if input.Value != nil {
				val = fmt.Sprintf("%v", input.Value)
			}
			lines = append(lines, fmt.Sprintf("- name: %s", yamlScalar(input.Name)))
			if val != "" {
				lines = append(lines, fmt.Sprintf("  value: %s", yamlScalar(val)))
			}
			if input.Description != nil {
				lines = append(lines, fmt.Sprintf("  description: %s", yamlScalar(*input.Description)))
			}
		}
	}

	lines = append(lines, "") // trailing newline
	return strings.Join(lines, "\n")
}

// GenerateInSpecProfile generates an in-memory InSpec profile from an HDF Baseline.
func GenerateInSpecProfile(baseline hdf.HDFBaseline, opts *GeneratorOptions) InSpecProfile {
	inspecYml := GenerateInSpecYml(baseline, opts)
	controls := make(map[string]string)

	if len(baseline.Requirements) == 0 {
		return InSpecProfile{InSpecYml: inspecYml, Controls: controls}
	}

	if opts != nil && opts.SingleFile {
		var stubs []string
		for _, req := range baseline.Requirements {
			stubs = append(stubs, GenerateControlStub(req))
		}
		controls["controls/controls.rb"] = strings.Join(stubs, "\n")
	} else {
		for _, req := range baseline.Requirements {
			// Sanitize ID for use as filename — strip path separators and
			// reject traversal attempts to prevent writing outside output dir.
			safeID := filepath.Base(strings.ReplaceAll(req.ID, "..", ""))
			if safeID == "." || safeID == "" {
				safeID = "unknown"
			}
			filename := fmt.Sprintf("controls/%s.rb", safeID)
			controls[filename] = GenerateControlStub(req)
		}
	}

	return InSpecProfile{InSpecYml: inspecYml, Controls: controls}
}

// ptrOr returns the dereferenced string pointer or the default value.
func ptrOr(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}

// yamlScalar wraps a string in single quotes if it contains characters that
// would break plain YAML scalars (colons, hashes, brackets, etc.). Strings
// that are safe as plain scalars are returned unquoted.
func yamlScalar(s string) string {
	// Characters that require quoting in a YAML plain scalar value.
	// Colon-space is the most common trigger (e.g., "address: foo").
	if strings.ContainsAny(s, ":#{}&*!|>'\"`@,[]{}") || strings.HasPrefix(s, "- ") {
		// Single-quote the value; escape embedded single quotes by doubling them.
		escaped := strings.ReplaceAll(s, "'", "''")
		return "'" + escaped + "'"
	}
	return s
}
