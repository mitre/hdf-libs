package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const siemProfileFormat = "x-hdf-siem-export-profile"

func siemEventFormat(target string) (string, error) {
	switch target {
	case "ecs", "ocsf":
		return target, nil
	case "splunk":
		return "x-splunk-export", nil
	default:
		return "", fmt.Errorf("unsupported SIEM target %q", target)
	}
}

func siemEvidencePackage(bundle *exportmap.ExportBundle, target string) ([]byte, error) {
	format, err := siemEventFormat(target)
	if err != nil {
		return nil, err
	}
	checksums := make([]*hdf.Checksum, 0, 3)
	for _, data := range [][]byte{bundle.Source, bundle.Events, bundle.Manifest} {
		digest, err := hdfengine.ChecksumHex("sha512", data)
		if err != nil {
			return nil, err
		}
		checksums = append(checksums, &hdf.Checksum{Algorithm: hdf.Sha512, Value: digest})
	}
	jsonType, ndjsonType := "application/json", "application/x-ndjson"
	pkg := hdf.HDFEvidencePackage{
		Name: "HDF SIEM export (" + target + ")",
		Contents: []hdf.ContentReference{
			{Type: hdf.HdfResults, URI: "source.json", Checksum: checksums[0]},
		},
		ExternalEvidence: []hdf.ExternalEvidenceReference{
			{URI: "events.ndjson", Format: format, MediaType: &ndjsonType, Checksum: checksums[1]},
			{URI: "manifest.json", Format: siemProfileFormat, MediaType: &jsonType, Checksum: checksums[2]},
		},
	}
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SIEM evidence package: %w", err)
	}
	return append(data, '\n'), nil
}

func siemArtifactPath(raw string) (string, error) {
	uri, err := url.Parse(raw)
	if err != nil || uri.IsAbs() || uri.Host != "" || strings.ContainsAny(raw, "?#") {
		return "", fmt.Errorf("expected a relative artifact URI without a query or fragment: %q", raw)
	}
	decoded, err := evidenceref.Decode(raw)
	if err != nil {
		return "", err
	}
	if !filepath.IsLocal(string(decoded)) || strings.ContainsAny(string(decoded), "\\:\x00") {
		return "", fmt.Errorf("expected a portable relative artifact path: %q", raw)
	}
	return filepath.Clean(string(decoded)), nil
}

func selectSIEMManifest(entries []hdfengine.EvidenceContent, selector string) (hdfengine.EvidenceContent, error) {
	selectedPath := ""
	if selector != "" {
		var err error
		selectedPath, err = siemArtifactPath(selector)
		if err != nil {
			return hdfengine.EvidenceContent{}, err
		}
	}
	matches := make([]hdfengine.EvidenceContent, 0, 1)
	for _, entry := range entries {
		if entry.Format != siemProfileFormat {
			continue
		}
		if selectedPath != "" {
			path, err := siemArtifactPath(entry.URI)
			if err != nil || path != selectedPath {
				continue
			}
		}
		matches = append(matches, entry)
	}
	if len(matches) != 1 {
		return hdfengine.EvidenceContent{}, fmt.Errorf("missing or ambiguous SIEM profile; --manifest must select one registered profile")
	}
	path, err := siemArtifactPath(matches[0].URI)
	if err != nil {
		return hdfengine.EvidenceContent{}, err
	}
	return findSIEMEntry(entries, path, "", siemProfileFormat)
}

func findSIEMEntry(entries []hdfengine.EvidenceContent, path, contentType, format string) (hdfengine.EvidenceContent, error) {
	matches := make([]hdfengine.EvidenceContent, 0, 1)
	for _, entry := range entries {
		candidate, err := siemArtifactPath(entry.URI)
		if err == nil && candidate == path {
			matches = append(matches, entry)
		}
	}
	if len(matches) != 1 {
		return hdfengine.EvidenceContent{}, fmt.Errorf("missing or ambiguous package artifact %q", path)
	}
	entry := matches[0]
	if entry.Type != contentType || entry.Format != format {
		return hdfengine.EvidenceContent{}, fmt.Errorf("wrong type or format for package artifact %q", path)
	}
	return entry, nil
}

func verifySIEMEntry(entry hdfengine.EvidenceContent, fetch hdfengine.FetchFunc) ([]byte, error) {
	if entry.ChecksumAlgorithm != "sha512" || entry.Checksum == "" {
		return nil, fmt.Errorf("artifact %q requires an explicit SHA512 checksum", entry.URI)
	}
	var data []byte
	results := hdfengine.VerifyChecksums([]hdfengine.EvidenceContent{entry}, func(uri string) ([]byte, error) {
		var err error
		data, err = fetch(uri)
		return data, err
	})
	result := results[0]
	if result.Status != hdfengine.ChecksumMatch {
		return nil, fmt.Errorf("verify artifact %q: %s %s", entry.URI, result.Status, result.Error)
	}
	return data, nil
}
