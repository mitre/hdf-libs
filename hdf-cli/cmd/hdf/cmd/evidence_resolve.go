package cmd

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/spf13/cobra"
)

func newEvidenceResolveCmd() *cobra.Command {
	var eventPath, manifestURI string
	cmd := &cobra.Command{
		Use:   "resolve <package.json> --event event.json",
		Short: "Verify a packaged SIEM finding and recover its original HDF source",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if eventPath == "" {
				return fmt.Errorf("--event is required: name one retained SIEM event")
			}
			data, _, err := readInputFileAndRaw(args[0])
			if err != nil {
				return err
			}
			event, err := readFromFile(eventPath, false)
			if err != nil {
				return err
			}
			resolved, err := resolveSIEMPackage(args[0], data, event, manifestURI)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(resolved.Source)
			return err
		},
	}
	cmd.Flags().StringVar(&eventPath, "event", "", "One retained event in the exporter's event shape (required)")
	cmd.Flags().StringVar(&manifestURI, "manifest", "", "Registered package-relative profile URI; required when several exports are present")
	return cmd
}

func resolveSIEMPackage(packagePath string, data, event []byte, selector string) (*exportmap.ResolvedExportSource, error) {
	validation := validators.ValidateEvidencePackage(data)
	if !validation.Valid {
		return nil, fmt.Errorf("invalid evidence package: %s", validation.Error())
	}
	_, entries, err := hdfengine.ParseEvidencePackage(data)
	if err != nil {
		return nil, err
	}
	external, err := hdfengine.ParseExternalEvidence(data)
	if err != nil {
		return nil, err
	}
	entries = append(entries, external...)
	selected, err := selectSIEMManifest(entries, selector)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(packagePath)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open package directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	fetch := func(uri string) ([]byte, error) {
		path, pathErr := siemArtifactPath(uri)
		if pathErr != nil {
			return nil, pathErr
		}
		if linkErr := refuseSymlinkIfConfigured(filepath.Join(dir, path)); linkErr != nil {
			return nil, linkErr
		}
		file, openErr := root.Open(path)
		if openErr != nil {
			return nil, fmt.Errorf("read contained artifact %q: %w", uri, openErr)
		}
		defer func() { _ = file.Close() }()
		return readOpenedFile(file, uri, true)
	}
	manifest, err := verifySIEMEntry(selected, fetch)
	if err != nil {
		return nil, err
	}
	var profile struct {
		Target    string                  `json:"target"`
		Events    string                  `json:"events"`
		Artifacts []hdf.ExternalReference `json:"artifacts"`
	}
	// Match the library's exact keys and last-value-wins duplicate-name policy.
	if err = json.Unmarshal(manifest, &profile, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, fmt.Errorf("decode SIEM profile: %w", err)
	}
	format, err := siemEventFormat(profile.Target)
	if err != nil {
		return nil, err
	}
	if profile.Events != "events.ndjson" || len(profile.Artifacts) == 0 {
		return nil, fmt.Errorf("invalid SIEM profile inventory")
	}
	manifestPath, err := siemArtifactPath(selected.URI)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(manifestPath)
	events, err := findSIEMEntry(entries, filepath.Join(base, profile.Events), "", format)
	if err != nil {
		return nil, err
	}
	if _, err = verifySIEMEntry(events, fetch); err != nil {
		return nil, err
	}
	artifacts := make([]exportmap.BundleArtifact, 0, len(profile.Artifacts))
	for _, artifact := range profile.Artifacts {
		if artifact.Href == nil {
			return nil, fmt.Errorf("missing source artifact location")
		}
		path, pathErr := siemArtifactPath(*artifact.Href)
		if pathErr != nil {
			return nil, pathErr
		}
		source, findErr := findSIEMEntry(entries, filepath.Join(base, path), "hdf-results", "")
		if findErr != nil {
			return nil, findErr
		}
		if artifact.Checksum == nil || string(artifact.Checksum.Algorithm) != source.ChecksumAlgorithm || artifact.Checksum.Value != source.Checksum {
			return nil, fmt.Errorf("package and manifest source checksums disagree")
		}
		retained, readErr := verifySIEMEntry(source, fetch)
		if readErr != nil {
			return nil, readErr
		}
		artifacts = append(artifacts, exportmap.BundleArtifact{Href: *artifact.Href, Bytes: retained})
	}
	return exportmap.ResolveExportEvent(event, manifest, artifacts)
}
