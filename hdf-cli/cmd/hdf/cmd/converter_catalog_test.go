package cmd

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// updateCatalog rewrites the committed converter manifest instead of asserting
// against it. Run after adding or removing a converter:
//
//	go test ./cmd/hdf/cmd -run TestConverterCatalogManifest -update-catalog
var updateCatalog = flag.Bool("update-catalog", false, "rewrite site/data/converters.json from the live registry")

// catalogEntry is one registered source→dest conversion, with the metadata the
// docs catalog page renders.
type catalogEntry struct {
	Source       string `json:"source"`
	Dest         string `json:"dest"`
	Name         string `json:"name"`
	AcceptsEmpty bool   `json:"acceptsEmpty"`
}

// catalogManifest is the serialized shape of site/data/converters.json. It also
// carries the BOM inventory formats that flow through `hdf system create` (into
// an HDF System doc, not Results) so the catalog page can point SPDX/AIBOM users
// at the right command instead of leaving them to conclude those are unsupported.
type catalogManifest struct {
	Converters       []catalogEntry `json:"converters"`
	SystemBomFormats []string       `json:"systemBomFormats"`
}

// catalogManifestPath resolves the committed manifest relative to this package
// (go test runs with the package dir as its working directory).
func catalogManifestPath() string {
	return filepath.Join("..", "..", "..", "..", "site", "data", "converters.json")
}

// buildCatalog snapshots the live converter registry and the system-BOM import
// formats into the manifest shape.
func buildCatalog(t *testing.T) catalogManifest {
	t.Helper()
	pairs := ListConverters()
	entries := make([]catalogEntry, 0, len(pairs))
	for _, p := range pairs {
		conv, err := GetConverter(p.Source, p.Dest)
		if err != nil {
			t.Fatalf("registered pair %s→%s has no retrievable converter: %v", p.Source, p.Dest, err)
		}
		e := catalogEntry{Source: p.Source, Dest: p.Dest, Name: conv.Name()}
		if ae, ok := conv.(EmptyInputAccepting); ok {
			e.AcceptsEmpty = ae.AcceptsEmptyInput()
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Dest < entries[j].Dest
	})

	bomFormats := append([]string(nil), bomFormatAliases...)
	sort.Strings(bomFormats)

	return catalogManifest{Converters: entries, SystemBomFormats: bomFormats}
}

// TestConverterCatalogManifest keeps site/data/converters.json — the source the
// docs site renders the converter catalog page from — in lockstep with the live
// registry. Adding or removing a converter fails this test until the manifest is
// regenerated (-update-catalog), so the published catalog can never silently
// drift from what the CLI actually supports.
func TestConverterCatalogManifest(t *testing.T) {
	manifest := buildCatalog(t)
	got, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	got = append(got, '\n')

	path := catalogManifestPath()
	if *updateCatalog {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		t.Logf("wrote %d converters + %d system BOM formats to %s", len(manifest.Converters), len(manifest.SystemBomFormats), path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest (%s): %v\nregenerate with: go test ./cmd/hdf/cmd -run TestConverterCatalogManifest -update-catalog", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("converter catalog manifest is stale — the registry and site/data/converters.json disagree.\n" +
			"regenerate with: go test ./cmd/hdf/cmd -run TestConverterCatalogManifest -update-catalog")
	}
}
