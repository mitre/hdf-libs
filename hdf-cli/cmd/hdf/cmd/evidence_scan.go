package cmd

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"

	bom "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/bom"
)

// scanResult is what a directory scan found, already routed. Paths are absolute.
type scanResult struct {
	systems     []string // >1 is an error; the caller names them all
	results     []string
	baselines   []string
	plans       []string
	amendments  []string
	comparisons []string
	boms        []string
	unsupported []string // detected HDF, but no Content_Type exists for it
	foreign     []string // not an HDF document at all
	unreadable  []string // present but could not be read — reported, never dropped silently
	symlinks    []string // skipped by type; reported, because "nothing is dropped in silence"
}

// skipUnreadable records an entry the scan could not read and continues the walk.
// A per-entry failure must not abort the scan, but it must not vanish either — the
// error is consumed here deliberately, and the path is reported at the end.
func (out *scanResult) skipUnreadable(path string, _ error) error {
	out.unreadable = append(out.unreadable, path)
	return nil
}

// looksLikeBOM reports whether a document carries a BOM's own discriminator.
//
// This MUST precede hdfengine.Detect, which falls to `components` after five
// more specific keys — CycloneDX's primary field, so a blind Detect files real
// SBOMs as HDF systems and validates them against the wrong schema.
func looksLikeBOM(data []byte) bool {
	var doc any
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	// IsBOMDocument, not DetectFormat: DetectFormat answers which format can be
	// NORMALIZED, so it declines a plain SPDX-3 software profile. This command
	// records a reference and never parses, so the wider question is the right
	// one — and a BOM it declines falls through to HDF detection, where a root
	// components key becomes a system document.
	return bom.IsBOMDocument(doc)
}

// routeDetected returns the scanResult field a detected type belongs to, and
// whether the Content_Type enum has a value for it at all. Two detected types
// have none: a requirement-change-event, and an evidence package itself — which
// is exactly what re-scanning a directory finds from the previous run.
func routeDetected(out *scanResult, detected, path string) {
	switch detected {
	case string(validators.TypeResults):
		out.results = append(out.results, path)
	case string(validators.TypeBaseline):
		out.baselines = append(out.baselines, path)
	case string(validators.TypeSystem):
		out.systems = append(out.systems, path)
	case string(validators.TypePlan):
		out.plans = append(out.plans, path)
	case string(validators.TypeAmendments):
		out.amendments = append(out.amendments, path)
	case string(validators.TypeComparison):
		out.comparisons = append(out.comparisons, path)
	default:
		out.unsupported = append(out.unsupported, fmt.Sprintf("%s (%s)", path, detected))
	}
}

// explicitSkips holds the documents named on the command line, identified by
// FILESYSTEM IDENTITY rather than path string: a hard link, or the same name in
// another letter-case on a case-insensitive volume, is one inode under two
// strings. Lower-casing the key instead would collapse two genuinely distinct
// files on a case-sensitive volume.
type explicitSkips struct {
	infos []os.FileInfo
}

// add records a path to skip. A path that cannot be stat'd is not recorded: it
// names nothing the walk can encounter, and the command reports a bad explicit
// path through its own reading of it rather than here.
func (e *explicitSkips) add(path string) {
	if fi, err := os.Stat(path); err == nil {
		e.infos = append(e.infos, fi)
	}
}

// has reports whether info is one of the recorded files. Linear over the explicit
// paths — one per file NAMED, which a glob makes more than one per flag, since
// the globs are expanded before the skip-set is built.
func (e *explicitSkips) has(info os.FileInfo) bool {
	for _, known := range e.infos {
		if os.SameFile(known, info) {
			return true
		}
	}
	return false
}

// scanEvidenceDir walks baseDir and routes every regular file by its CONTENT.
//
// Recursion is deliberate: the base directory is the artifacts folder a CI
// orchestrator hands from job to job, and those permit subdirectories.
//
// Two files with identical bytes under different names are BOTH listed —
// de-duplicating would drop a document the operator put in the tree, and
// contents[] has no uniqueness constraint. Confinement is os.Root's, so a
// symlink out of the tree is refused by the kernel rather than by a path
// comparison a rename could race. skip holds the explicitly-named documents.
func scanEvidenceDir(baseDir string, skip *explicitSkips) (*scanResult, error) {
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open --from-dir %s: %w", baseDir, err)
	}
	defer func() { _ = root.Close() }()

	// resolvedAbs, not EvalSymlinks: EvalSymlinks does NOT absolutize, so
	// `--from-dir .` would yield relative paths. The skip-set no longer depends on
	// this — it compares filesystem identity — but every recorded and displayed
	// path still does.
	realBase, err := resolvedAbs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve --from-dir %s: %w", baseDir, err)
	}

	out := &scanResult{}
	walkErr := fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// A directory we cannot list is reported, not passed over in silence.
			return out.skipUnreadable(filepath.Join(realBase, rel), walkErr)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			// A symlink is skipped by type: os.Root refuses an escaping one anyway,
			// and following an in-tree one would list the same bytes twice under two
			// names. Recorded so the skip is visible rather than silent.
			out.symlinks = append(out.symlinks, filepath.Join(realBase, rel))
			return nil
		}
		abs := filepath.Join(realBase, rel)
		// d.Info() rather than a second os.Stat. io/fs permits an implementation to
		// stat lazily here, so this is not a guarantee the interface makes; under
		// os.Root the entry's info was read eagerly with the directory, which is
		// what makes it the identity already seen rather than a fresh look.
		info, infoErr := d.Info()
		if infoErr != nil {
			return out.skipUnreadable(abs, infoErr)
		}
		if skip.has(info) {
			return nil
		}
		data, readErr := fs.ReadFile(root.FS(), rel)
		if readErr != nil {
			return out.skipUnreadable(abs, readErr)
		}
		if looksLikeBOM(data) {
			out.boms = append(out.boms, abs)
			return nil
		}
		if detected := hdfengine.Detect(data); detected != "" {
			routeDetected(out, detected, abs)
		} else {
			out.foreign = append(out.foreign, abs)
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("failed to scan %s: %w", baseDir, walkErr)
	}

	// Stable order, so a package built twice from one directory is identical.
	for _, s := range [][]string{out.systems, out.results, out.baselines, out.plans,
		out.amendments, out.comparisons, out.boms, out.unsupported, out.foreign,
		out.unreadable, out.symlinks} {
		sort.Strings(s)
	}
	return out, nil
}

// displayUnderBase renders a path relative to the scanned directory when it sits
// beneath it, so one stderr stream uses one path convention. Absolute paths are
// kept internally; this shortens only what is PRINTED. What a package records is
// shortened separately, by packageRelativeRef.
func displayUnderBase(baseDir, p string) string {
	base, err := resolvedAbs(baseDir)
	if err != nil {
		return p
	}
	// The path as given first, absolutized but NOT symlink-resolved: a skipped
	// symlink must display under its OWN name, because the message tells the
	// operator to name its target instead — resolving here would print the target
	// and make that advice nonsense.
	if abs, absErr := filepath.Abs(p); absErr == nil {
		if rel, relErr := filepath.Rel(base, abs); relErr == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	// Then the resolved form, for a caller handing us the spelling the operator
	// typed while the base is symlink-resolved (on macOS /tmp resolves to
	// /private/tmp, which alone makes Rel escape with "..").
	if abs, absErr := resolvedAbs(p); absErr == nil {
		if rel, relErr := filepath.Rel(base, abs); relErr == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return p
}

// reportScan tells the operator what the scan could not place. Nothing is dropped
// in silence: a foreign artifact gets the exact command that would include it,
// because inventing a format for it would be fabrication.
//
// Paths are absolute internally, but are DISPLAYED relative to the scanned
// directory, and the suggested --uri is relative too, so the printed command can
// be pasted as-is.
func reportScan(out *scanResult, baseDir, pkgPath string) {
	target := pkgPath
	if target == "" {
		target = "<package>"
	}
	show := func(p string) string { return displayUnderBase(baseDir, p) }
	for _, u := range out.unsupported {
		// carries a " (type)" suffix; keep it while shortening the path
		path, suffix := u, ""
		if i := strings.LastIndex(u, " ("); i > 0 {
			path, suffix = u[:i], u[i:]
		}
		fmt.Fprintf(os.Stderr, "Skipped %s%s: an evidence package's contents[] has no type for it.\n",
			show(path), suffix)
	}
	for _, u := range out.unreadable {
		fmt.Fprintf(os.Stderr, "Skipped %s: present but could not be read.\n", show(u))
	}
	for _, l := range out.symlinks {
		fmt.Fprintf(os.Stderr, "Skipped %s: a symlink. Name its target explicitly if it belongs in the package.\n", show(l))
	}
	for _, f := range out.foreign {
		fmt.Fprintf(os.Stderr, "Skipped %s: not an HDF document. To carry it as external evidence:\n"+
			"  hdf evidence add-evidence %s --uri %s --format <format>\n", show(f), target, show(f))
	}
}
