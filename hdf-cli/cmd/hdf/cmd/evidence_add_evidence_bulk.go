package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
)

type evidenceSelection struct {
	value     string
	directory bool
}

func expandEvidenceInputs(pkg string, opts addEvidenceOpts) (addEvidenceOpts, error) {
	if opts.recursive && len(opts.directories) == 0 {
		return opts, fmt.Errorf("--recursive requires --from-dir")
	}
	if len(opts.files)+len(opts.directories) == 0 {
		return opts, nil
	}
	if opts.checksum != "" {
		return opts, fmt.Errorf("--checksum cannot be used with local selectors; selected files are hashed independently")
	}
	groups := len(opts.uris) + len(opts.files) + len(opts.directories)
	if n := len(opts.formats); n != 0 && n != 1 && n != groups {
		return opts, fmt.Errorf("give one --format for all selectors or %d formats in --uri, --file, --from-dir order; got %d", groups, n)
	}
	formatAt := func(i int) string {
		if len(opts.formats) == 0 {
			return ""
		}
		if len(opts.formats) == 1 {
			return opts.formats[0]
		}
		return opts.formats[i]
	}
	// Keep original URI semantics; only the explicitly local selectors are expanded.
	uris := append([]string(nil), opts.uris...)
	var formats []string
	for i := range opts.uris {
		if len(opts.formats) > 0 {
			formats = append(formats, formatAt(i))
		}
	}
	selectors := make([]evidenceSelection, 0, len(opts.files)+len(opts.directories))
	for _, v := range opts.files {
		selectors = append(selectors, evidenceSelection{value: v})
	}
	for _, v := range opts.directories {
		selectors = append(selectors, evidenceSelection{value: v, directory: true})
	}
	excluded := make(map[string]os.FileInfo)
	for _, v := range []string{pkg, opts.outputPath} {
		if v != "" {
			p, err := filepath.Abs(v)
			if err != nil {
				return opts, err
			}
			info, statErr := os.Stat(p)
			if statErr != nil && !os.IsNotExist(statErr) {
				return opts, fmt.Errorf("inspect package/output %q: %w", p, statErr)
			}
			excluded[p] = info
		}
	}
	// The same directory the per-uri loop normalizes against; a reference is
	// package-relative by contract, so containment is measured from here.
	pkgDir := filepath.Dir(pkg)
	seen := make(map[string]string)
	for i, s := range selectors {
		if strings.TrimSpace(s.value) == "" {
			return opts, fmt.Errorf("local selector %d is blank", i+1)
		}
		format := formatAt(len(opts.uris) + i)
		paths, err := evidenceSelectionPaths(s, opts.recursive)
		if err != nil {
			return opts, err
		}
		discovered := s.directory || containsGlobChars(s.value)
		selected := 0
		for _, path := range paths {
			abs, err := filepath.Abs(path)
			if err != nil {
				return opts, err
			}
			if isExcludedEvidenceFile(abs, excluded) {
				if discovered {
					continue
				}
				return opts, fmt.Errorf("cannot add the package or output itself as evidence: %q", path)
			}
			if err := checkEvidenceSelectionFile(abs); err != nil {
				return opts, err
			}
			selected++
			if previous, exists := seen[abs]; exists && discovered {
				if previous != format {
					return opts, fmt.Errorf("%q is selected with conflicting formats %q and %q", path, previous, format)
				}
				continue
			}
			seen[abs] = format
			// A discovered name is a filesystem path, not a reference, but every consumer
			// of opts.uris Decodes a uri as an already-encoded reference, so recording the
			// raw path attested a%2Fb.json as a/b.json. It takes the two steps
			// packageRelativeIfInside takes for an in-package --uri instead: confine,
			// then Encode per segment.
			rel, inside := packageSubtreeRef(pkgDir, evidenceref.Decoded(abs))
			if !inside {
				// Shown absolute: run from inside the package, pkgDir is "." and
				// names nothing.
				shown := pkgDir
				if absDir, absErr := filepath.Abs(pkgDir); absErr == nil {
					shown = absDir
				}
				return opts, fmt.Errorf("selected evidence %q is outside the package's directory %q; "+
					"discovery records package-relative references, so use --uri to reference an "+
					"external artifact deliberately", path, shown)
			}
			uris = append(uris, evidenceref.Encode(string(rel)))
			if len(opts.formats) > 0 {
				formats = append(formats, format)
			}
		}
		if selected == 0 {
			return opts, &exitCodeError{code: exitNothingToDo, message: fmt.Sprintf("no files selected by %q after excluding the package and output", s.value), report: true}
		}
	}
	opts.uris = uris
	opts.formats = formats
	return opts, nil
}

func isExcludedEvidenceFile(path string, excluded map[string]os.FileInfo) bool {
	if _, ok := excluded[path]; ok {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	for _, other := range excluded {
		if other != nil && os.SameFile(info, other) {
			return true
		}
	}
	return false
}

func evidenceSelectionPaths(s evidenceSelection, recursive bool) ([]string, error) {
	if !s.directory {
		return expandGlobs([]string{s.value})
	}
	info, err := os.Lstat(s.value)
	if err != nil {
		return nil, fmt.Errorf("read evidence directory %q: %w", s.value, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a directory (symlinks are not followed)", s.value)
	}
	var paths []string
	err = filepath.WalkDir(s.value, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != s.value && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read evidence directory %q: %w", s.value, err)
	}
	return paths, nil
}

func checkEvidenceSelectionFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read selected evidence %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("selected evidence %q is a symlink; select a regular file directly", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("selected evidence %q is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read selected evidence %q: %w", path, err)
	}
	return f.Close()
}
