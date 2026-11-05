package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/evidenceref"
)

type evidenceSelection struct {
	value     string
	directory bool
}

type seenSelection struct {
	format  string
	literal bool
}

func expandEvidenceInputs(pkg string, opts addEvidenceOpts) (addEvidenceOpts, error) {
	if opts.recursive && len(opts.directories) == 0 {
		return opts, fmt.Errorf("--recursive requires --from-dir")
	}
	// The one --format count rule, for every invocation: one value for all selectors,
	// or one per selector. A per-entry list is built below only for the latter; the
	// former is left for resolveEvidenceFormats to broadcast or infer.
	groups := len(opts.uris) + len(opts.files) + len(opts.directories)
	if n := len(opts.formats); groups > 0 && n != 0 && n != 1 && n != groups {
		return opts, fmt.Errorf("give one --format for all selectors or %d formats in --uri, --file, --from-dir order; got %d", groups, n)
	}
	perSelector := len(opts.formats) == groups && groups > 0
	if len(opts.files)+len(opts.directories) == 0 {
		return opts, nil
	}
	if opts.checksum != "" {
		return opts, fmt.Errorf("--checksum cannot be used with local selectors; selected files are hashed independently")
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
		if perSelector {
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
	// The same directory the per-uri loop normalizes against; a reference is
	// package-relative by contract, so containment is measured from here.
	pkgDir := filepath.Dir(pkg)
	// Keyed on the absolute path so a repeat is recognized however it was reached;
	// a repeat is a slip only when BOTH namings were literal.
	seen := make(map[string]seenSelection)
	var skipped []skippedKind
	hidden := 0
	for i, s := range selectors {
		if strings.TrimSpace(s.value) == "" {
			return opts, fmt.Errorf("local selector %d is blank", i+1)
		}
		format := formatAt(len(opts.uris) + i)
		paths, hiddenHere, err := evidenceSelectionPaths(s, opts.recursive)
		if err != nil {
			return opts, err
		}
		hidden += hiddenHere
		discovered := s.directory || containsGlobChars(s.value)
		selected := 0
		for _, path := range paths {
			abs, err := filepath.Abs(path)
			if err != nil {
				return opts, err
			}
			// One Lstat, its FileInfo handed to both checks. Kind first, so a symlink
			// is reported as a symlink rather than dropped silently as excluded.
			info, err := os.Lstat(abs)
			if err != nil {
				return opts, fmt.Errorf("read selected evidence %q: %w", path, err)
			}
			if !info.Mode().IsRegular() {
				kind := nonRegularKind(info.Mode())
				if discovered {
					skipped = append(skipped, skippedKind{path: abs, kind: kind, mode: info.Mode()})
					continue
				}
				return opts, fmt.Errorf("selected evidence %q is %s; select a regular file directly", path, kind)
			}
			// The same predicate bundle uses for -o, so a hard link or alias of the
			// package is the package; a discovered one is passed over, a named one refused.
			if samePath(abs, pkg) || (opts.outputPath != "" && samePath(abs, opts.outputPath)) {
				if discovered {
					continue
				}
				return opts, fmt.Errorf("cannot add the package or output itself as evidence: %q", path)
			}
			selected++
			if previous, exists := seen[abs]; exists {
				if previous.format != format {
					return opts, fmt.Errorf("%q is selected with conflicting formats %q and %q", path, previous.format, format)
				}
				if previous.literal && !discovered {
					return opts, fmt.Errorf("%q is selected twice by --file; name it once", path)
				}
				continue
			}
			seen[abs] = seenSelection{format: format, literal: !discovered}
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
			if perSelector {
				formats = append(formats, format)
			}
		}
		if selected == 0 {
			// Say what was skipped BEFORE saying nothing was selected, or a selector whose
			// only entry was a symlink reads as if it matched nothing at all.
			reportSkippedSelections(pkgDir, skipped, hidden)
			return opts, &exitCodeError{code: exitNothingToDo, message: fmt.Sprintf("no files selected by %q after excluding the package and output", s.value), report: true}
		}
	}
	reportSkippedSelections(pkgDir, skipped, hidden)
	opts.uris = uris
	if perSelector {
		opts.formats = formats
	}
	return opts, nil
}

// reportSkippedSelections prints each entry discovery passed over by kind, so nothing
// is dropped in silence — the same shape evidence build gives its irregular entries,
// shown under the package directory the way the recorded references are.
func reportSkippedSelections(pkgDir string, skipped []skippedKind, hidden int) {
	if hidden > 0 {
		fmt.Fprintf(os.Stderr, "Skipped %d hidden entries; name one with --file to select it.\n", hidden)
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].path < skipped[j].path })
	for _, l := range skipped {
		advice := ""
		if l.mode&os.ModeSymlink != 0 {
			advice = " Name its target explicitly if it belongs in the package."
		}
		fmt.Fprintf(os.Stderr, "Skipped %s: %s.%s\n", displayUnderBase(pkgDir, l.path), l.kind, advice)
	}
}

// evidenceSelectionPaths lists what a selector names, and how many hidden entries
// discovery passed over. A literal --file is never filtered: the operator named it.
func evidenceSelectionPaths(s evidenceSelection, recursive bool) (paths []string, hidden int, err error) {
	if !s.directory {
		matched, err := expandGlobs([]string{s.value})
		if err != nil || !containsGlobChars(s.value) {
			return matched, 0, err
		}
		for _, m := range matched {
			if hiddenName(filepath.Base(m)) {
				hidden++
				continue
			}
			paths = append(paths, m)
		}
		return paths, hidden, nil
	}
	// The root is resolved and walked as scanEvidenceDir walks evidence build's
	// --from-dir, so every spelling of it is decided on the same resolved form.
	base, err := resolvedAbs(s.value)
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence directory %q: %w", s.value, err)
	}
	if info, statErr := os.Stat(base); statErr != nil {
		return nil, 0, fmt.Errorf("read evidence directory %q: %w", s.value, statErr)
	} else if !info.IsDir() {
		return nil, 0, fmt.Errorf("%q is not a directory", s.value)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence directory %q: %w", s.value, err)
	}
	defer func() { _ = root.Close() }()
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if rel == "." {
			return nil
		}
		if hiddenName(entry.Name()) {
			hidden++
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// A subdirectory met without --recursive is returned as a path so the caller
		// classifies and reports it exactly as it does a glob match on a directory.
		if entry.IsDir() && !recursive {
			paths = append(paths, filepath.Join(base, rel))
			return fs.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		paths = append(paths, filepath.Join(base, rel))
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("read evidence directory %q: %w", s.value, err)
	}
	return paths, hidden, nil
}
