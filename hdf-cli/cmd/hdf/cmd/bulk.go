package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// BulkResult holds the outcome of processing a single file in a multi-file operation.
type BulkResult struct {
	File    string      `json:"file"`
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Output  interface{} `json:"output,omitempty"`

	// detail is the inner command's own captured output for a failed file, kept
	// only when withFailureDetail is in effect. Unexported so it never reaches
	// the --json array: that shape is a published contract and this is a
	// human-readable rendering, not a new field.
	detail string
}

// BulkProcessFn processes a single file and returns an error if it fails.
type BulkProcessFn func(file string) error

// runBulk processes multiple files with the given function.
// By default, continues processing all files and reports failures at the end (POSIX convention).
// With -F/--fail-fast, aborts on first failure.
// bulkOption configures one runBulk call. Variadic so the five callers that want
// the default shape stay untouched — changing bulk output for convert, list,
// query, validate and add-component to fix a threshold-reporting gap would be a
// rider on five unrelated commands.
type bulkOption func(*bulkConfig)

type bulkConfig struct{ failureDetail bool }

// withFailureDetail prints the inner command's OWN captured output under a failed
// file, instead of collapsing it to the first line of its error. Use it where the
// inner command already renders a self-contained per-file verdict worth keeping:
// `validate threshold` names the document and lists the requirements that
// breached each bound, and discarding that made the same command answer the same
// question differently depending on how many files were passed.
func withFailureDetail() bulkOption {
	return func(c *bulkConfig) { c.failureDetail = true }
}

func runBulk(files []string, verb, successVerb string, processFn BulkProcessFn, opts ...bulkOption) error {
	cfg := bulkConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	var results []BulkResult

	for _, file := range files {
		result := BulkResult{File: file, Success: true}

		// In bulk mode, capture all output from the inner function.
		// On success: print captured stdout. On failure: print a short error.
		fidelityNote = ""
		captured, fnErr := captureOutput(func() error {
			return processFn(file)
		})
		note := takeFidelityNote()
		if fnErr != nil {
			result.Success = false
			result.Error = firstLine(fnErr.Error())
			if cfg.failureDetail {
				result.detail = captured.stderr
			}
		}

		switch {
		case jsonOutput && result.Success:
			var parsed interface{}
			if json.Unmarshal([]byte(captured.stdout), &parsed) == nil {
				result.Output = parsed
			}
		case jsonOutput:
			// JSON failure: error is captured in result.Error for the array output.
		case result.Success:
			fmt.Fprintf(os.Stderr, "%s: ok%s\n", file, note)
		case cfg.failureDetail && strings.TrimSpace(result.detail) != "":
			// The inner verdict already names the file and says why, so reprinting
			// "file: error" above it would say it twice in two vocabularies. The
			// note still rides along, for the same reason it does below.
			fmt.Fprint(os.Stderr, withNoteOnVerdictLine(result.detail, note))
		default:
			// The note rides the failure line too. A note explains the verdict at
			// least as often when the file failed — a threshold divergence is most
			// worth saying when it is why the gate flipped — and printing it only
			// on success hid it in exactly that case.
			fmt.Fprintf(os.Stderr, "%s: error%s\n", file, note)
		}

		results = append(results, result)

		// With --fail-fast, abort on first failure.
		if !result.Success && failFast {
			if jsonOutput {
				printBulkJSON(results)
			}
			return fmt.Errorf("%s", result.Error)
		}
	}

	if jsonOutput {
		printBulkJSON(results)
	} else {
		printBulkSummary(results, successVerb)
		// Under failureDetail a file that rendered its own verdict has already
		// said everything; reprinting a collapsed line would say it twice. But a
		// file that failed BEFORE reaching a verdict — unreadable, not HDF,
		// schema-invalid — has no detail, and suppressing its error too would
		// leave the log naming the file without saying why. That is the very
		// defect the detail option exists to cure, so it must not be reintroduced
		// one class of failure to the left.
		printBulkErrors(withoutDetail(results))
	}

	if bulkHasFailure(results) {
		return fmt.Errorf("%s", verb)
	}
	return nil
}

// expandGlobs expands glob patterns in the argument list and returns
// a list of file paths. Glob expansions are deduplicated (same file
// matched by multiple patterns appears once), but literal paths are
// always kept — passing the same file twice explicitly is intentional.
func expandGlobs(args []string) ([]string, error) {
	seen := make(map[string]bool)
	var result []string

	for _, arg := range args {
		if containsGlobChars(arg) {
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid glob pattern %q: %w", arg, err)
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("no files matched pattern %q", arg)
			}
			sort.Strings(matches)
			for _, m := range matches {
				abs, _ := filepath.Abs(m)
				if !seen[abs] {
					seen[abs] = true
					result = append(result, m)
				}
			}
		} else {
			result = append(result, arg)
		}
	}

	return result, nil
}

// containsGlobChars returns true if s contains *, ?, or [...].
func containsGlobChars(s string) bool {
	for _, c := range s {
		if c == '*' || c == '?' || c == '[' {
			return true
		}
	}
	return false
}

// bulkSummaryCounts returns (passed, failed) counts from a slice of BulkResults.
func bulkSummaryCounts(results []BulkResult) (int, int) {
	passed, failed := 0, 0
	for _, r := range results {
		if r.Success {
			passed++
		} else {
			failed++
		}
	}
	return passed, failed
}

// printBulkSummary prints a human-readable summary line for bulk operations.
// The successVerb is used to describe successful files (e.g., "converted", "validated").
func printBulkSummary(results []BulkResult, successVerb string) {
	passed, failed := bulkSummaryCounts(results)
	total := len(results)
	fmt.Println()
	if failed == 0 {
		fmt.Printf("Results: %d/%d %s\n", passed, total, successVerb)
	} else {
		fmt.Printf("Results: %d/%d %s, %d failed\n", passed, total, successVerb, failed)
	}
}

// withNoteOnVerdictLine attaches a fidelity note to the captured block's VERDICT
// line — the one carrying the ✗ and the file name. Neither end of the block works:
// the last line of a threshold verdict is a FINDING, so the note read as though it
// described that one requirement, and the first line is the agent-override count.
// Falls back to appending when no verdict line is found, so a caller that renders
// a different shape still sees the note rather than losing it.
func withNoteOnVerdictLine(detail, note string) string {
	if note == "" {
		return detail
	}
	lines := strings.Split(detail, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "✗ ") {
			lines[i] = line + note
			return strings.Join(lines, "\n")
		}
	}
	return strings.TrimRight(detail, "\n") + note + "\n"
}

// withoutDetail selects the failed results that rendered no verdict of their own,
// so their collapsed error line is still printed. A caller that did not ask for
// failure detail has no details at all, so every failure survives this filter.
func withoutDetail(results []BulkResult) []BulkResult {
	kept := make([]BulkResult, 0, len(results))
	for _, r := range results {
		if strings.TrimSpace(r.detail) == "" {
			kept = append(kept, r)
		}
	}
	return kept
}

// printBulkErrors prints the full error message for each failed file.
func printBulkErrors(results []BulkResult) {
	for _, r := range results {
		if !r.Success {
			fmt.Fprintf(os.Stderr, "\n%s:\n  %s\n", r.File, r.Error)
		}
	}
}

// printBulkJSON prints bulk results as a JSON array.
func printBulkJSON(results []BulkResult) {
	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))
}

// capturedOutput holds captured stdout and stderr from a function call.
type capturedOutput struct {
	stdout string
	stderr string
}

// captureOutput runs fn while capturing both stdout and stderr.
// Reads pipes concurrently to avoid deadlock when fn() output exceeds
// the OS pipe buffer (~64KB).
func captureOutput(fn func() error) (capturedOutput, error) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout = outW
	os.Stderr = errW

	// Read pipes concurrently to prevent deadlock
	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // reading stdout + stderr
	go func() { defer wg.Done(); _, _ = outBuf.ReadFrom(outR) }()
	go func() { defer wg.Done(); _, _ = errBuf.ReadFrom(errR) }()

	fnErr := fn()

	_ = outW.Close()
	_ = errW.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	wg.Wait()
	return capturedOutput{stdout: outBuf.String(), stderr: errBuf.String()}, fnErr
}

// firstLine returns the first line of s, stripping any trailing newline.
func firstLine(s string) string {
	if idx := strings.Index(s, "\n"); idx >= 0 {
		return s[:idx]
	}
	return s
}

// bulkHasFailure returns true if any result has Success == false.
func bulkHasFailure(results []BulkResult) bool {
	for _, r := range results {
		if !r.Success {
			return true
		}
	}
	return false
}

// isDirectoryOutput reports whether -o names a directory rather than a file:
// it ends in a path separator, or it already exists as one. A trailing
// separator is the only way to say "a directory that does not exist yet".
func isDirectoryOutput(path string) bool {
	if path == "" {
		return false
	}
	if last := path[len(path)-1]; last == '/' || last == filepath.Separator {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
