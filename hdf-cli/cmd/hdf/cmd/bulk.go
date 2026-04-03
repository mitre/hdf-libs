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
}

// BulkProcessFn processes a single file and returns an error if it fails.
type BulkProcessFn func(file string) error

// runBulk processes multiple files with the given function.
// Without -k/--continue-on-error, aborts on first failure.
// With -k, continues processing all files and reports failures at the end.
func runBulk(files []string, verb, successVerb string, processFn BulkProcessFn) error {
	var results []BulkResult

	for _, file := range files {
		result := BulkResult{File: file, Success: true}

		// In bulk mode, capture all output from the inner function.
		// On success: print captured stdout. On failure: print a short error.
		captured, fnErr := captureOutput(func() error {
			return processFn(file)
		})
		if fnErr != nil {
			result.Success = false
			result.Error = firstLine(fnErr.Error())
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
			fmt.Fprintf(os.Stderr, "%s: ok\n", file)
		default:
			fmt.Fprintf(os.Stderr, "%s: error\n", file)
		}

		results = append(results, result)

		// Without -k, abort on first failure.
		if !result.Success && !continueOnError {
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
		printBulkErrors(results)
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

// bulkOutputPath computes the output filename for a bulk conversion.
// Input "scan.nessus" with toFormat "hdf" → "scan.hdf.json"
// Input "report.sarif" with toFormat "csv" produces "report.hdf.csv".
func bulkOutputPath(outputDir, inputPath, toFormat string) string {
	base := filepath.Base(inputPath)
	ext := filepath.Ext(base)
	stem := base[:len(base)-len(ext)]

	var outName string
	if toFormat == "hdf" || toFormat == "" {
		outName = stem + ".hdf.json"
	} else {
		outName = stem + ".hdf." + toFormat
	}
	return filepath.Join(outputDir, outName)
}
