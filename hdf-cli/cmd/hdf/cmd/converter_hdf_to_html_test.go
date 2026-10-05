package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHDFToHTMLConverter_IsRegistered(t *testing.T) {
	converter, err := GetConverter("hdf", "html")
	require.NoError(t, err, "HDF-to-HTML converter should be registered")
	assert.Equal(t, "HDF to HTML", converter.Name())
	_, ok := converter.(ReportTypeSetter)
	assert.True(t, ok, "the HTML converter offers report types")
}

func TestHDFToHTMLConverter_Convert_Rich(t *testing.T) {
	inputData, err := os.ReadFile(converterFixturePath(t, "hdf-to-html", "input/rich.json"))
	require.NoError(t, err)

	converter, err := GetConverter("hdf", "html")
	require.NoError(t, err)
	require.NoError(t, converter.(ReportTypeSetter).SetReportType(""))

	output, err := converter.Convert(inputData)
	require.NoError(t, err)
	html := string(output)
	assert.True(t, strings.HasPrefix(html, "<!DOCTYPE html>"))
	for _, want := range []string{"systems/portal.hdf-system.json", "code.jquery.com", "mymac.com", "CI0012345", "Report type: Administrator"} {
		assert.Contains(t, html, want)
	}
}

func TestHDFToHTMLConverter_Convert_InvalidJSON(t *testing.T) {
	converter, err := GetConverter("hdf", "html")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid json"))
	require.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "hdf-to-html")
}

func TestConvertToHTML_CLI(t *testing.T) {
	input := converterFixturePath(t, "hdf-to-html", "input/rich.json")
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand(append([]string{"convert", input, "--to", "html", "-o", out}, args...)...)
		if err != nil {
			assert.NoFileExists(t, out, "a refused conversion writes nothing")
			return "", err
		}
		data, readErr := os.ReadFile(out)
		require.NoError(t, readErr)
		return string(data), nil
	}

	t.Run("auto-detects HDF and writes one self-contained file", func(t *testing.T) {
		html, err := run(t)
		require.NoError(t, err)
		assert.Contains(t, html, "Report type: Administrator")
		assert.Contains(t, html, "default-src 'none'")
		assert.Equal(t, 2, strings.Count(html, `<details class="fold component"`))
	})

	t.Run("--report-type selects the level of detail", func(t *testing.T) {
		executive, err := run(t, "--report-type", "executive")
		require.NoError(t, err)
		assert.Contains(t, executive, "Report type: Executive")
		assert.NotContains(t, executive, `<article class="requirement`)

		manager, err := run(t, "--report-type", "Manager")
		require.NoError(t, err)
		assert.Contains(t, manager, "Report type: Manager")
	})

	t.Run("a report type does not carry over to the next conversion", func(t *testing.T) {
		_, err := run(t, "--report-type", "executive")
		require.NoError(t, err)
		html, err := run(t)
		require.NoError(t, err)
		assert.Contains(t, html, "Report type: Administrator")
	})

	t.Run("an unknown report type is refused", func(t *testing.T) {
		_, err := run(t, "--report-type", "auditor")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--report-type")
		assert.Contains(t, err.Error(), `"auditor"`)
	})

	t.Run("--report-type is refused for another target", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.csv")
		_, _, err := executeCommand("convert", input, "--to", "csv", "-o", out, "--report-type", "manager")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--report-type applies to --to html only")
		assert.NoFileExists(t, out)
	})

	t.Run("the same input yields the same bytes", func(t *testing.T) {
		first, err := run(t)
		require.NoError(t, err)
		second, err := run(t)
		require.NoError(t, err)
		assert.Equal(t, first, second)
	})
}

// stageRunDirectory lays out what a scan run leaves behind: results documents at
// two levels, one of them legacy, beside artifacts that are not results.
func stageRunDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		full := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, data, 0o600))
	}
	rich, err := os.ReadFile(converterFixturePath(t, "hdf-to-html", "input/rich.json"))
	require.NoError(t, err)

	write("b-zap/zap.v3.hdf.json", rich)
	write("a-minimal.hdf.json", fixtures.Results.Minimal)
	write("c-legacy/ubi9.hdf.json", fixtures.Inspec.Ubi9Scan)
	write("b-zap/zap.amendments.json", fixtures.Amendments.MultiCVE)
	write("notes.txt", []byte("not json"))
	write("broken.json", []byte("{not json"))
	return dir
}

func TestConvertToHTML_CombinesSeveralInputs(t *testing.T) {
	rich := converterFixturePath(t, "hdf-to-html", "input/rich.json")
	detail := converterFixturePath(t, "hdf-to-html", "input/finding-detail.json")

	t.Run("several files and a file output make one report", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.html")
		_, stderr, err := executeCommand("convert", rich, detail, "--to", "html", "-o", out)
		require.NoError(t, err)
		assert.Contains(t, stderr, "Combined 2 documents into")

		data, err := os.ReadFile(out)
		require.NoError(t, err)
		html := string(data)
		assert.Contains(t, html, `<h2 id="sources-heading">Sources (2)</h2>`)
		assert.Contains(t, html, `<a href="#source-1">rich.json</a>`)
		assert.Contains(t, html, `<a href="#source-2">finding-detail.json</a>`)
		assert.Equal(t, 5, strings.Count(html, `<article class="requirement `))
	})

	t.Run("a glob behaves as the files it matches", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.html")
		pattern := filepath.Join(filepath.Dir(rich), "*.json")
		_, _, err := executeCommand("convert", pattern, "--to", "html", "-o", out, "--report-type", "executive")
		require.NoError(t, err)
		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Contains(t, string(data), `<h2 id="sources-heading">Sources (2)</h2>`)
		assert.Contains(t, string(data), "Report type: Executive")
	})

	t.Run("a directory output keeps one report per input", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "reports") + string(filepath.Separator)
		_, _, err := executeCommand("convert", rich, detail, "--to", "html", "-o", outDir)
		require.NoError(t, err)
		for _, name := range []string{"rich.hdf.html", "finding-detail.hdf.html"} {
			data, readErr := os.ReadFile(filepath.Join(outDir, name))
			require.NoError(t, readErr, name)
			assert.NotContains(t, string(data), `id="sources"`, "a per-input report has no source level")
		}
	})

	t.Run("inputs that share a file name are told apart by path", func(t *testing.T) {
		dir := t.TempDir()
		data, err := os.ReadFile(rich)
		require.NoError(t, err)
		first, second := filepath.Join(dir, "a", "scan.json"), filepath.Join(dir, "b", "scan.json")
		for _, p := range []string{first, second} {
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, data, 0o600))
		}
		out := filepath.Join(dir, "report.html")
		_, _, err = executeCommand("convert", first, second, "--to", "html", "-o", out)
		require.NoError(t, err)
		html, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Contains(t, string(html), filepath.ToSlash(first))
		assert.Contains(t, string(html), filepath.ToSlash(second))
	})

	t.Run("a named input that is not results is refused, and nothing is written", func(t *testing.T) {
		amendments := filepath.Join(t.TempDir(), "amendments.json")
		require.NoError(t, os.WriteFile(amendments, fixtures.Amendments.MultiCVE, 0o600))
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", rich, amendments, "--to", "html", "-o", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "amendments.json")
		assert.NoFileExists(t, out)
	})

	t.Run("a missing input fails the whole report and names the file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "gone.json")
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", rich, missing, "--to", "html", "-o", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gone.json")
		assert.NoFileExists(t, out)
	})

	t.Run("an output path that cannot be written is an error", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "no-such-dir", "report.html")
		_, _, err := executeCommand("convert", rich, detail, "--to", "html", "-o", out)
		require.Error(t, err)
	})

	t.Run("the output may not be one of the inputs", func(t *testing.T) {
		dir := t.TempDir()
		data, err := os.ReadFile(rich)
		require.NoError(t, err)
		a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
		require.NoError(t, os.WriteFile(a, data, 0o600))
		require.NoError(t, os.WriteFile(b, data, 0o600))
		_, _, err = executeCommand("convert", a, b, "--to", "html", "-o", b)
		require.Error(t, err)
		after, readErr := os.ReadFile(b)
		require.NoError(t, readErr)
		assert.Equal(t, string(data), string(after))
	})

	t.Run("an unknown report type is refused before anything is read", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", rich, detail, "--to", "html", "-o", out, "--report-type", "auditor")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--report-type")
		assert.NoFileExists(t, out)
	})
}

func TestConvertToHTML_DirectoryInput(t *testing.T) {
	t.Run("takes the results documents under it, current and legacy, in path order", func(t *testing.T) {
		dir := stageRunDirectory(t)
		out := filepath.Join(t.TempDir(), "report.html")
		_, stderr, err := executeCommand("convert", dir, "--to", "html", "-o", out)
		require.NoError(t, err)
		assert.Contains(t, stderr, "Combined 3 documents into")
		assert.Contains(t, stderr, "Skipped 3 file(s) that are not HDF results documents")

		data, err := os.ReadFile(out)
		require.NoError(t, err)
		html := string(data)
		assert.Contains(t, html, `<h2 id="sources-heading">Sources (3)</h2>`)
		first := strings.Index(html, `<a href="#source-1">a-minimal.hdf.json</a>`)
		second := strings.Index(html, `<a href="#source-2">zap.v3.hdf.json</a>`)
		third := strings.Index(html, `<a href="#source-3">ubi9.hdf.json</a>`)
		require.Positive(t, first)
		assert.Less(t, first, second)
		assert.Less(t, second, third)
		assert.NotContains(t, html, "amendments.json")
	})

	t.Run("a directory holding one results document still reports by source", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "only.json"), fixtures.Results.Minimal, 0o600))
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", dir, "--to", "html", "-o", out)
		require.NoError(t, err)
		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Contains(t, string(data), `<h2 id="sources-heading">Sources (1)</h2>`)
	})

	t.Run("a directory with no results documents is an error", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "amendments.json"), fixtures.Amendments.MultiCVE, 0o600))
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", dir, "--to", "html", "-o", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no HDF results documents found")
		assert.NoFileExists(t, out)
	})

	t.Run("a directory and a file can be given together", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "in-dir.json"), fixtures.Results.Minimal, 0o600))
		out := filepath.Join(t.TempDir(), "report.html")
		_, _, err := executeCommand("convert", dir, converterFixturePath(t, "hdf-to-html", "input/rich.json"), "--to", "html", "-o", out)
		require.NoError(t, err)
		data, err := os.ReadFile(out)
		require.NoError(t, err)
		assert.Contains(t, string(data), `<h2 id="sources-heading">Sources (2)</h2>`)
	})

	// A file over --max-size is the read failure every platform can produce; a
	// file mode cannot make a file unreadable on Windows or to root.
	t.Run("a file under the directory that cannot be read is reported and passed over", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.json"), fixtures.Results.Minimal, 0o600))
		oversized := append(bytes.Repeat([]byte(" "), 2<<20), fixtures.Results.Minimal...)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "too-big.json"), oversized, 0o600))

		out := filepath.Join(t.TempDir(), "report.html")
		_, stderr, err := executeCommand("convert", dir, "--to", "html", "-o", out, "--max-size", "1")
		require.NoError(t, err)
		assert.Contains(t, stderr, "Warning: skipped")
		assert.Contains(t, stderr, "too-big.json")
		assert.Contains(t, stderr, "Combined 1 documents into")
	})

	t.Run("without -o the combined report goes to stdout", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "only.json"), fixtures.Results.Minimal, 0o600))
		stdout, stderr, err := executeCommand("convert", dir, "--to", "html")
		require.NoError(t, err)
		assert.Contains(t, stdout, `<h2 id="sources-heading">Sources (1)</h2>`)
		assert.NotContains(t, stderr, "Combined", "the summary line is for a written file")
	})

	t.Run("another target does not take a directory", func(t *testing.T) {
		_, _, err := executeCommand("convert", stageRunDirectory(t), "--to", "csv", "-o", filepath.Join(t.TempDir(), "out.csv"))
		require.Error(t, err)
	})

	t.Run("a file that is not results is counted whatever its extension", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "results.json"), fixtures.Results.Minimal, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "scan.log"), []byte("scanner log\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hand notes\n"), 0o600))

		out := filepath.Join(t.TempDir(), "report.html")
		_, stderr, err := executeCommand("convert", dir, "--to", "html", "-o", out)
		require.NoError(t, err)
		assert.Contains(t, stderr, "Skipped 2 file(s) that are not HDF results documents")
		assert.Contains(t, stderr, "Combined 1 documents into")
	})
}

func TestConvertToHTML_DirectoryInput_OneReportPerInput(t *testing.T) {
	t.Run("inputs that share a file name are written to reports of their own", func(t *testing.T) {
		dir := t.TempDir()
		rich, err := os.ReadFile(converterFixturePath(t, "hdf-to-html", "input/rich.json"))
		require.NoError(t, err)
		for rel, data := range map[string][]byte{
			"host1/results.json": rich,
			"host2/results.json": fixtures.Results.Minimal,
		} {
			full := filepath.Join(dir, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
			require.NoError(t, os.WriteFile(full, data, 0o600))
		}

		outDir := filepath.Join(t.TempDir(), "reports") + string(filepath.Separator)
		_, _, err = executeCommand("convert", dir, "--to", "html", "-o", outDir)
		require.NoError(t, err)

		first, err := os.ReadFile(filepath.Join(outDir, "host1--results.hdf.html"))
		require.NoError(t, err)
		second, err := os.ReadFile(filepath.Join(outDir, "host2--results.hdf.html"))
		require.NoError(t, err)
		assert.NotEqual(t, string(first), string(second), "each input is reported on its own")

		entries, err := os.ReadDir(outDir)
		require.NoError(t, err)
		assert.Len(t, entries, 2, "one report per input, none overwritten")
	})

	// A qualified name can still meet a file that was already called that.
	t.Run("two inputs that name one report are refused before anything is written", func(t *testing.T) {
		dir := t.TempDir()
		for _, rel := range []string{"host1/results.json", "host2/results.json", "host1--results.json"} {
			full := filepath.Join(dir, rel)
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
			require.NoError(t, os.WriteFile(full, fixtures.Results.Minimal, 0o600))
		}

		outDir := filepath.Join(t.TempDir(), "reports") + string(filepath.Separator)
		_, _, err := executeCommand("convert", dir, "--to", "html", "-o", outDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host1--results.hdf.html")
		assert.NoDirExists(t, outDir)
	})
}

func TestSourceNames(t *testing.T) {
	assert.Equal(t, []string{"a.json", "b.json"}, sourceNames([]string{"x/a.json", "y/b.json"}))
	assert.Equal(t, []string{"x/a.json", "y/a.json", "b.json"}, sourceNames([]string{"x/a.json", "y/./a.json", "b.json"}))
}

func TestHDFToHTMLConverter_ConvertMany(t *testing.T) {
	converter, err := GetConverter("hdf", "html")
	require.NoError(t, err)
	multi, ok := converter.(MultiInputConverter)
	require.True(t, ok, "the HTML converter combines documents")
	require.NoError(t, converter.(ReportTypeSetter).SetReportType("executive"))
	t.Cleanup(func() { _ = converter.(ReportTypeSetter).SetReportType("") })

	out, err := multi.ConvertMany([]NamedInput{{Name: "a.json", Data: fixtures.Results.Minimal}, {Name: "b.json", Data: fixtures.Results.Minimal}})
	require.NoError(t, err)
	assert.Contains(t, string(out), `<h2 id="sources-heading">Sources (2)</h2>`)
	assert.Contains(t, string(out), "Report type: Executive")

	_, err = multi.ConvertMany(nil)
	require.Error(t, err)
}
