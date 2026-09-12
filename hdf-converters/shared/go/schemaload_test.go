package shared_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// Provenance convention for converter reference data.
//
// A directory holding schemas or fixtures records where they came from, so a
// developer debugging a converter years from now can find the reference it was
// built against:
//
//   - provenance.json — there IS a machine-readable schema. Lists each schema
//     file with its source URL and the SHA-256 of the file as vendored here.
//   - provenance.txt  — there is NO schema. Free prose explaining that, and
//     where the fixtures came from. Content is not asserted: the file's
//     existence is the signal, because prose is not machine-checkable.
//
// json wins when both are present; the txt then carries supplementary context.
//
// WHAT THIS DOES NOT VERIFY: everything inside a provenance.txt. A directory
// with no schema is trusted prose by construction. Do not read a green run as
// evidence that those descriptions are accurate or current.

type provenanceEntry struct {
	File           string `json:"file"`
	Source         string `json:"source"`
	SHA256         string `json:"sha256"`
	Retrieved      string `json:"retrieved"`
	Modified       string `json:"modified,omitempty"`
	UpstreamSHA256 string `json:"upstream_sha256,omitempty"`
}

type provenanceDoc struct {
	Schemas []provenanceEntry `json:"schemas"`
}

// schemaBearingDirs returns every directory under converters/ that holds a
// vendored schema, found by content rather than by directory name — a schema
// parked in fixtures/ is still a schema, and scoping the walk to schemas/ would
// under-report while still reporting green.
//
// One location IS excluded: fixtures/expected/, which holds this repo's own
// converter output rather than anything vendored. A schema placed there would
// not be covered.
func schemaBearingDirs(t *testing.T) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	root := shared.GetConvertersDir()
	require.NoError(t, filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		name := info.Name()
		if name == "provenance.json" || strings.Contains(path, string(filepath.Separator)+"expected"+string(filepath.Separator)) {
			return nil
		}
		switch {
		case strings.HasSuffix(name, ".xsd"):
		case strings.HasSuffix(name, ".json"):
			raw, readErr := os.ReadFile(path) // #nosec G304 -- repo-relative reference data
			if readErr != nil {
				// A file the walk can see but cannot read is a broken tree, not a
				// non-schema; failing here beats silently narrowing the sweep.
				return fmt.Errorf("reading %s: %w", path, readErr)
			}
			if !declaresJSONSchema(raw) {
				return nil
			}
		default:
			return nil
		}
		dir := filepath.Dir(path)
		found[dir] = append(found[dir], name)
		return nil
	}))
	return found
}

// declaresJSONSchema reports whether raw is a JSON object carrying a top-level
// "$schema". Unparseable JSON is simply not a schema: several converters vendor
// deliberately malformed fixtures to exercise error paths, and those must not
// fail the sweep.
func declaresJSONSchema(raw []byte) bool {
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	_, ok := probe["$schema"]
	return ok
}

func readProvenance(t *testing.T, dir string) (provenanceDoc, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "provenance.json")) // #nosec G304 -- repo-relative
	if err != nil {
		return provenanceDoc{}, false
	}
	var doc provenanceDoc
	require.NoError(t, json.Unmarshal(raw, &doc), "provenance.json is not valid JSON")
	return doc, true
}

// Every directory holding a vendored schema declares where it came from, and
// every schema it lists still hashes to what was recorded. That is what makes
// the file load-bearing rather than decorative: swapping a schema, editing one
// in place, adding one with no entry, or typing a hash wrong all fail here.
//
// The recorded hash is of the file AS VENDORED, not upstream. Two XCCDF XSDs are
// modified on purpose so libxml2 resolves them offline; they carry the upstream
// hash separately and stay tamper-evident locally.
func TestSchemaLoadProvenanceCoversEveryVendoredSchema(t *testing.T) {
	dirs := schemaBearingDirs(t)
	require.NotEmpty(t, dirs, "no vendored schemas found — the walk is broken, not the tree")

	checked := 0
	for dir, files := range dirs {
		label := filepath.Base(filepath.Dir(dir)) + "/" + filepath.Base(dir)
		doc, hasJSON := readProvenance(t, dir)
		if !hasJSON {
			t.Errorf("%s holds %d vendored schema(s) but has no provenance.json: %v", label, len(files), files)
			continue
		}

		recorded := map[string]provenanceEntry{}
		for _, e := range doc.Schemas {
			recorded[e.File] = e
		}
		for _, f := range files {
			t.Run(label+"/"+f, func(t *testing.T) {
				e, listed := recorded[f]
				require.True(t, listed, "vendored schema is not listed in provenance.json")
				require.NotEmpty(t, e.Source, "no source URL recorded")
				raw, err := os.ReadFile(filepath.Join(dir, f)) // #nosec G304 -- repo-relative
				require.NoError(t, err)
				assert.Equal(t, e.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)),
					"file does not match the SHA-256 recorded in provenance.json")
			})
			checked++
		}
	}
	assert.Greater(t, checked, 3, "too few schemas checked for this to be meaningful")
}

// A schema nobody can compile is not ground truth. Kept separate from provenance
// because ajv and gojsonschema do not accept exactly the same documents, so the
// TypeScript peer asserts the same property over the same tree -- minus the
// draft-04 CVSS family, which ajv 8 cannot load at all and which this side
// therefore covers alone.
func TestSchemaLoadEveryVendoredSchemaCompiles(t *testing.T) {
	for dir, files := range schemaBearingDirs(t) {
		for _, f := range files {
			if !strings.HasSuffix(f, ".json") {
				continue // XSDs are compiled by libxml2 in the xccdf converter's own tests
			}
			t.Run(filepath.Base(filepath.Dir(dir))+"/"+f, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join(dir, f)) // #nosec G304 -- repo-relative
				require.NoError(t, err)
				_, schemaErr := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(raw))
				require.NoError(t, schemaErr, "vendored schema does not compile")
			})
		}
	}
}

// Link rot and upstream rewriting a published schema in place are real, but
// checking them needs the network, which would make every local run flaky and
// every offline run fail. Opt in with HDF_PROVENANCE_NETWORK=1 (a scheduled job,
// not the PR gate) to re-fetch each source and compare it to what was recorded.
func TestSchemaLoadProvenanceSourcesStillResolve(t *testing.T) {
	if os.Getenv("HDF_PROVENANCE_NETWORK") != "1" {
		t.Skip("set HDF_PROVENANCE_NETWORK=1 to check source URLs against the network")
	}
	client := &http.Client{Timeout: 90 * time.Second}
	for dir := range schemaBearingDirs(t) {
		doc, ok := readProvenance(t, dir)
		if !ok {
			continue
		}
		for _, e := range doc.Schemas {
			t.Run(filepath.Base(filepath.Dir(dir))+"/"+e.File, func(t *testing.T) {
				want := e.SHA256
				if e.Modified != "" {
					want = e.UpstreamSHA256
					require.NotEmpty(t, want, "a locally modified schema must record upstream_sha256")
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.Source, nil)
				require.NoError(t, err)
				// Per file type, not blanket: schema.ocsf.io serves HTML unless
				// asked for JSON, while csrc.nist.gov serves an EMPTY body for an
				// .xsd requested as application/json -- which hashes to the
				// empty-string digest and reads as upstream drift rather than a
				// bad request.
				if strings.HasSuffix(e.File, ".json") {
					req.Header.Set("Accept", "application/json")
				}
				resp, err := client.Do(req)
				require.NoError(t, err, "source URL did not resolve")
				defer func() { _ = resp.Body.Close() }()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, want, fmt.Sprintf("%x", sha256.Sum256(body)),
					"upstream no longer serves the bytes recorded in provenance.json")
			})
		}
	}
}
