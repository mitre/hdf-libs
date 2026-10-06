package hdfengine

import (
	"os"
	"path/filepath"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
)

// The cross-language parity contract for the loader core: for each shared
// committed fixture, Go Load and the TS load (test/loader.test.ts) must agree on
// the detected wire format, the detected document type, and validity. This table
// is asserted here on the Go side; test/loader.test.ts asserts the SAME fixtures
// to the SAME expected values on the TS side. A divergence in parse+detect
// behaviour fails one side of the pair. See detect_test.go for the same
// shared-fixture parity pattern.
func TestLoader_CrossLanguageParity(t *testing.T) {
	cases := []struct {
		fixture     string
		wantFormat  InputFormat
		wantDocType string
		wantValid   bool
		// bytes, when set, is the document itself: a shared-corpus row has no testdata file.
		bytes []byte
	}{
		{"query-fixture.json", FormatJSON, "results", true, nil},
		{"win2022-stig.json (hdf-fixtures)", FormatJSON, "baseline", true, fixtures.Baseline.Win2022Stig},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			data := c.bytes
			var err error
			if data == nil {
				data, err = os.ReadFile(filepath.Join("..", "testdata", c.fixture))
			}
			if err != nil {
				t.Fatalf("read %s: %v", c.fixture, err)
			}
			res, err := Load(data, 0)
			if err != nil {
				t.Fatalf("Load(%s): %v", c.fixture, err)
			}
			if res.Format != c.wantFormat {
				t.Errorf("%s: format = %q, want %q", c.fixture, res.Format, c.wantFormat)
			}
			if res.DocType != c.wantDocType {
				t.Errorf("%s: docType = %q, want %q", c.fixture, res.DocType, c.wantDocType)
			}
			if res.Valid != c.wantValid {
				t.Errorf("%s: valid = %v, want %v", c.fixture, res.Valid, c.wantValid)
			}
		})
	}
}
