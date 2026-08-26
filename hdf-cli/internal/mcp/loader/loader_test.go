package loader

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
)

// A real HDF System document (validated by the schema but NOT struct-parsed by
// the engine core) exercises the wrapper's all-types validity path.
func validSystem(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "cmd", "hdf", "cmd", "testdata", "evidence-verify", "system.json"))
	if err != nil {
		t.Skipf("system fixture unavailable: %v", err)
	}
	return b
}

// A real HDF Results document (from the shared corpus) for the valid/cache paths.
func validResults() []byte { return fixtures.Results.Minimal }

// A real-but-schema-invalid HDF Results document: real structure with baselines
// as a string instead of an array. Detected as "results", fails validation —
// the degraded-read path. Not fabricated data; a real doc with one field broken.
const invalidResults = `{
  "baselines": "not an array",
  "components": [],
  "statistics": {}
}`

func TestLoad_InvalidDoc_DegradedMode(t *testing.T) {
	l := New(0, 0, 0)
	res, err := l.Load([]byte(invalidResults))
	if err != nil {
		t.Fatalf("degraded read must NOT hard-fail, got error: %v", err)
	}
	if res.Valid {
		t.Fatal("invalid document should have Valid=false")
	}
	if res.DocType != "results" {
		t.Errorf("docType = %q, want results (detected)", res.DocType)
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected degraded envelope validation errors")
	}
	// At least one error should carry a source line number > 0.
	hasLine := false
	for _, e := range res.Errors {
		if e.Line > 0 {
			hasLine = true
		}
		if e.Description == "" {
			t.Error("validation error missing description")
		}
	}
	if !hasLine {
		t.Error("expected at least one line-numbered validation error")
	}
}

func TestLoad_ValidNonResultsType_ReportedValid(t *testing.T) {
	// A valid system document — which the engine core detects but does NOT
	// struct-parse — must be reported valid (via schema validation), not mistaken
	// for a degraded read.
	l := New(0, 0, 0)
	res, err := l.Load(validSystem(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.DocType != "system" {
		t.Errorf("docType = %q, want system", res.DocType)
	}
	if !res.Valid {
		t.Fatalf("a valid system doc must be reported valid, got errors: %+v", res.Errors)
	}
	if len(res.Errors) != 0 {
		t.Errorf("valid doc must carry no degraded errors, got %v", res.Errors)
	}
}

func TestLoad_InvalidNonResultsType_Degraded(t *testing.T) {
	// A document detected as system (has "components") but schema-invalid degrades
	// with line-numbered errors rather than being mistaken for valid.
	bad := []byte("{\n  \"components\": \"not an array\"\n}")
	res, err := New(0, 0, 0).Load(bad)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.DocType != "system" || res.Valid {
		t.Errorf("expected detected system + invalid, got docType=%q valid=%v", res.DocType, res.Valid)
	}
	if len(res.Errors) == 0 {
		t.Error("invalid system doc must carry degraded errors")
	}
}

func TestLoad_UnknownType_DegradedWithGenericError(t *testing.T) {
	l := New(0, 0, 0)
	res, err := l.Load([]byte(`{"nope": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid || res.DocType != "" {
		t.Errorf("unknown type should be invalid with empty docType, got valid=%v type=%q", res.Valid, res.DocType)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected one error, got %+v", res.Errors)
	}
	// Valid JSON with no matching root keys is a RECOGNIZED-TYPE problem, not a
	// parse problem: the message must say so and must NOT claim the input is
	// non-JSON (jobi.3 / D6). It also hints the recognized types.
	msg := res.Errors[0].Description
	if !strings.Contains(msg, "not a recognized HDF document type") {
		t.Errorf("valid-JSON-unknown-type message should name a recognized-type problem, got %q", msg)
	}
	if strings.Contains(msg, "non-JSON") || strings.Contains(msg, "not valid JSON") {
		t.Errorf("valid JSON must not be reported as a parse problem, got %q", msg)
	}
	if !strings.Contains(msg, "results") || !strings.Contains(msg, "amendments") {
		t.Errorf("message should hint the recognized types, got %q", msg)
	}
}

func TestLoad_NotJSON_ParseMessage(t *testing.T) {
	l := New(0, 0, 0)
	res, err := l.Load([]byte(`{ this is not: json `))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid || res.DocType != "" {
		t.Errorf("malformed JSON should be invalid with empty docType, got valid=%v type=%q", res.Valid, res.DocType)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("expected one error, got %+v", res.Errors)
	}
	// Genuinely malformed JSON must get a parse-oriented message, distinct from
	// the valid-JSON-wrong-type case, so an agent does not chase a phantom type.
	msg := res.Errors[0].Description
	if !strings.Contains(msg, "not valid JSON") {
		t.Errorf("malformed JSON should get a parse-oriented message, got %q", msg)
	}
	if strings.Contains(msg, "recognized HDF document type") {
		t.Errorf("a parse failure must not be reported as a wrong-type problem, got %q", msg)
	}
}

func TestLoad_ValidDoc(t *testing.T) {
	l := New(0, 0, 0)
	res, err := l.Load(validResults())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid, got errors: %+v", res.Errors)
	}
	if res.Engine == nil || res.Engine.Results == nil {
		t.Fatal("expected parsed results on the engine result")
	}
}

func TestCache_HitOnSecondLoad(t *testing.T) {
	l := New(0, 0, 0)
	if r, _ := l.Load(validResults()); r.CacheHit {
		t.Fatal("first load must be a cache MISS")
	}
	r2, _ := l.Load(validResults())
	if !r2.CacheHit {
		t.Fatal("second load of identical bytes must be a cache HIT")
	}
	if !r2.Valid || r2.Engine == nil || r2.Engine.Results == nil {
		t.Error("cached result must carry the parsed document")
	}
}

func TestCache_MissForDifferentDocs(t *testing.T) {
	l := New(0, 0, 0)
	l.Load(validResults())                 //nolint:errcheck // exercising cache
	r, _ := l.Load([]byte(invalidResults)) // different bytes
	if r.CacheHit {
		t.Fatal("a different document must be a cache MISS")
	}
}

func TestCache_EvictionByBytes(t *testing.T) {
	small := validResults()                      // minimal.json (small)
	large := fixtures.Results.InspecMultilayered // multilayered (larger)
	// Budget holds either document alone, but not both → loading the second
	// evicts the first (LRU by bytes).
	budget := int64(len(large))
	if int64(len(small)) > budget {
		t.Skip("fixture sizes do not satisfy small < large for the eviction case")
	}
	l := New(0, 0, budget)

	valid := small
	l.Load(small) //nolint:errcheck // seed the first (oldest) doc
	l.Load(large) //nolint:errcheck // distinct doc forces eviction of the oldest

	// The cache must not exceed its budget after eviction.
	l.mu.Lock()
	over := l.curSize > l.cacheBytes
	l.mu.Unlock()
	if over {
		t.Fatalf("cache size %d exceeds budget %d after eviction", l.curSize, l.cacheBytes)
	}

	// The first document should have been evicted → re-loading it is a MISS.
	r, _ := l.Load(valid)
	if r.CacheHit {
		t.Error("expected the LRU-evicted document to be a cache MISS on reload")
	}
}

func TestCache_OversizeDocumentBypasses(t *testing.T) {
	valid := validResults()
	// Budget smaller than the document → it must load (valid) but never cache.
	l := New(0, 0, int64(len(valid))-1)
	r1, err := l.Load(valid)
	if err != nil {
		t.Fatalf("oversize doc must still load: %v", err)
	}
	if !r1.Valid {
		t.Fatal("oversize doc should still parse validly")
	}
	r2, _ := l.Load(valid)
	if r2.CacheHit {
		t.Error("a document larger than the whole budget must bypass the cache (no hit)")
	}
}

func TestCache_BudgetFromEnvVar(t *testing.T) {
	// HDF_MCP_CACHE_BYTES sets the budget when New is given cacheBytes<=0. A tiny
	// env budget makes an ordinary document oversize → it loads but never caches.
	t.Setenv("HDF_MCP_CACHE_BYTES", "5")
	l := New(0, 0, 0)
	if l.cacheBytes != 5 {
		t.Fatalf("cacheBytes = %d, want 5 (from HDF_MCP_CACHE_BYTES)", l.cacheBytes)
	}
	l.Load(validResults()) //nolint:errcheck // seed
	if r, _ := l.Load(validResults()); r.CacheHit {
		t.Error("with a 5-byte env budget, an ordinary document must bypass the cache")
	}
}

func TestLoad_SizeGuardReturnsHardError(t *testing.T) {
	l := New(4, 0, 0) // 4-byte per-document limit
	_, err := l.Load([]byte("way bigger than four bytes"))
	if err == nil {
		t.Fatal("expected a hard error from the size guard")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected size error, got %v", err)
	}
}

func TestLoad_WritesNothingToStdout(t *testing.T) {
	orig := os.Stdout
	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = wp

	l := New(0, 0, 0)
	l.Load(validResults())           //nolint:errcheck // exercising stdout silence
	l.Load([]byte(invalidResults))   //nolint:errcheck
	l.Load([]byte(`{"nope": true}`)) //nolint:errcheck

	wp.Close()
	os.Stdout = orig
	buf := make([]byte, 1024)
	n, _ := rp.Read(buf)
	if n > 0 {
		t.Fatalf("loader wrote %d bytes to stdout (must be silent): %q", n, buf[:n])
	}
}

func TestLoadByHash_RoundTrip(t *testing.T) {
	l := New(0, 0, 0)
	data := validResults()
	if _, err := l.Load(data); err != nil {
		t.Fatalf("seed load: %v", err)
	}
	hexSha := fmt.Sprintf("%x", sha256.Sum256(data))

	bytes, res, ok := l.LoadByHash(hexSha)
	if !ok {
		t.Fatal("a document registered via Load must be retrievable by its content sha256")
	}
	if string(bytes) != string(data) {
		t.Error("LoadByHash must return the exact registered bytes")
	}
	if res == nil || !res.Valid || res.DocType != "results" {
		t.Errorf("LoadByHash result = %+v, want valid results", res)
	}

	if _, _, ok := l.LoadByHash("00" + hexSha[2:]); ok {
		t.Error("an unknown content sha256 must miss")
	}
	if _, _, ok := l.LoadByHash("not-hex"); ok {
		t.Error("a non-hex sha must miss, not panic")
	}
}
