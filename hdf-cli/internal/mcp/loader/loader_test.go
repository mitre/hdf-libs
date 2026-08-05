package loader

import (
	"os"
	"strings"
	"testing"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
)

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

func TestLoad_UnknownType_DegradedWithGenericError(t *testing.T) {
	l := New(0, 0, 0)
	res, err := l.Load([]byte(`{"nope": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid || res.DocType != "" {
		t.Errorf("unknown type should be invalid with empty docType, got valid=%v type=%q", res.Valid, res.DocType)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Description, "unrecognized") {
		t.Errorf("expected one 'unrecognized' error, got %+v", res.Errors)
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
