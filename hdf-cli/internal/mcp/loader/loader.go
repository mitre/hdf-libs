// Package loader is the MCP-side document loader: a thin Go wrapper over the
// pure hdf-engine loader core. It adds the two concerns that belong to the
// stdio MCP process and NOT the shared engine:
//
//   - a byte-bounded, LRU parsed-document cache (HDF_MCP_CACHE_BYTES, default
//     256 MB), so repeated reads of the same document skip re-parsing; and
//   - a degraded-read envelope: an invalid document returns a successful result
//     with valid:false, the detected type, and the first N line-numbered
//     validation errors — never a hard error.
//
// It writes nothing to stdout (that would corrupt the stdio protocol stream);
// diagnostics go to stderr via the standard logger only.
package loader

import (
	"container/list"
	"crypto/sha256"
	"os"
	"strconv"
	"sync"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// DefaultCacheBytes is the default parsed-document cache budget (256 MB). A
// parsed HDF document is a large multiple of its on-disk size, so the budget is
// generous relative to file sizes. Override via HDF_MCP_CACHE_BYTES.
const DefaultCacheBytes = 256 * 1024 * 1024

// DefaultMaxErrors is how many line-numbered validation errors the degraded
// envelope carries by default.
const DefaultMaxErrors = 10

// ValidationError is one degraded-envelope error, annotated with the source
// line number (0 when it cannot be located) via the shared line-map helper.
type ValidationError struct {
	Line        int    `json:"line"`
	Field       string `json:"field"`
	Description string `json:"description"`
}

// Result is the MCP-facing load outcome. On success, Engine holds the parsed
// document from the engine core. On an invalid document (a degraded read),
// Valid is false and Errors carries the first N line-numbered validation errors
// — returned as a successful call, not an error.
type Result struct {
	Engine     *hdfengine.LoadResult
	Valid      bool
	DocType    string
	Errors     []ValidationError
	ErrorsMore bool // true when more validation errors existed than were returned
	CacheHit   bool
}

// Loader wraps the engine core with a byte-bounded LRU cache. It is safe for
// concurrent use by multiple MCP request handlers.
type Loader struct {
	maxSize    int // per-document input size limit (0 = engine default)
	cacheBytes int64
	maxErrors  int

	mu      sync.Mutex
	cache   map[string]*list.Element // content hash → LRU element
	lru     *list.List               // front = most recently used
	curSize int64
}

type cacheEntry struct {
	key    string
	size   int64
	result *hdfengine.LoadResult
}

// New builds a Loader. cacheBytes <= 0 uses HDF_MCP_CACHE_BYTES, then
// DefaultCacheBytes; maxErrors <= 0 uses DefaultMaxErrors; maxSize is the
// per-document input limit passed to the engine (0 = engine default).
func New(maxSize, maxErrors int, cacheBytes int64) *Loader {
	if cacheBytes <= 0 {
		cacheBytes = cacheBytesFromEnv()
	}
	if maxErrors <= 0 {
		maxErrors = DefaultMaxErrors
	}
	return &Loader{
		maxSize:    maxSize,
		cacheBytes: cacheBytes,
		maxErrors:  maxErrors,
		cache:      make(map[string]*list.Element),
		lru:        list.New(),
	}
}

// cacheBytesFromEnv reads HDF_MCP_CACHE_BYTES, falling back to DefaultCacheBytes
// when unset or unparseable.
func cacheBytesFromEnv() int64 {
	if v := os.Getenv("HDF_MCP_CACHE_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return DefaultCacheBytes
}

// Load runs the engine core over data and applies the MCP concerns: it serves a
// cached parse when the same bytes were seen before, and produces the degraded
// envelope for invalid documents instead of failing. It only returns a non-nil
// error for a genuine load-path failure (e.g. the size guard) — never for a
// merely invalid document.
//
// Cache accounting uses the input byte length as the size proxy (a parsed doc's
// exact heap size is not directly measurable in Go); the generous default budget
// accounts for parsed documents being a multiple of their input size.
func (l *Loader) Load(data []byte) (*Result, error) {
	key := hashKey(data)
	size := int64(len(data))

	if cached, ok := l.get(key); ok {
		return l.buildResult(cached, data, true), nil
	}

	engineRes, err := hdfengine.Load(data, l.maxSize)
	if err != nil {
		return nil, err // e.g. size guard — a real load failure, not a degraded doc
	}

	l.put(key, size, engineRes)
	return l.buildResult(engineRes, data, false), nil
}

// buildResult assembles the MCP Result, computing the degraded envelope when the
// engine core reports the document invalid.
func (l *Loader) buildResult(engineRes *hdfengine.LoadResult, data []byte, cacheHit bool) *Result {
	r := &Result{
		Engine:   engineRes,
		Valid:    engineRes.Valid,
		DocType:  engineRes.DocType,
		CacheHit: cacheHit,
	}
	if !engineRes.Valid {
		r.Errors, r.ErrorsMore = l.degradedErrors(engineRes.DocType, data)
	}
	return r
}

// degradedErrors validates data against its detected type and returns the first
// N errors annotated with source line numbers. When the type is unknown there is
// no schema to validate against, so a single explanatory error is returned.
func (l *Loader) degradedErrors(docType string, data []byte) ([]ValidationError, bool) {
	if docType == "" {
		return []ValidationError{{
			Line:        0,
			Field:       "",
			Description: "unrecognized or non-JSON HDF document",
		}}, false
	}

	vr := validators.Validate(data, validators.SchemaType(docType))
	if vr.Valid {
		// Detected type validates cleanly yet the engine core marked it invalid
		// (e.g. trailing garbage after a valid object). Surface that generically.
		return []ValidationError{{Description: "document failed to parse despite matching its schema"}}, false
	}

	lineMap := hdfutil.JSONPathLineMap(data)
	out := make([]ValidationError, 0, l.maxErrors)
	for _, e := range vr.Errors {
		if len(out) >= l.maxErrors {
			return out, true
		}
		out = append(out, ValidationError{
			Line:        hdfutil.LookupLineNumber(lineMap, e.Field),
			Field:       e.Field,
			Description: e.Description,
		})
	}
	return out, false
}

// --- byte-bounded LRU cache ---

func (l *Loader) get(key string) (*hdfengine.LoadResult, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.cache[key]
	if !ok {
		return nil, false
	}
	l.lru.MoveToFront(el)
	return el.Value.(*cacheEntry).result, true
}

// put inserts an entry, evicting least-recently-used entries until the budget is
// satisfied. A single document larger than the whole budget bypasses the cache
// (loaded uncached) rather than thrashing every other entry out.
func (l *Loader) put(key string, size int64, result *hdfengine.LoadResult) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.cache[key]; exists {
		return
	}
	if size > l.cacheBytes {
		return // oversize single document: bypass the cache
	}

	for l.curSize+size > l.cacheBytes && l.lru.Len() > 0 {
		l.evictOldest()
	}

	el := l.lru.PushFront(&cacheEntry{key: key, size: size, result: result})
	l.cache[key] = el
	l.curSize += size
}

// evictOldest removes the least-recently-used entry. Caller holds l.mu.
func (l *Loader) evictOldest() {
	el := l.lru.Back()
	if el == nil {
		return
	}
	ent := el.Value.(*cacheEntry)
	l.lru.Remove(el)
	delete(l.cache, ent.key)
	l.curSize -= ent.size
}

// hashKey is the cache key: the SHA-256 of the input bytes, so identical
// documents share a cache slot regardless of where they were read from.
func hashKey(data []byte) string {
	sum := sha256.Sum256(data)
	return string(sum[:])
}
