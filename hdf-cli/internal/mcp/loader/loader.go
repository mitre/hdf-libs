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
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
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
	bytes  []byte // the raw document, retained so a content-addressed handle resolves
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

// UnrecognizedMessage is the diagnostic for input that resolved to no HDF
// document type. It distinguishes the two causes an agent must tell apart: a
// genuine parse failure (not valid JSON) versus valid JSON whose root keys match
// no HDF type (a recognized-type problem), which it answers by naming the
// recognized types. Shared so the loader and the validate tool never drift.
func UnrecognizedMessage(data []byte) string {
	if !json.Valid(data) {
		return "the input is not valid JSON"
	}
	return "valid JSON, but not a recognized HDF document type (expected one of: " +
		strings.Join(hdfengine.KnownTypes(), ", ") + ")"
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

	l.put(key, size, engineRes, data)
	return l.buildResult(engineRes, data, false), nil
}

// LoadByHash returns the cached raw bytes and parsed result for a document whose
// content SHA-256 (hex) matches a document seen by a prior Load and still
// resident in the cache. It backs content-addressed handle resolution (jobi.1):
// an authored/derived document registered via Load is retrievable by its
// handle's contentSha256 with no file on disk. ok is false on a cache miss
// (evicted or never seen) or a malformed hex digest — the caller maps that to
// the cache-miss taxonomy code, never a path error.
func (l *Loader) LoadByHash(contentSha256Hex string) (data []byte, res *Result, ok bool) {
	raw, err := hex.DecodeString(contentSha256Hex)
	if err != nil {
		return nil, nil, false
	}
	l.mu.Lock()
	el, hit := l.cache[string(raw)]
	if !hit {
		l.mu.Unlock()
		return nil, nil, false
	}
	l.lru.MoveToFront(el)
	ent := el.Value.(*cacheEntry)
	engineRes, bytes := ent.result, ent.bytes
	l.mu.Unlock()

	return bytes, l.buildResult(engineRes, bytes, true), true
}

// buildResult assembles the MCP Result and determines validity for ALL detected
// document types. The engine core only struct-parses (and thus validates)
// results and baseline; for every other detected type this wrapper validates
// against the schema so a valid system/plan/amendments/etc. is reported valid
// rather than mistaken for a degraded read. Invalid documents get the degraded
// envelope (line-numbered errors); a valid document never does.
func (l *Loader) buildResult(engineRes *hdfengine.LoadResult, data []byte, cacheHit bool) *Result {
	r := &Result{
		Engine:   engineRes,
		DocType:  engineRes.DocType,
		CacheHit: cacheHit,
	}

	// Results/baseline the engine parsed cleanly are valid.
	if engineRes.Valid {
		r.Valid = true
		return r
	}
	// No type detected: distinguish a genuine parse failure from valid JSON that
	// simply is not an HDF document type, so an agent does not chase a phantom
	// parse error (jobi.3 / D6). Neither has a schema to validate against.
	if engineRes.DocType == "" {
		r.Errors = []ValidationError{{Description: UnrecognizedMessage(data)}}
		return r
	}

	// Detected a type the engine did not validate (non-results/baseline), or a
	// results/baseline that failed to parse. Validate against the detected schema.
	vr := validators.Validate(data, validators.SchemaType(engineRes.DocType))
	if vr.Valid {
		// A results/baseline the engine rejected but that passes schema validation
		// failed for a non-schema reason (e.g. trailing data); surface that.
		if engineRes.ParseError != "" {
			r.Errors = []ValidationError{{Description: engineRes.ParseError}}
			return r
		}
		r.Valid = true
		return r
	}

	r.Errors, r.ErrorsMore = l.degradedErrors(vr, data)
	return r
}

// degradedErrors turns a failed validation result into the first N errors
// annotated with source line numbers.
func (l *Loader) degradedErrors(vr validators.ValidationResult, data []byte) ([]ValidationError, bool) {
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
func (l *Loader) put(key string, size int64, result *hdfengine.LoadResult, data []byte) {
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

	// Retain a private copy of the bytes so a later mutation of the caller's
	// slice cannot corrupt a content-addressed resolution.
	buf := make([]byte, len(data))
	copy(buf, data)
	el := l.lru.PushFront(&cacheEntry{key: key, size: size, result: result, bytes: buf})
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
