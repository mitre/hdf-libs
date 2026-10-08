package hdfutil

// DefaultMaxItems is the maximum number of items processed from any single
// input array. Truncation is silent (returns partial results with a boolean
// flag) to avoid breaking legitimate large scans while capping memory usage.
const DefaultMaxItems = 100000

// Ptr returns a pointer to the given value. Replaces per-converter stringPtr,
// floatPtr, and ptr[T] helpers.
func Ptr[T any](v T) *T { return &v }

// Deref reads the value behind a pointer, or the zero value when it is nil.
// The inverse of Ptr, and the replacement for per-converter deref/derefString
// helpers; a named string type keeps its type, so call sites that want a plain
// string convert the result.
func Deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// LimitSlice returns at most maxItems elements from items. The second return
// value is true if the slice was truncated. If maxItems <= 0, DefaultMaxItems
// is used.
func LimitSlice[T any](items []T, maxItems int) ([]T, bool) {
	if maxItems <= 0 {
		maxItems = DefaultMaxItems
	}
	if len(items) <= maxItems {
		return items, false
	}
	return items[:maxItems], true
}
