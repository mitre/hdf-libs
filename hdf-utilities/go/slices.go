package hdfutil

// DefaultMaxItems is the maximum number of items processed from any single
// input array. Truncation is silent (returns partial results with a boolean
// flag) to avoid breaking legitimate large scans while capping memory usage.
const DefaultMaxItems = 100000

// Ptr returns a pointer to the given value. Replaces per-converter stringPtr,
// floatPtr, and ptr[T] helpers.
func Ptr[T any](v T) *T { return &v }

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
