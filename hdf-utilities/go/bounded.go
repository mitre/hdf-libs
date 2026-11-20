package hdfutil

import (
	"errors"
	"fmt"
	"io"
)

// ErrInputTooLarge is wrapped by the error ReadAtMost returns when the input is
// longer than its limit.
var ErrInputTooLarge = errors.New("input too large")

// ReadAtMost reads all of r, refusing input longer than limit bytes. It reads one
// byte past the limit so an over-long input is an error wrapping ErrInputTooLarge
// rather than a silently truncated prefix. source names the input in both errors.
func ReadAtMost(r io.Reader, limit int64, source string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", source, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrInputTooLarge, source, limit)
	}
	return data, nil
}
