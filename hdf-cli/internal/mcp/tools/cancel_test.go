package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
)

// hdfengine.Filter hands back the partial match set it gathered when ctx is
// cancelled; a handler that serialises that as a complete envelope reports a
// confidently-wrong smaller universe. A cancelled request must propagate the
// context error instead, as hdf_diff does.
func TestHdfQuery_HonorsCancellation(t *testing.T) {
	name := writeRoot(t, "r.json", readToolsFixture(t, "query-results.json"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _, err := hdfQuery(loader.New(0, 0, 0))(ctx, nil, queryInput{Source: handle.Source{Path: name}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a cancelled query, got err=%v res=%+v", err, res)
	}
}

func TestHdfAggregate_HonorsCancellation(t *testing.T) {
	name := writeRoot(t, "r.json", readToolsFixture(t, "query-results.json"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _, err := hdfAggregate(loader.New(0, 0, 0))(ctx, nil, aggregateInput{Sources: []handle.Source{{Path: name}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a cancelled aggregate, got err=%v res=%+v", err, res)
	}
}
