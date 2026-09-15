# Conveyor fixtures — provenance

`sample-results.json` is **real-shaped Conveyor output** — a Conveyor API
response wrapping file-analysis results with genuine artifacts: real SHA-256 file
hashes (`033ecf8f…`), TLP classification (`TLP:C`), CART-encoded content markers,
and realistic timestamps and file-info structures. `empty.json` is a
zero-results document.

**Refreshing:** Conveyor is an access-gated analysis service; there is no free/open
path to regenerate current output. The response contract is stable, so this
capture remains a valid tested contract. Refresh only on an API-shape change,
sourcing from a real Conveyor instance and scrubbing any environment-specific
identifiers.
