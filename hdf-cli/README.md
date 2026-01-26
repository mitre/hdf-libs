# hdf-cli

Command-line tool for working with Heimdall Data Format (HDF) files.

## Building

Requires Go 1.23+ and the hdf-schema types to be generated:

```bash
# From hdf-libs root
cd hdf-schema && pnpm build && cd ../hdf-cli

# Build
go build -o hdf ./cmd/hdf
```

## Usage

```bash
# Validate an HDF file
./hdf validate results.json

# Display file info
./hdf info results.json

# Show statistics
./hdf stats results.json

# List controls
./hdf list controls results.json

# Query controls
./hdf query --status failed results.json

# Convert legacy HDF (v1.0) to current format (v2.0)
./hdf convert legacyhdf to hdf old-scan.json new-scan.json
```

## Testing

```bash
go test ./...

# With coverage
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```
