# ADR-0010: `DocumentStore` and `hdf-data` — One Data Access Model for the CLI, the MCP Server, the Server, and TypeScript Applications

**Status:** Moved to [`mitre/hdf-data-platform`](https://github.com/mitre/hdf-data-platform/blob/main/docs/adr/adr-0010-hdf-data-access-layer.md)

This ADR defines the data access model in both languages. Its TypeScript packages are built in the `hdf-data-platform` repository, and it asks this repository for a Go store at `hdf-cli/internal/store` (not yet built); it is maintained there, and whatever it says about files, renames or cards in this repository is a request to this repository, carried through pull requests here. The text that was here is in this repository's history at commit `21013300`.

Section references elsewhere in this repository (for example "ADR-0010 §5") refer to that document.
