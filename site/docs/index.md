# hdf-libs documentation

Reference docs for the Heimdall Data Format. Start with the readers' guide; pull in the spec or a focused guide when you need depth on a specific topic.

## Start here

- [**HDF Readers' Guide**](architecture/hdf-readers-guide.md) — narrative introduction. What HDF is, why it exists, how the seven document types fit together. Read this first.

## Reference

- [**Specification**](specification/hdf-specification.md) — formal schema documentation for all seven HDF document types, field-by-field.
- [Document type ecosystem](architecture/hdf-document-ecosystem.md) — design rationale and full ecosystem view across the seven types.
- [Status determination](architecture/status-determination.md) — how a control's overall status is derived from its results (the precedence rules).

## Guides

- [CLI user-story examples](guides/cli-user-story-examples.md) — runnable end-to-end workflows for every `hdf` subcommand.
- [Converter fingerprint registry](guides/converter-fingerprint-registry.md) — how auto-detection picks the right converter for an input file.
- [Label keys reference](guides/label-keys-reference.md) — well-known label keys (`system`, `environment`, `region`, …) used for grouping components and baselines.
- [OSCAL alignment](guides/oscal-alignment.md) — mapping between HDF and OSCAL document types.
- [OSCAL CLI examples](guides/oscal-cli-examples.md) — converting FedRAMP SAR/SAP/SSP/POA&M between OSCAL and HDF.
- [Legacy HDF migration](guides/migration-legacy-hdf.md) — for tool authors moving from InSpec exec-json (Legacy HDF / v2) to the current schema.

## Contributing

- [Developer guide](contributing/developer-guide.md) — dual TS+Go implementation patterns, testing conventions, monorepo layout, cross-platform notes.
