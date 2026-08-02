# XCCDF 1.2 XSD — provenance

Used to validate `hdf-to-xccdf` output against the NIST XCCDF 1.2 schema in its
tests (Go side, via `shared/go/xsdvalidate` → libxml2). The converter emits
`xmlns="http://checklists.nist.gov/xccdf/1.2"`.

| file | source | original SHA-256 | modified? |
|---|---|---|---|
| `xccdf_1.2.xsd` | https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd | `22c6c2eeca08e517a278a9571304cb84277651ebb6fe4934af5af46c2428424e` | schemaLocations rewritten |
| `cpe-language_2.3.xsd` | https://csrc.nist.gov/schema/cpe/2.3/cpe-language_2.3.xsd | `3b67e10f5c0df1414d542252019c77fc6858009679a288ea9d3840e9dc709c21` | schemaLocations rewritten |
| `cpe-naming_2.3.xsd` | https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd | `d37f813fe223922fb7456751d453482009fc7075a3f5ad5e1999d075d190dd69` | byte-identical |
| `xml.xsd` | https://www.w3.org/2009/01/xml.xsd | `cc701736c42cc64126fad063bb95f94484b5de3b5f808a86ea098b0957aff829` | byte-identical |

Retrieved 2026-07-30.

**schemaLocation rewrites (offline validation):** `xccdf_1.2.xsd` and
`cpe-language_2.3.xsd` `<xsd:import>` companions by absolute URL / server-root
path. Those `schemaLocation`s were rewritten to the local relative filenames
(all four XSDs sit in this directory) so libxml2 compiles the schema without
network access. Only the `schemaLocation` attribute values were changed; the
schema definitions are otherwise upstream-identical (see original SHAs above).

**Import graph:** `xccdf_1.2.xsd` → `xml.xsd`, `cpe-language_2.3.xsd`;
`cpe-language_2.3.xsd` → `cpe-naming_2.3.xsd`, `xml.xsd`.

Note: `hdf-to-xccdf` output is XSD-validated on the Go side; the TypeScript output
is covered transitively by the Go↔TS golden-parity test (byte-identical output).
CKL was evaluated and excluded — DISA publishes no authoritative `.ckl` XSD.
