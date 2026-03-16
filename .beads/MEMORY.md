# hdf-libs Persistent Learnings

## Browser-Bundleable Patterns

### JSON data loading (hdf-mappings)
- Use `import rawData from '../data/foo.json' with { type: 'json' }` instead of readFileSync
- Pattern proven in hdf-validators (9 JSON imports)
- `copy-data` build script must stay — tsc emits import verbatim, JSON must exist in dist/data/ for Node runtime
- Bundlers (Vite/esbuild) inline JSON automatically

### Hashing (hdf-utilities)
- `globalThis.crypto.subtle.digest()` works in Node 20+ and all modern browsers
- Functions must be async — returns ArrayBuffer, needs manual hex/base64 conversion
- Algorithm name mapping: `sha256` → `'SHA-256'`, `sha512` → `'SHA-512'`
- `bufferToHex`: iterate Uint8Array, `b.toString(16).padStart(2, '0')`
- `bufferToBase64`: build binary string from Uint8Array, use `btoa()`

### CSV (hdf-utilities)
- PapaParse 5.5.3 is UMD-only, breaks Rollup strict ESM (global.document refs)
- d3-dsv is pure ESM replacement: csvParse, csvParseRows, csvFormat, csvFormatRows, dsvFormat
- d3-dsv lacks: skipEmptyLines, transformHeader, dynamicTyping, error reporting — implement manually

## Async Converter Pattern
- All converter entry functions are async, returning `Promise<string>` (or `Promise<HdfResults>` for nessus)
- Test pattern: `it('...', async () => { ... await convertXxxToHdf(...) ... })`
- Error test pattern: `await expect(convertXxxToHdf(...)).rejects.toThrow(...)`
- Helper functions calling converters must also be async

## Edit Tool Patterns for Bulk Changes
- `replace_all` with `() => {` → `async () => {` safely adds async to all `it()` callbacks (only matches zero-param arrow functions with braces)
- Caveat: also matches `expect(() => {` block-style error tests — fix those individually after
- For adding `await`, use specific context patterns like `JSON.parse(convertXxx(` or `= convertXxx(` to avoid touching error test lines

## XCCDF/ARF Converter Patterns
- XCCDF 1.2 namespace: `http://checklists.nist.gov/xccdf/1.2`
- ARF 1.1 namespace: `http://scap.nist.gov/schema/asset-reporting-format/1.1`
- Go XML: must specify full namespace in struct tags `xml:"http://checklists.nist.gov/xccdf/1.2 title"`
- TS XML: fast-xml-parser with removeNSPrefix:true strips namespaces automatically
- Array tags needed: Group, Rule, Profile, rule-result, ident, select, set-value, target-address, platform
- ARF additional array tags: report, report-request, asset, connection, relationship, ref, component, data-stream
- VulnDiscussion extraction: regex `<VulnDiscussion>(.*?)</VulnDiscussion>` from description field
- XCCDF result mapping: pass→Passed, fail→Failed, error→Error, unknown→Error, notapplicable→NotApplicable, notchecked/notselected/informational→NotReviewed, fixed→Passed
- Fixtures: validated against XCCDF 1.2 XSD from csrc.nist.gov
- Real fixture sources: heimdall2 repo, OpenSCAP/openscap (tests/API/XCCDF/), OpenSCAP/openscap-report (tests/test_data/)
- ARF format detection: peek at root XML element name — `Benchmark` → XCCDF, `asset-report-collection` → ARF
- Go ARF: 14 struct types with full namespace tags for arf/core/ai/ds namespaces
- Go ARF: check `report.Content.TestResult.ID != ""` to identify XCCDF reports (skip OVAL)
- ARF asset enrichment: FQDN, MAC (skip 00:00:00:00:00:00), IP from ai:computing-device
- ARF relationships: `core:relationship type="...isAbout"` links report ID → asset ID

## CLI Converter Test Validation
- assertHDFOutput uses validators.ValidateResults() for real HDF schema validation
- Pre-existing issue: converter_registry_test.go resets global map, breaks converter tests in full suite
- Converter tests pass in isolation (`-run Xccdf|Arf`) even when full suite fails

## Converter Done Checklist (learned the hard way)
- Barrel export: typescript/index.ts + re-export from hdf-converters/src/index.ts
- Export existence test in hdf-converters/test/index.test.ts
- CLI integration: converter_<name>.go + converter_<name>_test.go
- All converters async (sha256 is async via Web Crypto)
- Never use crypto module — use sha256 from @mitre/hdf-utilities

## Naming Conventions
- Converter directories use tool name only, no vendor prefix: `grype-to-hdf` not `anchore-grype-to-hdf`
- Go packages: `grype_to_hdf`, functions: `ConvertGrypeToHDF`
- TypeScript functions: `convertGrypeToHdf`
- CLI registry keys: `"grype"` (just the tool name)

## CycloneDX Converter Patterns
- CycloneDX JSON: `bomFormat: "CycloneDX"` is the detection key
- Vulnerabilities are top-level array (not nested in components)
- `affects[].ref` maps to component `bom-ref` — build lookup map
- Components can be nested (`components[].components`) — flatten first
- Ratings: prefer CVSS score/10 over severity string (maxImpact pattern)
- CVSS methods: CVSSv2, CVSSv3, CVSSv31, CVSSv4
- VEX: pure vulnerability document with no components — use ref string as component name
- No-vuln SBOM: valid input, produces empty requirements
- HDF schema requires `descriptions` with minItems:1 and a `default` label — always provide fallback

## Nikto Converter Patterns
- Nikto JSON: flat structure with `vulnerabilities[]` array, no severity field
- Impact: hardcoded 0.5 for all findings (matches heimdall2)
- Status: all Failed (Nikto only reports detected issues)
- NIST mapping: `getNiktoNistControl(id)` (TS) / `nikto.NISTControl(id)` (Go)
- Fallback: DEFAULT_STATIC_ANALYSIS_NIST_TAGS = ["SA-11", "RA-5"]
- OSVDB tag: include only when present and != "0"
- Duplicate vuln IDs: group by ID, multiple results per requirement
- Go mapping module: hdf-mappings/go/nikto/ (//go:embed, sync.Once, map[string]string)
- Fixture source: heimdall2 zero.webappsecurity.json (14 vulns)

## Go Mapping Module Pattern (hdf-mappings/go/)
- Embed JSON via `//go:embed filename.json`
- Lazy init with `sync.Once`
- For simple key→value: `map[string]string`
- For complex: custom struct + `[]Mapping` unmarshaled into lookup maps
- Existing modules: cwe (int→[]string), awsconfig (string→*Mapping), cci (string→string), nikto (string→string)

## Go JSON Serialization Gotcha
- `var x []Type` → nil slice → JSON `null`
- `x := []Type{}` → empty slice → JSON `[]`
- HDF schema rejects `null` for array fields — always initialize as empty slice

## Lint Policy
- Zero warnings required across all `pnpm lint` output (root-level)
- golangci-lint: don't disable checks that are already disabled by default (e.g. hugeParam, rangeValCopy are not in gocritic diagnostic/style tags)
- Fix pre-existing warnings, not just new ones

## Converter Pattern Conventions (established by snyk/gosec, enforced on ZAP)
- **Baseline.Name**: Always a fixed scan label (e.g., "Snyk Scan", "OWASP ZAP Scan"), never dynamic data. Dynamic context goes in Title.
- **Targets**: Populate when tool scans an identifiable target. Type mapping: DAST→Application, SAST→Repository, Container→ContainerImage, Host→Host, Cloud→CloudAccount. Omit (don't set "Unknown") when no target identifiable.
- **SARIF routing**: Use shared.DetectFormat()/detectFormat(), delegate transparently to sarif converter. Never error on SARIF input. Use static imports (not dynamic `await import()`).
- **Shared utilities**: Never write local stripHTML(), isSarif(), or NIST/CCI tag builders. Use shared/go/ and shared/typescript/ modules.
- **TS test __dirname**: Always use `dirname(fileURLToPath(import.meta.url))` pattern for ESM. Never use bare `__dirname`.
- **Copyright enum**: Go `hdf.Application`, TS `Copyright.Application` (import from @mitre/hdf-schema)

## Monorepo Structure
- hdf-mappings: data loading + lookup functions
- hdf-utilities: json/hash/xml/csv parsing utilities
- hdf-converters: tool-specific converters using schema + utilities + mappings
- hdf-schema: types + factory functions (no Node-only code)
- Sub-path exports pattern: `"./json": { "import": "...", "types": "..." }` in package.json
