# ADR-001: Dual TypeScript/Go Converter Implementations

**Status**: Accepted
**Date**: 2026-01-03
**Deciders**: Will Dower

## Context

HDF converters transform security tool output (Nessus, Burp Suite, etc.) into HDF format. We need to support:
1. Web applications and Node.js tooling
2. Standalone CLI tool for security teams

## Decision

Maintain **dual implementations** of all converters:
- TypeScript for npm package (`@mitre/hdf-converters`)
- Go for CLI binary (`hdf-cli`)

## Rationale

### Security Advantages (Go CLI)

**Eliminates Node.js attack surface**:
- Node.js runtime: ~30MB with known vulnerabilities
- npm supply chain: thousands of transitive dependencies
- Go binary: 2-5MB, zero runtime dependencies

**Smaller trusted computing base**:
- Static compilation, memory safety
- Easier security audit (single binary vs npm tree)

### Distribution Advantages (Go CLI)

**No runtime required**:
- Users download single binary
- No Node.js installation needed
- Works in air-gapped environments

**Faster startup**:
- Go: ~1-5ms startup
- Node.js: ~50-200ms startup

### Flexibility Advantages (TypeScript)

**Web and programmatic use**:
- Import in web apps (Heimdall)
- Use in Node.js automation
- Easier for TypeScript developers

## Implementation Strategy

1. **TypeScript first**: Reference implementation
2. **Go port**: Once TypeScript is stable and tested
3. **Differential testing**: Shared fixtures ensure parity
4. **Shared test data**: Single source of truth for expected output

## Consequences

### Positive

- Security teams get standalone binary (no Node.js requirement)
- Web developers get npm package (familiar tooling)
- Differential testing catches divergence automatically
- Each implementation optimized for its use case

### Negative

- ~2x implementation effort per converter
- Must keep implementations in sync
- Additional test infrastructure (differential testing)

### Mitigation

- TypeScript as reference implementation (implement once, port once)
- Differential tests enforce parity (catches drift immediately)
- Estimated 12hrs per converter (4hr TS + 6hr Go + 2hr tests)
- ~30 converters planned = ~360 hours total (manageable)

## Alternatives Considered

### TypeScript-to-Go Transpiler

**Rejected**: No viable transpiler exists
- Researched: leona/ts2go, armsnyder/ts2go, CodeConvert.ai
- All produce unusable output for real codebases
- Manual porting is more reliable

### Go Only

**Rejected**: Excludes web/Node.js use cases
- Heimdall web app needs TypeScript
- npm ecosystem expects npm packages
- Developer experience suffers

### TypeScript Only

**Rejected**: Security and distribution concerns
- Node.js runtime vulnerabilities
- npm supply chain attacks
- Users need to install Node.js

## References

- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- Implementation: `hdf-converters/CONVERTER_GUIDE.md`
