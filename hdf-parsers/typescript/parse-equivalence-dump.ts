// Produces the canonical parse-outcome shape consumed by
// parse-equivalence.test.ts. The matching Go producer lives at
// ../go/cmd/parse-equivalence-dump/main.go. See that file for why the shape
// is intentionally narrow (counts, not full parsed data).
import { parseBaseline, parseResults } from './index.js';

// Error strings are intentionally absent — ajv-formats (TS) and
// gojsonschema (Go) format the SAME schema violation differently
// ("required.baselines: is required" vs "baselines is required"), so
// asserting on exact text would false-fail. Success+counts captures the
// signal we actually care about (do both parsers reach the same outcome
// on the same bytes).
export interface ParseEquivalenceDump {
  success: boolean;
  baselineCount: number;
  requirementCount: number;
}

// `kind` picks which parser is exercised; the Results fixture goes through
// parseResults, the Baseline fixture through parseBaseline. Without that
// dispatch a baseline fixture would always fail parseResults and the test
// would never actually verify baseline-parse parity.
export type ParseKind = 'results' | 'baseline';

export function dumpParse(input: string, kind: ParseKind): ParseEquivalenceDump {
  if (kind === 'baseline') {
    const r = parseBaseline(input);
    const out: ParseEquivalenceDump = {
      success: r.success,
      baselineCount: 0,
      requirementCount: 0,
    };
    if (r.success && r.data) {
      // HDF Baseline is one doc with a flat requirements[] — model it as
      // baselineCount=1 so we still surface count parity across languages.
      out.baselineCount = 1;
      out.requirementCount = r.data.requirements?.length ?? 0;
    }
    return out;
  }
  const r = parseResults(input);
  const out: ParseEquivalenceDump = {
    success: r.success,
    baselineCount: 0,
    requirementCount: 0,
  };
  if (r.success && r.data) {
    out.baselineCount = r.data.baselines?.length ?? 0;
    for (const b of r.data.baselines ?? []) {
      out.requirementCount += b.requirements?.length ?? 0;
    }
  }
  return out;
}
