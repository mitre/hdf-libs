// Shared timestamp guard for ESLint flat configs.
//
// Forbids `new Date(<value>)` on a tool-supplied value: a zone-less value is
// read as host-local and diverges from the (UTC-normalized) canonical form.
// Route tool timestamps through `parseTimestamp` from @mitre/hdf-utilities.
// Matches the first argument across the coercion forms callers actually use
// (`new Date(raw as string)`, `new Date(raw!)`, `new Date(String(raw))`, ...);
// the no-arg form and numeric/string literals are intentionally not matched.
//
// Imported by the eslint.config.js of every package that parses timestamps
// (hdf-converters, hdf-diff, hdf-utilities). The Go peer is
// scripts/check-timestamp-usage.mjs. See
// site/docs/contributing/developer-guide.md (Timestamp Handling).

export const DATE_GUARD_MSG =
  'Do not parse a tool timestamp with `new Date(value)` (zone-less values are read as host-local). Use `parseTimestamp` from @mitre/hdf-utilities. See site/docs/contributing/developer-guide.md (Timestamp Handling).';

export const DATE_GUARD_RULES = [
  'Identifier',
  'MemberExpression',
  'TSAsExpression',
  'TSNonNullExpression',
  'CallExpression',
  'TemplateLiteral',
].map((argType) => ({
  selector: `NewExpression[callee.name='Date'] > ${argType}.arguments`,
  message: DATE_GUARD_MSG,
}));
