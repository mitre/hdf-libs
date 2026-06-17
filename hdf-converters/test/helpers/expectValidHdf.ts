// Thin test helpers that route an importer's in-memory output through the
// matching @mitre/hdf-validators schema check. Mirrors the Go pattern:
//   body, _ := json.Marshal(result); v := validators.ValidateAmendments(body)
// JSON-roundtripping the result converts Date instances to ISO strings the
// schema expects, so callers don't have to remember to do it themselves.
import { expect } from 'vitest';
import {
  validateAmendments,
  validateBaseline,
  validateResults,
} from '@mitre/hdf-validators';

export function expectValidAmendments(result: unknown): void {
  const v = validateAmendments(JSON.parse(JSON.stringify(result)));
  expect(v.valid, v.getErrorMessage()).toBe(true);
}

export function expectValidResults(result: unknown): void {
  const v = validateResults(JSON.parse(JSON.stringify(result)));
  expect(v.valid, v.getErrorMessage()).toBe(true);
}

export function expectValidBaseline(result: unknown): void {
  const v = validateBaseline(JSON.parse(JSON.stringify(result)));
  expect(v.valid, v.getErrorMessage()).toBe(true);
}
