import { describe, it, expect } from 'vitest';
import {
  escapeQuotes,
  generateControlStub,
  generateInSpecYml,
  generateInSpecProfile,
  generateUpgrade,
  generateDelta,
  generateDeltaJson,
  generateDeltaMarkdown,
  mergeRequirement,
  mergeTags,
  mergeDescriptions,
  mergeRefs,
} from '../src/index.js';

describe('barrel exports', () => {
  it('exports all public functions', () => {
    expect(typeof escapeQuotes).toBe('function');
    expect(typeof generateControlStub).toBe('function');
    expect(typeof generateInSpecYml).toBe('function');
    expect(typeof generateInSpecProfile).toBe('function');
    expect(typeof generateUpgrade).toBe('function');
    expect(typeof generateDelta).toBe('function');
    expect(typeof generateDeltaJson).toBe('function');
    expect(typeof generateDeltaMarkdown).toBe('function');
    expect(typeof mergeRequirement).toBe('function');
    expect(typeof mergeTags).toBe('function');
    expect(typeof mergeDescriptions).toBe('function');
    expect(typeof mergeRefs).toBe('function');
  });
});
