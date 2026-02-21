/**
 * Input format detection via structural fingerprinting.
 *
 * Examines raw input to determine which shared format converter
 * should handle it, allowing tool-specific converters to delegate.
 */

export type InputFormat = 'sarif' | 'unknown';

/**
 * Detects the format of raw input by examining structural characteristics.
 *
 * SARIF fingerprint: JSON object with "version" (string) and "runs" (array).
 */
export function detectFormat(input: string): InputFormat {
  if (!input || !input.trim().startsWith('{')) {
    return 'unknown';
  }

  try {
    const parsed = JSON.parse(input);
    if (typeof parsed !== 'object' || parsed === null) {
      return 'unknown';
    }

    if (isSARIF(parsed)) {
      return 'sarif';
    }
  } catch {
    return 'unknown';
  }

  return 'unknown';
}

function isSARIF(obj: Record<string, unknown>): boolean {
  return typeof obj.version === 'string' && Array.isArray(obj.runs);
}
