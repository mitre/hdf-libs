/**
 * Input format detection via structural fingerprinting.
 *
 * Examines raw input to determine which shared format converter
 * should handle it, allowing tool-specific converters to delegate.
 */

export type InputFormat = 'sarif' | 'junit' | 'xccdf' | 'arf' | 'unknown';

/**
 * Detects the format of raw input by examining structural characteristics.
 *
 * SARIF fingerprint: JSON object with "version" (string) and "runs" (array).
 * JUnit fingerprint: XML with <testsuites> or <testsuite> root element.
 */
export function detectFormat(input: string): InputFormat {
  if (!input) {
    return 'unknown';
  }

  const trimmed = input.trim();
  if (trimmed.startsWith('{')) {
    return detectJSON(trimmed);
  }
  if (trimmed.startsWith('<')) {
    return detectXML(trimmed);
  }

  return 'unknown';
}

function detectJSON(input: string): InputFormat {
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

function detectXML(input: string): InputFormat {
  // Extract root element name by finding the first opening tag after XML declaration/comments.
  // Handles both prefixed (e.g. <arf:asset-report-collection>) and unprefixed elements.
  const rootMatch = input.match(/<(?!\?|!--)(?:[a-zA-Z_][\w.-]*:)?([a-zA-Z_][\w.-]*)/);
  if (!rootMatch) {
    return 'unknown';
  }

  const rootElement = rootMatch[1];
  switch (rootElement) {
    case 'testsuites':
    case 'testsuite':
      return 'junit';
    case 'Benchmark':
      return 'xccdf';
    case 'asset-report-collection':
      return 'arf';
    default:
      return 'unknown';
  }
}

function isSARIF(obj: Record<string, unknown>): boolean {
  return typeof obj.version === 'string' && Array.isArray(obj.runs);
}
