/**
 * Escape a string as a Ruby string literal whose value is the string unchanged.
 *
 * Strategy:
 * - A control character other than tab or LF → double-quoted (Ruby folds a raw CR)
 * - Both single and double quotes → %q() with \, ( and ) escaped
 * - Only single quotes → double-quoted with \, " and interpolation escaped
 * - Otherwise → single-quoted with \ and ' escaped
 *
 * Parity: EscapeQuotes (Go), pinned by testdata/ruby-literal-cases.json.
 */
export function escapeQuotes(s: string): string {
  const hasSingle = s.includes("'");
  const hasDouble = s.includes('"');

  if (hasControl(s) || (hasSingle && !hasDouble)) {
    return doubleQuoted(s);
  }

  if (hasSingle && hasDouble) {
    return `%q(${s.replace(/[\\()]/g, '\\$&')})`;
  }

  return `'${s.replace(/[\\']/g, '\\$&')}'`;
}

function isEscapedControl(code: number): boolean {
  return (code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f;
}

function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (isEscapedControl(s.charCodeAt(i))) return true;
  }
  return false;
}

/**
 * Escapes \, ", a # that would start #{, #@ or #$ interpolation, CR as \r and
 * any other control character as \uXXXX.
 */
function doubleQuoted(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    const code = s.charCodeAt(i);
    if (c === '\\' || c === '"' || (c === '#' && '{@$'.includes(s[i + 1] ?? ' '))) {
      out += `\\${c}`;
    } else if (c === '\r') {
      out += '\\r';
    } else if (isEscapedControl(code)) {
      out += `\\u${code.toString(16).toUpperCase().padStart(4, '0')}`;
    } else {
      out += c;
    }
  }
  return `${out}"`;
}
