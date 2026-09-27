/**
 * The OSCAL exporters mint a fresh UUID per element and stamp the conversion
 * moment into the document, so their output differs on every run and can never be
 * frozen as-is. Masking makes it comparable.
 *
 * UUIDs are replaced by first-occurrence ordinal ("uuid-1", "uuid-2", ...) rather
 * than a single constant, because OSCAL UUIDs REFERENCE each other: a party uuid
 * reappears under responsible-parties, a risk uuid under related-risks. Collapsing
 * them all to one placeholder would let Go and TypeScript emit entirely different
 * reference graphs and still compare equal. Ordinals keep the graph observable:
 * the same uuid always maps to the same ordinal, a different wiring maps
 * differently, and the comparison fails as it should.
 *
 * Ordinals are assigned over a key-sorted walk so both languages number the UUIDs
 * identically regardless of the order their serializers happen to emit keys.
 *
 * Mirrored by MaskVolatileJSON in shared/go/goldenmask.go. The two must stay in
 * lockstep.
 */

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Blank the values that change on every run: keys named in `volatileKeys`, and
 * every UUID (by first-occurrence ordinal). Returns the masked document for
 * comparison, not for consumption.
 */
export function maskVolatileJson(value: unknown, volatileKeys: string[]): unknown {
  return maskValue(value, new Set(volatileKeys), new Map<string, string>());
}

function maskValue(value: unknown, volatile: Set<string>, seen: Map<string, string>): unknown {
  if (Array.isArray(value)) return value.map((item) => maskValue(item, volatile, seen));

  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    // Canonical walk order, so ordinals match Go's.
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = volatile.has(k)
        ? '(normalized)'
        : maskValue((value as Record<string, unknown>)[k], volatile, seen);
    }
    return out;
  }

  if (typeof value === 'string') return maskUuid(value, seen);
  return value;
}

function maskUuid(s: string, seen: Map<string, string>): string {
  // A "#<uuid>" fragment reference points at the uuid it names, so it shares that ordinal.
  if (s.length > 1 && s.startsWith('#') && UUID_PATTERN.test(s.slice(1))) return `#${maskUuid(s.slice(1), seen)}`;
  if (!UUID_PATTERN.test(s)) return s;
  const existing = seen.get(s);
  if (existing !== undefined) return existing;
  const placeholder = `uuid-${seen.size + 1}`;
  seen.set(s, placeholder);
  return placeholder;
}
