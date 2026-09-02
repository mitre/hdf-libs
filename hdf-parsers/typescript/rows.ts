import type { HDFResults, Cvss, Epss, Kev, AffectedPackage, EvaluatedRequirement } from '@mitre/hdf-schema';

/**
 * A flat, row-per-requirement projection of an HDF Results document, keyed by
 * column name. A column is omitted (the key is absent) when no value is
 * available. Values are stringified for downstream CSV / wide-JSON emission;
 * numeric and boolean source data are formatted without trailing zeros.
 */
export type Row = Record<string, string>;

/**
 * Expand an HDF Results document into a slice of rows — one per requirement,
 * per baseline, in input order. CVE-ecosystem columns (cvss_base_score,
 * cvss_computed_score, epss_score, epss_percentile, kev_in_kev, cwe,
 * affected_packages) are populated from the structured fields on
 * Evaluated_Requirement; cvss_base_score also falls back to the legacy scalar
 * tags.cvss_base_score for back-compat with files emitted by older converters.
 */
export function flattenToRows(results: HDFResults): Row[] {
  const rows: Row[] = [];
  const baselines = results?.baselines ?? [];
  for (const b of baselines) {
    for (const r of b.requirements ?? []) {
      const row: Row = {
        id: r.id,
        baseline: b.name,
      };
      fillCveColumns(row, r);
      rows.push(row);
    }
  }
  return rows;
}

function fillCveColumns(row: Row, r: EvaluatedRequirement): void {
  // cvss[] — first entry drives cvss_base_score / cvss_computed_score.
  if (r.cvss && r.cvss.length > 0) {
    const first = r.cvss[0] as Cvss;
    if (first.baseScore !== undefined && first.baseScore !== null) {
      row.cvss_base_score = formatNumber(first.baseScore);
    }
    if (first.computedScore !== undefined && first.computedScore !== null) {
      row.cvss_computed_score = formatNumber(first.computedScore);
    }
  }

  // Legacy fallback: only if structured cvss[].baseScore did not populate.
  if (row.cvss_base_score === undefined && r.tags && 'cvss_base_score' in r.tags) {
    const v = scalarString((r.tags as Record<string, unknown>)['cvss_base_score']);
    if (v !== undefined) row.cvss_base_score = v;
  }

  // epss
  if (r.epss) {
    const epss = r.epss as Epss;
    row.epss_score = formatNumber(epss.score);
    row.epss_percentile = formatNumber(epss.percentile);
  }

  // kev
  if (r.kev) {
    const kev = r.kev as Kev;
    row.kev_in_kev = String(kev.inKev);
  }

  // cwe[] — joined with ";"
  if (r.cwe && r.cwe.length > 0) {
    row.cwe = r.cwe.join(';');
  }

  // affectedPackages[] — joined "name@version;name@version"
  if (r.affectedPackages && r.affectedPackages.length > 0) {
    const parts: string[] = [];
    for (const p of r.affectedPackages as AffectedPackage[]) {
      if (!p.name) continue;
      if (!p.version) {
        parts.push(p.name);
      } else {
        parts.push(`${p.name}@${p.version}`);
      }
    }
    if (parts.length > 0) {
      row.affected_packages = parts.join(';');
    }
  }
}

/**
 * Format a number without trailing zeros (e.g. 7.5 -> "7.5", 7 -> "7").
 */
function formatNumber(n: number): string {
  return String(n);
}

/**
 * Stringify a scalar tag value (numeric / string / bool). Used for the
 * legacy tags.cvss_base_score fallback, where the value may arrive as a
 * string ("6.4") or a number (6.4) depending on the converter.
 */
function scalarString(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  if (typeof v === 'string') {
    return v === '' ? undefined : v;
  }
  if (typeof v === 'number') {
    return String(v);
  }
  if (typeof v === 'boolean') {
    return String(v);
  }
  return undefined;
}
