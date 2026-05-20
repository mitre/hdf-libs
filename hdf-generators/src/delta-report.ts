import type { DeltaResult, LinkRecord } from './delta-types.js';

/**
 * JSON report payload for delta operations.
 * SAF CLI-compatible: { links: LinkRecord[] }
 */
export interface DeltaJsonReport {
  links: LinkRecord[];
}

/**
 * Generate a structured JSON report from a delta result.
 * Matches SAF CLI's delta.json format: { ...diff, links }.
 */
export function generateDeltaJson(result: DeltaResult): DeltaJsonReport {
  return {
    links: result.linkRecords,
  };
}

/**
 * Format a per-link match method description matching SAF CLI's logMatchMethod.
 */
function formatMatchMethod(lr: LinkRecord): string {
  const confidencePct = (lr.confidence * 100).toFixed(0) + '%';
  switch (lr.matchMethod) {
    case 'srgDeterministic':
      return `SRG deterministic (${lr.srg ?? '?'}) [${lr.relationship}]`;
    case 'srgCciTiebreak':
      return `SRG block + CCI tiebreak (Jaccard=${confidencePct}) [${lr.relationship}]`;
    case 'vendorFuzzyTitle':
      return `Vendor fuzzy title (confidence=${confidencePct}) [${lr.relationship}]`;
    case 'exactId':
      return `Exact ID [${lr.relationship}]`;
    case 'cciMatch':
      return `CCI match [${lr.relationship}]`;
    case 'fuzzyTitle':
      return `Fuzzy title (confidence=${confidencePct}) [${lr.relationship}]`;
    case 'none':
      return 'No match';
    default:
      return `${lr.matchMethod} [${lr.relationship}]`;
  }
}

/**
 * Generate a Markdown report from a delta result.
 * Matches SAF CLI's delta.md format: mapping table, control counts,
 * match statistics, and statistics validation.
 */
export function generateDeltaMarkdown(result: DeltaResult): string {
  const lines: string[] = [];
  const stats = result.statistics;

  // Mapping results — SAF CLI format: Old Control -> New Control
  if (result.linkRecords.length > 0) {
    lines.push('Mapping Results ===========================================================================');
    lines.push('\tOld Control -> New Control');
    for (const lr of result.linkRecords) {
      if (lr.relationship !== 'no-match' && lr.oldId) {
        lines.push(`\t   ${lr.oldId} -> ${lr.newId}`);
      }
    }

    const totalMapped = stats.totalMappedControls;
    lines.push(`Total Mapped Controls:  ${totalMapped}`);
    lines.push('');
  }

  // Control counts
  lines.push('Control Counts ===========================');
  lines.push(`Total Controls Available for Delta:  ${stats.oldControlsLength}`);
  lines.push(`     Total Controls Found on XCCDF:  ${stats.newControlsLength}`);
  lines.push('');

  // Match statistics
  lines.push('Match Statistics =========================');
  lines.push(`                    Match Controls:  ${stats.match}`);
  lines.push(`        Possible Mismatch Controls:  ${stats.posMisMatch}`);
  lines.push(`            Related Match Controls:  ${stats.dupMatch}`);
  lines.push(`                 No Match Controls:  ${stats.noMatch}`);
  lines.push('');

  // Statistics validation
  lines.push('Statistics Validation =============================================');
  const totalMapped = stats.totalMappedControls;
  const matchMappedValid = (stats.match + stats.posMisMatch + stats.dupMatch) === totalMapped;
  const processedValid = (totalMapped + stats.noMatch) === stats.newControlsLength;
  lines.push(`Match + Mismatch + Related = Total Mapped Controls:  (${stats.match}+${stats.posMisMatch}+${stats.dupMatch}=${totalMapped}) ${matchMappedValid}`);
  lines.push(`  Total Processed = Total XCCDF Controls:  (${totalMapped}+${stats.noMatch}=${totalMapped + stats.noMatch}) ${processedValid}`);
  lines.push('');

  // Per-control match method details
  if (result.linkRecords.length > 0) {
    lines.push('Match Details =============================================================');
    for (const lr of result.linkRecords) {
      if (lr.oldId) {
        lines.push(`  ${lr.oldId} --> ${lr.newId}`);
        lines.push(`       Match method:  ${formatMatchMethod(lr)}`);
      } else {
        lines.push(`  (none) --> ${lr.newId}  [no match]`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}
