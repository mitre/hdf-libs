/**
 * GitLab Vulnerability Report envelope fingerprint.
 *
 * Detects the document the gitlab-vulnerabilities fetcher assembles: a project
 * block with a fullPath and a vulnerabilities array whose nodes carry uuid and
 * state. The sibling CI-artifact report also has a vulnerabilities array but no
 * project block and no state, so it scores 0 here.
 */

import { registerFingerprint, getFingerprint, type ConverterFingerprint } from '../../../shared/typescript/registry.js';

export const gitlabVulnerabilitiesFingerprint: ConverterFingerprint = {
  id: 'gitlab-vulnerabilities-to-hdf',
  label: 'GitLab Vulnerability Report',
  direction: 'ingest',
  inputFamily: 'json',
  outputType: 'results',
  fingerprint: (input: unknown): number => {
    if (typeof input !== 'object' || input === null) return 0;
    const obj = input as Record<string, unknown>;
    const project = obj.project;
    if (typeof project !== 'object' || project === null) return 0;
    const fullPath = (project as Record<string, unknown>).fullPath;
    if (typeof fullPath !== 'string' || fullPath === '') return 0;
    if (!Array.isArray(obj.vulnerabilities)) return 0;
    if (obj.vulnerabilities.length === 0) return 0.9;
    const first = obj.vulnerabilities[0] as Record<string, unknown> | null;
    if (!first || typeof first !== 'object') return 0;
    if (typeof first.uuid === 'string' && typeof first.state === 'string') return 1.0;
    return 0;
  },
};

export function register(): void {
  if (getFingerprint('gitlab-vulnerabilities-to-hdf')) return;
  registerFingerprint(gitlabVulnerabilitiesFingerprint);
}
