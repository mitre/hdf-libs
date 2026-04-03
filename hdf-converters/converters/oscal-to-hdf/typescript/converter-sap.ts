/**
 * OSCAL Assessment Plan (SAP) to HDF Plan converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_sap.go.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { inputIntegrity, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfPlan,
  Assessment,
  RunnerConfig,
} from '@mitre/hdf-schema';
import { PlanType } from '@mitre/hdf-schema';
import type {
  Oscal,
  SecurityAssessmentPlanSAP,
  AssessedControls,
  ReferencedControlObjectives,
} from './types.js';
import {
  controlIdToNistTag,
  controlIdsToNistTags,
  extractControlIdFromObjectiveId,
  extractPropValue,
  flattenParts,
  extractMetadata,
  toKebabCase,
} from './shared.js';

/**
 * Converts an OSCAL Assessment Plan document to HDF Plan JSON.
 *
 * @param input - Raw JSON string containing an OSCAL assessment-plan
 * @returns HDF Plan JSON string
 */
export async function convertOscalSapToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-assessment-plan');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc['assessment-plan']) {
    throw new Error(
      "oscal-assessment-plan: input is not an assessment-plan document (root key is not 'assessment-plan')",
    );
  }

  const ap = doc['assessment-plan'];
  const integrity = await inputIntegrity(input);
  const meta = extractMetadata(ap.metadata);

  // Build assessments from reviewed-controls
  const assessments = buildAssessments(ap);

  // Extract systemRef from import-ssp
  const systemRef = ap['import-ssp']?.href || undefined;

  // Determine plan type from assessment-assets/tasks
  const planType = determinePlanType(ap);

  // Build description from metadata remarks and terms-and-conditions
  const description = buildPlanDescription(ap);

  const plan: HdfPlan = {
    name: toKebabCase(ap.metadata.title, 'oscal-assessment-plan'),
    assessments,
    integrity,
    systemRef,
    version: meta.version,
    type: planType,
    description,
    generator: {
      name: 'hdf-converters',
      version: '1.0.0',
    },
  };

  return JSON.stringify(plan, null, 2);
}

function buildAssessments(ap: SecurityAssessmentPlanSAP): Assessment[] {
  if (!ap['reviewed-controls']) {
    return [{ baselineRef: 'oscal-assessment-plan' }];
  }

  const assessments: Assessment[] = [];

  for (const cs of ap['reviewed-controls']['control-selections'] ?? []) {
    const assessment: Assessment = {
      baselineRef: deriveBaselineRef(ap, cs),
    };

    if (cs.description) {
      assessment.description = cs.description;
    }

    assessment.runner = extractRunnerConfig(ap) ?? undefined;
    assessment.targetSelector = buildTargetSelector(ap) ?? undefined;

    assessments.push(assessment);
  }

  // If no control selections but there are control-objective-selections
  if (assessments.length === 0 && (ap['reviewed-controls']['control-objective-selections']?.length ?? 0) > 0) {
    for (const co of ap['reviewed-controls']['control-objective-selections']!) {
      const assessment: Assessment = {
        baselineRef: deriveBaselineRefFromObjectives(ap, co),
        runner: extractRunnerConfig(ap) ?? undefined,
      };
      if (co.description) {
        assessment.description = co.description;
      }
      assessments.push(assessment);
    }
  }

  // Ensure at least one assessment exists
  if (assessments.length === 0) {
    assessments.push({ baselineRef: 'oscal-assessment-plan' });
  }

  return assessments;
}

function deriveBaselineRef(ap: SecurityAssessmentPlanSAP, cs: AssessedControls): string {
  if (cs['include-all'] !== undefined) {
    if (ap['import-ssp']?.href) {
      return ap['import-ssp'].href;
    }
    return 'all-controls';
  }

  if (cs['include-controls'] && cs['include-controls'].length > 0) {
    const ids = cs['include-controls'].map(sc => controlIdToNistTag(sc['control-id']));
    return ids.join(',');
  }

  if (ap['import-ssp']?.href) {
    return ap['import-ssp'].href;
  }

  return 'oscal-assessment-plan';
}

function deriveBaselineRefFromObjectives(
  ap: SecurityAssessmentPlanSAP,
  co: ReferencedControlObjectives,
): string {
  if (co['include-all'] !== undefined) {
    if (ap['import-ssp']?.href) {
      return ap['import-ssp'].href;
    }
    return 'all-objectives';
  }

  if (co['include-objectives'] && co['include-objectives'].length > 0) {
    const ids = co['include-objectives'].map(sc =>
      extractControlIdFromObjectiveId(sc['objective-id']),
    );
    return controlIdsToNistTags(ids).join(',');
  }

  return 'oscal-assessment-plan';
}

function extractRunnerConfig(ap: SecurityAssessmentPlanSAP): RunnerConfig | null {
  const assets = ap['assessment-assets'];
  if (!assets) return null;

  // Look for the first assessment platform
  const platforms = assets['assessment-platforms'];
  if (platforms && platforms.length > 0) {
    const platform = platforms[0]!;
    const config: RunnerConfig = {};
    if (platform.title) {
      config.name = platform.title;
    }
    return config;
  }

  // Fall back to components
  if (assets.components && assets.components.length > 0) {
    const comp = assets.components[0]!;
    const config: RunnerConfig = {
      name: comp.title,
    };
    const version = extractPropValue(comp.props, 'version');
    if (version) {
      config.version = version;
    }
    return config;
  }

  return null;
}

function buildTargetSelector(
  ap: SecurityAssessmentPlanSAP,
): Record<string, string> | null {
  const subjects = ap['assessment-subjects'];
  if (!subjects || subjects.length === 0) return null;

  const selector: Record<string, string> = {};
  for (const subject of subjects) {
    if (subject.type) {
      const key = 'subject-type';
      if (selector[key] !== undefined) {
        selector[key] += ',' + subject.type;
      } else {
        selector[key] = subject.type;
      }
    }
    if (subject['include-all'] !== undefined) {
      selector['include-' + subject.type] = 'all';
    }
  }

  if (Object.keys(selector).length === 0) return null;
  return selector;
}

function determinePlanType(ap: SecurityAssessmentPlanSAP): PlanType | undefined {
  const aType = extractPropValue(ap.metadata.props, 'assessment-type');
  if (aType) {
    switch (aType.toLowerCase()) {
      case 'automated':
        return PlanType.Automated;
      case 'manual':
        return PlanType.Manual;
    }
  }

  if (ap.tasks && ap.tasks.length > 0) {
    return PlanType.Hybrid;
  }

  return undefined;
}

function buildPlanDescription(ap: SecurityAssessmentPlanSAP): string | undefined {
  const parts: string[] = [];

  if (ap.metadata.remarks) {
    parts.push(ap.metadata.remarks);
  }

  if (ap['terms-and-conditions']?.parts && ap['terms-and-conditions'].parts.length > 0) {
    const terms = flattenParts(ap['terms-and-conditions'].parts);
    if (terms) {
      parts.push('Terms and Conditions: ' + terms);
    }
  }

  if (parts.length === 0) return undefined;
  return parts.join('\n\n');
}
