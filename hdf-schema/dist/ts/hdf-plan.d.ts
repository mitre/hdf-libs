/**
 * Defines an assessment plan — what baselines to run against which targets, with resolved
 * inputs and scheduling. Maps to OSCAL Assessment Plan.
 */
export interface HdfPlan {
    /**
     * The assessments to perform. Each assessment pairs a baseline with targets and resolved
     * inputs.
     */
    assessments: Assessment[];
    /**
     * Description of the plan's purpose and scope.
     */
    description?: string;
    /**
     * Information about the tool that generated this plan.
     */
    generator?: Generator;
    /**
     * Cryptographic integrity information for verifying this plan document has not been
     * tampered with.
     */
    integrity?: Integrity;
    /**
     * Optional key-value labels for grouping and querying plans.
     */
    labels?: {
        [key: string]: string;
    };
    /**
     * Human-readable plan name. Example: 'Portal Monthly Assessment'.
     */
    name: string;
    /**
     * Unique identifier for this plan. Optional in casual use, expected in production
     * documents. Auto-generated if omitted during creation.
     */
    planId?: string;
    /**
     * Optional scheduling configuration for recurring assessments.
     */
    schedule?: Schedule;
    /**
     * URI to the hdf-system document this plan targets. Example: 'portal-prod.hdf-system.json'.
     */
    systemRef?: string;
    /**
     * The type of assessment plan.
     */
    type?: PlanType;
    /**
     * Version of this plan document.
     */
    version?: string;
    [property: string]: any;
}
/**
 * A single assessment within a plan — defines which baseline to run against which targets
 * with what configuration.
 */
export interface Assessment {
    /**
     * Reference to the baseline to evaluate. May be a baseline name (e.g. 'RHEL9-STIG'), a
     * relative path to an HDF Baseline document (e.g. 'rhel9-stig.hdf-baseline.json'), or an
     * absolute URI.
     */
    baselineRef: string;
    /**
     * componentId of the system component this assessment targets. Use for direct component
     * binding. Alternative to targetSelector.
     */
    componentRef?: string;
    /**
     * Description of this assessment's purpose.
     */
    description?: string;
    /**
     * Resolved input values for this assessment. Keys are input names, values are the final
     * resolved values (after baseline defaults + system overrides).
     */
    inputs?: {
        [key: string]: any;
    };
    /**
     * Runner/scanner configuration for this assessment.
     */
    runner?: RunnerConfig;
    /**
     * Label selector to match targets for this assessment. Overrides the system component's
     * targetSelector if provided.
     */
    targetSelector?: {
        [key: string]: string;
    };
    [property: string]: any;
}
/**
 * Runner/scanner configuration for this assessment.
 *
 * Configuration for the assessment runner/scanner.
 */
export interface RunnerConfig {
    /**
     * Name of the assessment runner. Example: 'cinc-auditor', 'inspec', 'openscap'.
     */
    name?: string;
    /**
     * Version of the runner.
     */
    version?: string;
    [property: string]: any;
}
/**
 * Information about the tool that generated this plan.
 *
 * Information about the tool that generated this HDF file.
 */
export interface Generator {
    /**
     * The name of the software that produced this HDF file. Example: 'gosec-to-hdf'.
     */
    name: string;
    /**
     * The version of the tool. Example: '5.22.3'.
     */
    version: string;
    [property: string]: any;
}
/**
 * Cryptographic integrity information for verifying this plan document has not been
 * tampered with.
 *
 * Cryptographic integrity information for verifying the HDF file has not been tampered
 * with. If algorithm is provided, checksum must also be provided, and vice versa.
 */
export interface Integrity {
    /**
     * The hash algorithm used for the checksum.
     */
    algorithm?: HashAlgorithm;
    /**
     * The checksum value.
     */
    checksum?: string;
    /**
     * Optional cryptographic signature.
     */
    signature?: string;
    /**
     * Identifier of who signed this file.
     */
    signedBy?: string;
    [property: string]: any;
}
/**
 * The hash algorithm used for the checksum.
 *
 * Supported cryptographic hash algorithms for checksums and integrity verification.
 */
export declare enum HashAlgorithm {
    Sha256 = "sha256",
    Sha384 = "sha384",
    Sha512 = "sha512"
}
/**
 * Optional scheduling configuration for recurring assessments.
 *
 * Scheduling configuration for recurring assessments.
 */
export interface Schedule {
    /**
     * Cron expression for recurring assessments. Example: '0 2 1 * *' (2 AM on the 1st of each
     * month).
     */
    cron?: string;
    /**
     * Date after which assessments should no longer run. ISO 8601 format.
     */
    endDate?: Date;
    /**
     * Email addresses or notification endpoints to alert when assessments complete.
     */
    notifyOnCompletion?: string[];
    /**
     * Email addresses or notification endpoints to alert when regressions are detected.
     */
    notifyOnRegression?: string[];
    /**
     * Earliest date to begin assessments. ISO 8601 format.
     */
    startDate?: Date;
    [property: string]: any;
}
/**
 * The type of assessment plan.
 *
 * The type of assessment. 'automated' for scanner-driven, 'manual' for human-performed,
 * 'hybrid' for both.
 */
export declare enum PlanType {
    Automated = "automated",
    Hybrid = "hybrid",
    Manual = "manual"
}
