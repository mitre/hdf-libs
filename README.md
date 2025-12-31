# HDF Libraries

**Heimdall Data Format (HDF)** is a standardized JSON schema for representing security assessment baselines and assesresults across diverse tools and platforms.

## Overview

Security teams use many different tools—vulnerability scanners, compliance checkers, configuration auditors, cloud security posture managers—each producing results in its own format. HDF provides a common data model that normalizes these outputs, enabling:

- **Unified dashboards** across all security tools
- **Consistent metrics** regardless of data source
- **Interoperability** between security platforms
- **Historical analysis** with a stable schema

## Packages

This monorepo contains the following libraries:

| Package | Description |
|---------|-------------|
| `@mitre/hdf-schema` | JSON schemas and generated types for HDF documents |
| `@mitre/hdf-mappings` | CCI, NIST 800-53, CIS, and CMMC framework mappings |
| `@mitre/hdf-utilities` | Generic utilities for XML, CSV, and hash operations |
| `@mitre/hdf-parsers` | Parse and flatten HDF documents |
| `@mitre/hdf-converters` | Convert 30+ security tool formats to HDF |
| `@mitre/hdf-generators` | Generate templates and baseline documents |
| `@mitre/hdf-validators` | Validate HDF documents against schemas |

## Schema Types

HDF defines two primary document types:

### HDF Results
Assessment results from running security checks against a target system. Contains:
- Target system information (hosts, containers, cloud accounts, etc.)
- Evaluated baselines with requirement results
- Pass/fail status for each check
- Statistics and timing data

### HDF Baseline
Security requirement definitions without results. Contains:
- Requirement metadata (title, description, severity)
- Check and fix instructions
- Framework mappings (NIST, CIS, etc.)
- Dependencies between requirements

## Installation

```bash
npm install @mitre/hdf-schema
```
