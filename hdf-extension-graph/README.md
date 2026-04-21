# @mitre/hdf-extension-graph

Bidirectional extension graph processing for HDF baseline hierarchies.

## Why this exists

HDF baseline documents can represent 'overlay' structures that form extension chains of parent baselines and their children. For example, a DISA STIG baseline defines hundreds of requirements; an organizational overlay on that DISA baseline can modify a subset for organization-specific policies; a project overlay can further tighten thresholds for a specific system. When an HDF results file contains multiple baselines linked via `parentBaseline`, understanding what each layer changed requires walking these chains bidirectionally.

Without this library, answering "did this overlay change the impact of SV-238196, or inherit it unchanged?" requires manually cross-referencing requirements across baselines by ID. The extension graph provides:

- **`root`** — jump from any overlay requirement to the original base definition
- **`modifications`** — which fields (impact, title, severity, effectiveImpact, disposition) an overlay changed relative to its parent
- **`isRedundant`** — whether an overlay re-declares a control without actually changing it
- **`fullCode`** — the complete code from all layers in one string
- **`extensionChain`** — the ordered list of baselines from root to leaf

This is the same graph algorithm that powers Heimdall's control detail panel, extracted as a standalone library.

## Installation

```bash
pnpm add @mitre/hdf-extension-graph
```

Requires `@mitre/hdf-schema` as a peer dependency.

## Usage

### Build the graph

```typescript
import { buildExtensionGraph } from '@mitre/hdf-extension-graph';
import type { HdfResults } from '@mitre/hdf-schema';

const hdfResults: HdfResults = JSON.parse(fileContents);
const graph = buildExtensionGraph(hdfResults);
```

### Navigate baselines

```typescript
// Find root baselines (no parent)
const roots = graph.rootBaselines;

// Find a specific baseline
const stig = graph.findBaseline('rhel9-stig-baseline');

// See what extends it
for (const overlay of stig.extendedBy) {
  console.log(`${overlay.data.name} extends ${stig.data.name}`);
}
```

### Navigate requirements

```typescript
// Find all instances of a control across all baselines
const controls = graph.findRequirements('SV-238196');

// Get the root (base) control
const root = controls[1].root; // walks up the chain

// Get the full code with all layers
console.log(controls[1].fullCode);
// # my-overlay
// describe sshd_config do
//   its("ClientAliveInterval") { should cmp <= 300 }
// end
//
// # rhel9-stig-baseline
// describe sshd_config do
//   its("ClientAliveInterval") { should cmp <= 600 }
// end
```

### Detect changes

```typescript
const overlay = graph.baselines[1].requirements[0];

// Is this overlay just inheriting, or did it change something?
if (!overlay.isRedundant) {
  console.log('This overlay modifies the base control');
}

// What specifically changed?
for (const mod of overlay.modifications) {
  console.log(`${mod.field}: ${mod.originalValue} → ${mod.newValue}`);
}
// impact: 0.5 → 0.9
// title: SSH timeout → SSH timeout (project)
```

### Walk the chain

```typescript
// Ordered list of baselines from root to current
const chain = overlay.extensionChain;
console.log(chain.map(b => b.data.name));
// ['disa-rhel7-stig', 'cms-rhel7-overlay', 'project-overlay']
```

## API

### `buildExtensionGraph(results: HdfResults): ExtensionGraph`

Builds a bidirectional extension graph from an HDF Results file. Links baselines via `parentBaseline` and requirements by matching `id` across linked baselines.

### `ExtensionGraph`

| Property / Method | Type | Description |
|---|---|---|
| `baselines` | `ContextualizedBaseline[]` | All baselines in the graph |
| `requirements` | `ContextualizedRequirement[]` | All requirements across all baselines |
| `rootBaselines` | `ContextualizedBaseline[]` | Baselines with no parent |
| `findBaseline(name)` | `ContextualizedBaseline \| undefined` | Find baseline by name |
| `findRequirements(id)` | `ContextualizedRequirement[]` | Find all requirements with given id |

### `ContextualizedBaseline`

| Property | Type | Description |
|---|---|---|
| `data` | `EvaluatedBaseline` | Original baseline data |
| `sourcedFrom` | `HdfResults` | The results file this came from |
| `extendsFrom` | `ContextualizedBaseline[]` | Parent baselines |
| `extendedBy` | `ContextualizedBaseline[]` | Child baselines |
| `requirements` | `ContextualizedRequirement[]` | Wrapped requirements |

### `ContextualizedRequirement`

| Property | Type | Description |
|---|---|---|
| `data` | `EvaluatedRequirement` | Original requirement data |
| `sourcedFrom` | `ContextualizedBaseline` | Owning baseline |
| `extendsFrom` | `ContextualizedRequirement[]` | Parent requirements |
| `extendedBy` | `ContextualizedRequirement[]` | Child requirements |
| `root` | `ContextualizedRequirement` | Base requirement at bottom of chain |
| `isRedundant` | `boolean` | True if code is empty or matches root |
| `fullCode` | `string` | Concatenated code from all layers |
| `extensionChain` | `ContextualizedBaseline[]` | Baselines from root to leaf |
| `modifications` | `Modification[]` | Fields changed vs immediate parent |

### `Modification`

```typescript
interface Modification {
  field: string;        // 'impact', 'title', or 'severity'
  originalValue: unknown;
  newValue: unknown;
  inBaseline: string;   // Name of the baseline making the change
}
```

## Notes

- **TypeScript only** — there is no Go implementation of hdf-extension-graph.
- The HDF schemas consumed by this package are documented at <https://mitre.github.io/hdf-libs/schemas/>.

## License

Apache-2.0
