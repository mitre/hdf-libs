import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  dts: true,
  sourcemap: true,
  // The generated .oas.json/.yaml are written into dist by build:components,
  // which runs first; a clean here would delete them.
  clean: false,
  target: 'node20',
  // 'neutral' keeps the repo's .js output extension and exports-map shape. The
  // loader reads the tracked schema embed, so node builtins are real runtime
  // imports and must stay external rather than be resolved into the bundle.
  platform: 'neutral',
  external: [/^node:/],
});
