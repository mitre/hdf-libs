// Local (empty) PostCSS config so vite/VitePress's config search stops inside
// this package instead of walking up out of a git worktree into the parent
// checkout (which a sandbox may not grant → EPERM on the parent package.json).
// No PostCSS plugins are used; this only halts the upward search.
export default {};
