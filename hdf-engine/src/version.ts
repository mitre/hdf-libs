// Library version, kept on the workspace lockstep with package.json (the Go
// peer is hdf-engine/go/engine.go Version(); index.test.ts pins both to
// package.json). It lives in its own module so engines that stamp it into
// documents (merge.ts) can import it without a cycle through index.ts.
export const engineVersion = '3.7.0';
