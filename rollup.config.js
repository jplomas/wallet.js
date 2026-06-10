/**
 * Rollup configuration for dual ESM/CJS builds.
 */
import resolve from '@rollup/plugin-node-resolve';

// @noble/hashes is ESM-only, so it must be bundled into the CJS build
// (along with @theqrl/mldsa87) — see SECURITY.md "Bundled Dependencies
// in the CJS Artifact". The ESM build externalizes both.
const nobleExternal = ['@noble/hashes/sha2.js', '@noble/hashes/sha3.js', '@noble/hashes/utils.js'];
const otherExternal = ['@theqrl/mldsa87'];

export default [
  {
    input: 'src/index.js',
    output: {
      file: 'dist/cjs/wallet.js',
      format: 'cjs',
      exports: 'named',
    },
    plugins: [resolve({ preferBuiltins: false })],
  },
  {
    input: 'src/index.js',
    output: {
      file: 'dist/mjs/wallet.js',
      format: 'esm',
    },
    external: [...nobleExternal, ...otherExternal],
  },
];
