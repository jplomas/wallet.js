/**
 * Smoke tests for the built ESM and CJS dist bundles.
 *
 * These verify that `npm run build` produces bundles a consumer can actually
 * import (ESM) or require (CJS) without ERR_REQUIRE_ESM or other loader
 * errors.  They exercise a representative slice of the public API through
 * each entry-point so regressions in the rollup config are caught early.
 */
import { expect } from 'chai';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const exec = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const NODE = process.execPath;

/**
 * Helper: run an inline script in a child process so the current test
 * process's module cache / loader state is not affected.
 */
function run(script, opts = {}) {
  const args = opts.cjs ? ['-e', script] : ['--input-type=module', '-e', script];
  return exec(NODE, args, { cwd: ROOT, timeout: 30000 });
}

describe('dist bundle smoke tests', () => {
  describe('ESM (dist/mjs/wallet.js)', () => {
    it('imports and creates a wallet', async () => {
      const { stdout } = await run(`
        import { MLDSA87 } from './dist/mjs/wallet.js';
        const w = MLDSA87.newWallet();
        console.log(w.getAddressStr());
      `);
      // Canonical 64-byte address → Q + 128 lowercase hex chars (v6.x)
      expect(stdout.trim()).to.match(/^Q[0-9a-f]{128}$/);
    });

    it('sign and verify round-trip', async () => {
      const { stdout } = await run(`
        import { MLDSA87 } from './dist/mjs/wallet.js';
        const w = MLDSA87.newWallet();
        const msg = new TextEncoder().encode('test');
        const sig = w.sign(msg);
        const ok = MLDSA87.verify(sig, msg, w.getPK(), w.getDescriptor());
        console.log(ok);
      `);
      expect(stdout.trim()).to.equal('true');
    });

    it('mnemonic round-trip', async () => {
      const { stdout } = await run(`
        import { MLDSA87 } from './dist/mjs/wallet.js';
        const w1 = MLDSA87.newWallet();
        const m = w1.getMnemonic();
        const w2 = MLDSA87.newWalletFromMnemonic(m);
        console.log(w1.getAddressStr() === w2.getAddressStr());
      `);
      expect(stdout.trim()).to.equal('true');
    });
  });

  describe('CJS (dist/cjs/wallet.js)', () => {
    it('requires and creates a wallet', async () => {
      const { stdout } = await run(
        `
        const { MLDSA87 } = require('./dist/cjs/wallet.js');
        const w = MLDSA87.newWallet();
        console.log(w.getAddressStr());
      `,
        { cjs: true }
      );
      // Canonical 64-byte address → Q + 128 lowercase hex chars (v6.x)
      expect(stdout.trim()).to.match(/^Q[0-9a-f]{128}$/);
    });

    it('sign and verify round-trip', async () => {
      const { stdout } = await run(
        `
        const { MLDSA87 } = require('./dist/cjs/wallet.js');
        const w = MLDSA87.newWallet();
        const msg = new TextEncoder().encode('test');
        const sig = w.sign(msg);
        const ok = MLDSA87.verify(sig, msg, w.getPK(), w.getDescriptor());
        console.log(ok);
      `,
        { cjs: true }
      );
      expect(stdout.trim()).to.equal('true');
    });

    it('mnemonic round-trip', async () => {
      const { stdout } = await run(
        `
        const { MLDSA87 } = require('./dist/cjs/wallet.js');
        const w1 = MLDSA87.newWallet();
        const m = w1.getMnemonic();
        const w2 = MLDSA87.newWalletFromMnemonic(m);
        console.log(w1.getAddressStr() === w2.getAddressStr());
      `,
        { cjs: true }
      );
      expect(stdout.trim()).to.equal('true');
    });
  });
});
