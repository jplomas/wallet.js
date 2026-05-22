/**
 * TypeScript consumer-experience gate.
 *
 * Compiles `test/types/consumer.ts` against the package's published typings
 * (`types/index.d.ts`, mapped via `test/types/tsconfig.json`) using
 * `tsc --noEmit --strict`. The consumer file imports every public export
 * and exercises every documented signature, so any drift between source
 * JSDoc and what TypeScript users see — a removed export, a renamed
 * parameter, a narrowed return type — surfaces as a hard failure here
 * before it ships to npm.
 *
 * Companion to `types-build.mocha.js`, which generates declarations from
 * source and checks them for TS2440-class generation bugs. This test
 * instead checks the *committed* typings, exercising the same surface a
 * downstream `npm install` would see.
 */
import { expect } from 'chai';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const exec = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const TSC = path.join(ROOT, 'node_modules', '.bin', 'tsc');
const CONSUMER_TSCONFIG = path.join(ROOT, 'test', 'types', 'tsconfig.json');

describe('TypeScript consumer compile', function () {
  this.timeout(60000);

  it('test/types/consumer.ts type-checks against committed types/ under --strict', async () => {
    let exitCode = 0;
    const { stdout, stderr } = await exec(TSC, ['-p', CONSUMER_TSCONFIG], { cwd: ROOT, timeout: 45000 })
      .then((r) => ({ stdout: r.stdout || '', stderr: r.stderr || '' }))
      .catch((err) => {
        exitCode = typeof err.code === 'number' ? err.code : 1;
        return { stdout: err.stdout || '', stderr: err.stderr || '' };
      });
    expect(exitCode, `tsc exited ${exitCode}\nstdout:\n${stdout}\nstderr:\n${stderr}`).to.equal(0);
    expect(stdout, `tsc reported diagnostics:\n${stdout}`).to.equal('');
  });
});
