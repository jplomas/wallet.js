/**
 * Regression tests guarding the generated TypeScript declarations (types/**).
 *
 * Background: PR #80 (commit 32d18a5) removed a redundant
 *   `@typedef {import('../common/descriptor.js').Descriptor} Descriptor`
 * from src/wallet/ml_dsa_87/wallet.js.  Because `Descriptor` was already
 * imported as an ES value import in the same file, `tsc --declaration`
 * emitted BOTH `export type Descriptor = import(...).Descriptor;` AND
 * `import { Descriptor } from '../common/descriptor.js';` into the generated
 * .d.ts — which TypeScript then rejects with:
 *   error TS2440: Import declaration conflicts with local declaration of 'Descriptor'.
 *
 * These tests catch two classes of regression:
 *   1. A static scan flags any source file that declares a JSDoc `@typedef`
 *      with the same name as an ES import in the same file (the exact
 *      shape of the original bug).
 *   2. A live `tsc` invocation generates declarations into a temp dir and
 *      then type-checks them, failing on any TS2440 so that new, differently
 *      shaped conflicts are also caught.
 */
import { expect } from 'chai';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { readdirSync, readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const exec = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const SRC = path.join(ROOT, 'src');
const TSC = path.join(ROOT, 'node_modules', '.bin', 'tsc');

/** Recursively collect every .js file under dir. */
function collectJsFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectJsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Find names that are both `import { Name } from '...'` AND
 * `@typedef {import('...').Something} Name` in the same file. This is the
 * exact pattern that caused the Descriptor conflict in PR #80.
 */
function findTypedefImportConflicts(source) {
  const importedNames = new Set();
  // Matches: import { A, B as C } from '...'; (including multiline)
  const importRe = /import\s*(?:type\s*)?\{([^}]+)\}\s*from\s*['"][^'"]+['"]/g;
  let m;
  while ((m = importRe.exec(source)) !== null) {
    for (const raw of m[1].split(',')) {
      const name = raw
        .trim()
        .split(/\s+as\s+/i)
        .pop();
      if (name) importedNames.add(name.trim());
    }
  }

  const conflicts = [];
  // Matches: @typedef {import('...').X} Name  (Name is what gets declared)
  const typedefRe = /@typedef\s*\{\s*import\([^)]*\)[^}]*\}\s*([A-Za-z_$][\w$]*)/g;
  while ((m = typedefRe.exec(source)) !== null) {
    const name = m[1];
    if (importedNames.has(name)) conflicts.push(name);
  }
  return conflicts;
}

describe('generated .d.ts sanity', function () {
  this.timeout(60000);

  it('no source file declares a @typedef with the same name as an ES import (TS2440 regression)', () => {
    const offenders = [];
    for (const file of collectJsFiles(SRC)) {
      const conflicts = findTypedefImportConflicts(readFileSync(file, 'utf8'));
      if (conflicts.length > 0) {
        offenders.push(`${path.relative(ROOT, file)}: ${conflicts.join(', ')}`);
      }
    }
    expect(
      offenders,
      `The following files declare a @typedef whose name is also ES-imported in the ` +
        `same file. tsc will emit both an 'export type' and an 'import' for that ` +
        `name in the generated .d.ts, producing TS2440. Remove the redundant ` +
        `@typedef (the ES import already brings the type in scope).\n  ` +
        offenders.join('\n  ')
    ).to.deep.equal([]);
  });

  it('generated .d.ts files type-check without TS2440 import-conflict errors', async () => {
    const outDir = mkdtempSync(path.join(tmpdir(), 'walletjs-types-'));
    try {
      // 1. Generate declarations from src/ into outDir.
      // `--ignoreConfig` opts out of the project's tsconfig.json so the
      // file-list arguments below are honored. TypeScript 6 made the
      // "files on CLI + tsconfig present" combination an error (it was
      // silently a tsconfig skip in 5.x).
      await exec(
        TSC,
        [
          '--ignoreConfig',
          '--allowJs',
          '--declaration',
          '--emitDeclarationOnly',
          '--outDir',
          outDir,
          '--rootDir',
          SRC,
          ...collectJsFiles(SRC),
        ],
        { cwd: ROOT, timeout: 45000 }
      );

      // 2. Type-check the generated .d.ts files. We only care about conflicts
      //    introduced by our source (TS2440) — unrelated ambient-type lookups
      //    (e.g. Buffer) are ignored so the test stays focused and portable.
      const tsconfigPath = path.join(outDir, 'tsconfig.check.json');
      writeFileSync(
        tsconfigPath,
        JSON.stringify(
          {
            compilerOptions: {
              noEmit: true,
              // skipLibCheck MUST be false — our generated files are .d.ts,
              // which tsc treats as "lib" files. With skipLibCheck on, the
              // TS2440 conflict we are guarding against would be silently
              // ignored.
              skipLibCheck: false,
              moduleResolution: 'node',
              target: 'ES2020',
              module: 'ES2020',
              types: [],
            },
            include: ['**/*.d.ts'],
          },
          null,
          2
        )
      );

      let stdout = '';
      let stderr = '';
      try {
        const res = await exec(TSC, ['-p', tsconfigPath], { cwd: ROOT, timeout: 45000 });
        stdout = res.stdout;
        stderr = res.stderr;
      } catch (err) {
        // tsc exits non-zero when it reports any diagnostic — capture output.
        stdout = err.stdout || '';
        stderr = err.stderr || '';
      }

      const combined = `${stdout}\n${stderr}`;
      const conflictLines = combined.split(/\r?\n/).filter((line) => /error TS2440:/.test(line));
      expect(
        conflictLines,
        `tsc reported import/local-declaration conflicts in generated .d.ts ` +
          `(this usually means a @typedef duplicates an ES import — see PR #80):\n` +
          conflictLines.join('\n')
      ).to.deep.equal([]);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});
