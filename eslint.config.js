import js from '@eslint/js';
import { flatConfigs as importXFlatConfigs } from 'eslint-plugin-import-x';
import prettier from 'eslint-plugin-prettier';
import prettierConfig from 'eslint-config-prettier';
import globals from 'globals';

/** Rules shared by every linted area. */
const sharedRules = {
  // Prettier integration
  'prettier/prettier': 'error',

  // Import rules
  'import-x/extensions': ['error', 'ignorePackages'],
  'import-x/namespace': 'off',

  // Disabled rules (matching previous airbnb overrides)
  'max-classes-per-file': 'off',
  'no-bitwise': 'off',
  'no-plusplus': 'off',
};

export default [
  // Ignore patterns
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      'types/**',
      'coverage/**',
      'test-results/**',
      '.claude/**',
      'audit/**',
      'wallaby.js',
      'wallaby.cjs',
    ],
  },

  // Base recommended rules
  js.configs.recommended,

  // Import plugin recommended config
  importXFlatConfigs.recommended,

  // Prettier config (disables formatting rules)
  prettierConfig,

  // Library source and Node test suites
  {
    files: ['src/**/*.js', 'test/**/*.js'],
    plugins: {
      prettier,
    },
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.mocha,
        ...globals.es2020,
      },
    },
    settings: {
      'import-x/ignore': ['@theqrl/mldsa87'],
    },
    rules: sharedRules,
  },

  // Browser test harness (mocha/chai/buffer shims and suite entry)
  {
    files: ['browser-tests/**/*.js'],
    plugins: {
      prettier,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.mocha,
      },
    },
    rules: sharedRules,
  },

  // Node-side tooling: test server/setup, cross-verify scripts, root configs
  {
    files: ['scripts/**/*.js', '.github/cross-verify/**/*.js', '*.config.js', 'eslint.config.js'],
    plugins: {
      prettier,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
      },
    },
    rules: sharedRules,
  },

  // CommonJS tooling files
  {
    files: ['**/*.cjs'],
    plugins: {
      prettier,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
    rules: sharedRules,
  },
];
