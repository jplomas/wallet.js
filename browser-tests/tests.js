import './setup.js';
import '../test/unit/address.mocha.js';
import '../test/unit/context.mocha.js';
import '../test/unit/cross-implementation.mocha.js';
import '../test/unit/descriptor.mocha.js';
import '../test/unit/edge-cases.mocha.js';
import '../test/unit/factory.mocha.js';
import '../test/unit/metamorphic.mocha.js';
import '../test/unit/ml_dsa_87.wallet.mocha.js';
import '../test/unit/mnemonic.mocha.js';
import '../test/unit/public-api.mocha.js';
import '../test/unit/random.mocha.js';
import '../test/unit/seed.mocha.js';
import '../test/unit/seed-ownership.mocha.js';
import '../test/unit/utils.bytes.mocha.js';
import '../test/unit/verify-with-reason.mocha.js';
import '../test/unit/wallettype.mocha.js';
// Suites that cannot run in the browser, and why:
// - fuzz.mocha.js: depends on fast-check (Node-only distribution)
// - secret-enumeration.mocha.js: depends on node:util's inspect
// - dist-bundle.mocha.js, types-build.mocha.js, types-consumer.mocha.js:
//   spawn child processes (node:child_process) to exercise built artifacts
